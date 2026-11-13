//! against a stand-in C library (tests/audit/libc.c) for x86-64 and AArch64
//! (ELF), both PE architectures, and both Mach-O architectures (chained
//! and classic fixups), at -O0 and -O2. Every `bad_*` function must get
//! exactly the finding its comment names, no `ok_*` function any.
//!
//! Requires libtcg-x86_64.so and libtcg-aarch64.so (scripts/build-libtcg.sh).
#![cfg(target_os = "linux")]

#[path = "common/mod.rs"]
mod common;
#[path = "audit/formats.rs"]
mod formats;

use std::collections::BTreeSet;

use biara_lift::{
    Arg, CallSite, CallSites, Callee, analysis_machine,
    audit::{Input, Issue, audit},
};
use biara_loader::Image;
use biara_tcg::Libtcg;
use common::recover_program;
use formats::Target;

fn check(target: &Target) {
    let machine = analysis_machine().unwrap();
    for opt in [0, 2] {
        let at = format!("{} -O{opt}", target.name);
        let path = (target.build)(opt);
        let image = Image::load(&path).unwrap();
        assert_eq!(image.os, target.os, "{at}");
        let extra = (target.names)(&path);
        let lib = Libtcg::load(&Libtcg::find(target.qemu_arch).expect("libtcg"), None).unwrap();
        let mut lib = lib.lock();
        let cfg = recover_program(&mut lib, &image);
        let mut sites = CallSites::new(&machine, lib.info(), &cfg).unwrap();
        sites.add(&cfg.functions.keys().copied().collect()).unwrap();
        let regs = sites.arg_registers();
        let calls = sites.sites();
        let c_name = target.c_name;
        let fn_name = |f: u64| {
            image
                .function_at(f)
                .map(|s| s.name.clone())
                .or_else(|| extra.get(&f).cloned())
                .unwrap_or_else(|| format!("{f:#x}"))
        };
        // Corpus and import names as the loader reports them (Mach-O loses
        // its underscore there); `c` maps what the C source calls them.
        let strip = |n: &str| n.strip_prefix('_').unwrap_or(n).to_owned();
        let cn = |n: &str| c_name(n).to_owned();
        let c = |n: &str| strip(&cn(n));
        let caller = |c: &CallSite| fn_name(c.caller);
        let callee = |c: &CallSite| match &c.callee {
            Callee::Import(i) => i.clone(),
            Callee::Function(f) => cfg
                .stub_import(*f)
                .map(str::to_owned)
                .unwrap_or_else(|| fn_name(*f)),
            Callee::Indirect { target } => format!("*({target})"),
        };
        let call = |f: &str, to: &str| -> CallSite {
            let (f, to) = (&c(f)[..], &c(to)[..]);
            let mut hits = calls.iter().filter(|site| {
                caller(site) == f
                    && [callee(site), (target.base)(callee(site)), cn(&callee(site))]
                        .iter()
                        .any(|n| n == to)
            });
            let c = hits
                .next()
                .unwrap_or_else(|| panic!("{at}: no {to} call in {f}"));
            assert!(hits.next().is_none(), "{at}: several {to} calls in {f}");
            c.clone()
        };
        let string_at = |what: &str, a: &Arg| match a {
            Arg::Const(p) => {
                let mut buf = [0u8; 16];
                assert!(image.read_const(*p, &mut buf), "{at}: {p:#x} unreadable");
                buf.split(|&b| b == 0).next().unwrap().to_vec()
            }
            other => panic!("{at}: {what}: {other} is no string"),
        };

        let read = call("bad_read", "read");
        assert_eq!(read.args[0], Arg::Const(0), "{at}");
        assert!(
            matches!(read.args[1], Arg::Stack(o) if o <= -16),
            "{at}: {}",
            read.args[1]
        );
        assert_eq!(read.args[2], Arg::Const(64), "{at}");
        if opt == 2 && target.os == "windows" {
            // `printf("%s\n", s)` becomes `puts(s)`.
            assert!(
                matches!(call("ok_fmt", "puts").args[0], Arg::Incoming(_)),
                "{at}"
            );
        } else {
            assert_eq!(
                string_at("ok_fmt printf", &call("ok_fmt", "printf").args[0]),
                b"%s\n",
                "{at}"
            );
        }
        let fill = call("bad_fill", "fill");
        assert!(
            matches!(fill.args[0], Arg::Stack(o) if o <= -16),
            "{at}: {}",
            fill.args[0]
        );
        assert_eq!(fill.args[1], Arg::Const(64), "{at}");
        assert_eq!(
            call("fill", "read").args[1],
            Arg::Incoming(regs[0].clone()),
            "{at}"
        );
        // argv[1], from the second argument register.
        assert_eq!(
            call("main", "bad_fmt_argv").args[0],
            Arg::Deref {
                reg: regs[1].clone(),
                off: 8
            },
            "{at}"
        );
        assert_eq!(
            call("bad_fmt_env", "printf").args[0],
            Arg::Returned {
                import: "getenv".into(),
                pc: call("bad_fmt_env", "getenv").pc
            },
            "{at}"
        );
        let choice = call("ok_fmt_choice", "printf");
        let Arg::OneOf(fmts) = &choice.args[0] else {
            panic!("{at}: {}", choice.args[0]);
        };
        let fmts: BTreeSet<Vec<u8>> = fmts.iter().map(|a| string_at("ok_fmt_choice", a)).collect();
        assert_eq!(
            fmts,
            BTreeSet::from([b"%s\n".to_vec(), b"%s!\n".to_vec()]),
            "{at}"
        );
        let gettext = call("ok_fmt_translated", "dcgettext");
        let translated = call("ok_fmt_translated", "printf");
        assert_eq!(
            translated.args[0],
            Arg::Returned {
                import: "dcgettext".into(),
                pc: gettext.pc
            },
            "{at}"
        );
        // The translation survives the `sink(buf)` call leaking another
        // slot: the per-call check lets its slot through. (Silence itself
        // is covered by the exact-findings set below.)
        let after = call("ok_fmt_after_import", "printf");
        assert!(
            matches!(after.args[0], Arg::Returned { .. }),
            "{at}: {}",
            after.args[0]
        );
        // The translation survives the x87 traffic in between: the FPU
        // stack helpers leave every register global alone. (Silence itself
        // is covered by the exact-findings set below.)
        let long = call("ok_fmt_long_double", "printf");
        assert!(
            matches!(long.args[0], Arg::Returned { .. }),
            "{at}: {}",
            long.args[0]
        );
        // The incoming format survives two `sink` calls (the first leaks
        // another slot, so the per-call check must let its slot through):
        assert_eq!(
            call("ok_fmt_arg_kept", "printf").args[0],
            Arg::Incoming(regs[0].clone()),
            "{at}"
        );
        // `ok_fmt_kept_across_leak`'s format slot survives its `sink(buf)`
        // call (which leaks a different slot): its format argument must
        // still resolve to the constant. (Silence itself is covered by the
        // exact-findings set below.)
        if opt == 2 && target.os == "windows" {
            // The compiler sees through the local and folds the whole call
            // to `puts("x")`: nothing format-like is left to check.
            assert_eq!(
                string_at(
                    "kept_across_leak puts",
                    &call("ok_fmt_kept_across_leak", "puts").args[0]
                ),
                b"x",
                "{at}"
            );
        } else {
            assert_eq!(
                string_at(
                    "kept_across_leak printf",
                    &call("ok_fmt_kept_across_leak", "printf").args[0]
                ),
                b"%s\n",
                "{at}"
            );
        }
        // audit asks for them: (caller, import, kind, function the value
        // or buffer is in).
        let mut fresh = CallSites::new(&machine, lib.info(), &cfg).unwrap();
        // PE: the loader cannot know `main` (the CRT calls it); the corpus
        // links it as the entry point.
        let main = image.main.or_else(|| {
            extra
                .iter()
                .find_map(|(&a, n)| (n == target.main).then_some(a))
        });
        let findings = audit(
            &mut fresh,
            &image.indirect_entries(),
            main,
            &|addr, buf| image.read_const(addr, buf),
            &|_| None,
        )
        .unwrap();
        let found: BTreeSet<(String, String, &str, String)> = findings
            .iter()
            .map(|f| {
                let (kind, place) = match &f.issue {
                    Issue::Format { input, at, .. } => (
                        match input {
                            None => "format",
                            Some(Input::CommandLine) => "format: command line",
                            Some(Input::Environment) => "format: environment",
                            Some(Input::Read { .. }) => "format: input",
                        },
                        *at,
                    ),
                    Issue::Overflow { frame, .. } => ("overflow", *frame),
                    Issue::Unbounded { frame, .. } => ("unbounded", *frame),
                    Issue::ObjectOverflow { .. } | Issue::ObjectUnbounded { .. } => {
                        panic!("undeclared object bound in legacy corpus")
                    }
                };
                (
                    caller(&f.site),
                    (target.base)(c(f.site.import().unwrap_or("?"))),
                    kind,
                    fn_name(place),
                )
            })
            .collect();
        let expected: BTreeSet<(String, String, &str, String)> = [
            ("bad_read", "read", "overflow", "bad_read"),
            ("bad_copy", "memcpy", "overflow", "bad_copy"),
            ("fill", "read", "overflow", "bad_fill"),
            ("bad_fmt_argv", "printf", "format: command line", "main"),
            (
                "bad_fmt_env",
                "printf",
                "format: environment",
                "bad_fmt_env",
            ),
            ("bad_fmt_input", "printf", "format: input", "bad_fmt_input"),
            ("bad_fmt_hook", "printf", "format", "bad_fmt_hook"),
            ("bad_fmt_args", "printf", "format: command line", "main"),
            (
                "bad_fmt_filled",
                "printf",
                "format: input",
                "bad_fmt_filled",
            ),
            ("bad_fmt_escaped", "printf", "format", "bad_fmt_escaped"),
            ("bad_fmt_global", "printf", "format", "bad_fmt_global"),
            ("mid_fmt_wrapper", "printf", "format: command line", "main"),
            ("bad_strcpy", "strcpy", "unbounded", "bad_strcpy"),
        ]
        .into_iter()
        .map(|(f, i, k, p)| (c(f), i.to_owned(), k, c(p)))
        .collect();
        assert_eq!(found, expected, "{at}");
    }
}

#[test]
fn elf() {
    for t in formats::elf() {
        check(&t);
    }
}

#[test]
fn pe() {
    for t in formats::pe() {
        check(&t);
    }
}

#[test]
fn macho() {
    for t in formats::macho() {
        check(&t);
    }
}
