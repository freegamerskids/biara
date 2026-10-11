//! Diffing two builds of tests/diff/prog.c (`V2` changes one function,
//! adds one, removes one): every other function must match as `Same`.
//!
//! Requires libtcg-x86_64.so and libtcg-aarch64.so (scripts/build-libtcg.sh).
#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
};

use biara_diff::{Match, Program, diff};
use biara_loader::Image;
use biara_tcg::Libtcg;

fn tmp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// `ld.lld` for clang: the Rust toolchain's lld.
fn linker() -> PathBuf {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    let sysroot = String::from_utf8(out.stdout).unwrap();
    let rustlib = PathBuf::from(sysroot.trim()).join("lib/rustlib");
    let lld = std::fs::read_dir(&rustlib)
        .unwrap()
        .map(|e| e.unwrap().path().join("bin/rust-lld"))
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("no rust-lld under {}", rustlib.display()));
    let dir = tmp().join("ld-diff");
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("ld.lld");
    if link.symlink_metadata().is_err() {
        std::os::unix::fs::symlink(&lld, &link).unwrap_or(());
    }
    link
}

/// Build `prog.c` (`V2` iff `v2`) for `arch`, dynamically linked against a
/// stand-in shared libc (so PLT stubs exist and are skipped by matching).
fn build(arch: &str, v2: bool) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/diff");
    let lib_dir = tmp().join(format!("diff-lib-{arch}"));
    std::fs::create_dir_all(&lib_dir).unwrap();
    let status = Command::new(env!("BIARA_CLANG"))
        .args([
            &format!("--target={arch}-linux-gnu"),
            "-O2",
            "-fpic",
            "-nostdlib",
            "-shared",
            "-fno-stack-protector",
            "-fuse-ld=lld",
            &format!("--ld-path={}", linker().display()),
            "-o",
        ])
        .arg(lib_dir.join("libc.so"))
        .arg(dir.join("libc.c"))
        .status()
        .unwrap();
    assert!(status.success(), "building the {arch} stand-in libc");
    let interp = match arch {
        "x86_64" => "/lib64/ld-linux-x86-64.so.2",
        _ => "/lib/ld-linux-aarch64.so.1",
    };
    let out = tmp().join(format!("diff-{arch}-{}", if v2 { "v2" } else { "v1" }));
    let mut cc = Command::new(env!("BIARA_CLANG"));
    cc.args([
        &format!("--target={arch}-linux-gnu"),
        "-O2",
        "-nostdlib",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fpie",
        "-pie",
        "-fuse-ld=lld",
        &format!("--ld-path={}", linker().display()),
        &format!("-Wl,--dynamic-linker={interp}"),
        "-Wno-format-security",
    ]);
    if v2 {
        cc.arg("-DV2");
    }
    let status = cc
        .arg("-o")
        .arg(&out)
        .arg(dir.join("prog.c"))
        .arg(format!("-L{}", lib_dir.display()))
        .arg("-lc")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "building {arch} {}",
        if v2 { "v2" } else { "v1" }
    );
    out
}

fn recover(arch: &str, path: &std::path::Path) -> (Image, biara_cfg::Cfg) {
    let image = Image::load(path).unwrap();
    let lib = Libtcg::load(&Libtcg::find(arch).expect("libtcg"), None).unwrap();
    let mut lib = lib.lock();
    let machine = biara_lift::host_machine().unwrap();
    let opts = biara_lift::ResolveOptions {
        cfg: biara_cfg::Options {
            os: image.os,
            imports: image.imports.clone(),
            discovery: Some(biara_cfg::Discovery {
                code: image.code.clone(),
                extents: image.function_extents(),
                data_pointers: image.code_pointers.clone(),
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let starts: Vec<u64> = image.function_starts().into_iter().collect();
    let cfg = biara_lift::recover_resolving(
        &mut *lib,
        &machine,
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &starts,
        opts,
    )
    .unwrap();
    (image, cfg)
}

fn names(image: &Image, cfg: &biara_cfg::Cfg) -> BTreeMap<u64, String> {
    cfg.functions
        .keys()
        .map(|&e| {
            (
                e,
                image
                    .function_at(e)
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| format!("{e:#x}")),
            )
        })
        .collect()
}

fn check(arch: &str) {
    let (image1, cfg1) = recover(arch, &build(arch, false));
    let (image2, cfg2) = recover(arch, &build(arch, true));
    let old = Program::new(&cfg1, &image1);
    let new = Program::new(&cfg2, &image2);
    let matches = diff(&old, &new);
    let name = names(&image1, &cfg1);
    let name2 = names(&image2, &cfg2);
    let kind = |m: &Match| match m {
        Match::Same { .. } => "same",
        Match::Changed { .. } => "changed",
        Match::Added { .. } => "added",
        Match::Uncertain { .. } => "uncertain",
        Match::Removed { .. } => "removed",
    };
    let mut found: BTreeSet<(String, &str, String)> = BTreeSet::new();
    for m in &matches {
        match m {
            Match::Same { old, new } => {
                found.insert((name[old].clone(), kind(m), name2[new].clone()));
            }
            Match::Changed { old, new } | Match::Uncertain { old, new } => {
                found.insert((name[old].clone(), kind(m), name2[new].clone()));
            }
            Match::Added { new } => {
                found.insert((String::new(), kind(m), name2[new].clone()));
            }
            Match::Removed { old } => {
                found.insert((name[old].clone(), kind(m), String::new()));
            }
        }
    }
    // `show` references an anonymous readonly object with no proven extent,
    // so it is uncertain rather than claiming equality from a NUL prefix.
    // `total` changed; `gone`/`fresh` are one-sided; `_start` changed;
    // `sel` has swapped loop arms. Import stubs are excluded.
    let expected: BTreeSet<(String, &str, String)> = [
        ("show", "uncertain", "show"),
        ("total", "changed", "total"),
        ("", "added", "fresh"),
        ("gone", "removed", ""),
        ("_start", "changed", "_start"),
        ("sel", "changed", "sel"),
        ("scale", "changed", "scale"),
        ("fib", "same", "fib"),
    ]
    .into_iter()
    .map(|(f, k, g)| (f.to_owned(), k, g.to_owned()))
    .collect();
    assert_eq!(found, expected, "{arch}");
}

#[test]
fn x86_64() {
    check("x86_64");
}

#[test]
fn aarch64() {
    check("aarch64");
}

fn build_source(arch: &str, label: &str, source: &str, base: u64) -> PathBuf {
    build_input(arch, label, source, base, "c", &[])
}

fn build_assembly(arch: &str, label: &str, source: &str, base: u64) -> PathBuf {
    build_input(
        arch,
        label,
        source,
        base,
        "S",
        &[format!("-Wl,--section-start=.rodata={:#x}", base + 0x10000)],
    )
}

fn build_input(
    arch: &str,
    label: &str,
    source: &str,
    base: u64,
    extension: &str,
    extra: &[String],
) -> PathBuf {
    let path = tmp().join(format!("diff-regression-{arch}-{label}.{extension}"));
    let out = path.with_extension("elf");
    std::fs::write(&path, source).unwrap();
    let status = Command::new(env!("BIARA_CLANG"))
        .args([
            &format!("--target={arch}-linux-gnu"),
            "-O1",
            "-nostdlib",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-asynchronous-unwind-tables",
            "-fno-optimize-sibling-calls",
            "-fpie",
            "-pie",
            "-Wl,--no-dynamic-linker",
            "-fuse-ld=lld",
            &format!("--ld-path={}", linker().display()),
            &format!("-Wl,--image-base={base:#x}"),
            "-o",
        ])
        .arg(&out)
        .arg(&path)
        .args(extra)
        .status()
        .unwrap();
    assert!(status.success(), "building regression {arch}/{label}");
    out
}

fn pair_named(matches: &[Match], old: &Program, new: &Program, name: &str) -> Match {
    matches
        .iter()
        .find(|m| match **m {
            Match::Same { old: o, new: n }
            | Match::Changed { old: o, new: n }
            | Match::Uncertain { old: o, new: n } => {
                old.name_of(o).as_deref() == Some(name) && new.name_of(n).as_deref() == Some(name)
            }
            _ => false,
        })
        .unwrap_or_else(|| panic!("missing paired {name}: {matches:?}"))
        .clone()
}

fn regressions(arch: &str) {
    let source = |answer: i32, predicate: &str, leaf: &str| {
        format!(
            r#"
        __attribute__((noinline)) int {leaf}(void) {{ __asm__ volatile("" ::: "memory"); return {answer}; }}
        __attribute__((noinline)) int predicate(int x) {{ return x {predicate} 7; }}
        void _start(void) {{
            int result = {leaf}();
            for (;;) __asm__ volatile("" : : "r"(result) : "memory");
        }}
    "#
        )
    };
    let (image1, cfg1) = recover(
        arch,
        &build_source(arch, "constants-old", &source(1, "<", "answer"), 0x400000),
    );
    let (image2, cfg2) = recover(
        arch,
        &build_source(arch, "constants-new", &source(2, ">", "answer"), 0x400000),
    );
    let old = Program::new(&cfg1, &image1);
    let new = Program::new(&cfg2, &image2);
    let matches = diff(&old, &new);
    for name in ["answer", "predicate", "_start"] {
        assert!(
            matches!(
                pair_named(&matches, &old, &new, name),
                Match::Changed { .. }
            ),
            "{arch}/{name}: {matches:?}"
        );
    }
    let (image3, cfg3) = recover(
        arch,
        &build_source(
            arch,
            "renamed-rebased",
            &source(1, "<", "renamed"),
            0x700000,
        ),
    );
    let rebased = Program::new(&cfg3, &image3);
    let matches = diff(&old, &rebased);
    let answer = cfg1
        .functions
        .keys()
        .find(|&&e| old.name_of(e).as_deref() == Some("answer"))
        .unwrap();
    assert!(matches.iter().any(|m| matches!(*m, Match::Same { old: o, new: n } if o == *answer && rebased.name_of(n).as_deref() == Some("renamed"))), "{arch}: {matches:?}");
    assert!(
        matches.iter().all(|m| matches!(m, Match::Same { .. })),
        "{arch}: {matches:?}"
    );

    // A translation failure at a matched callee prevents both its own equality
    // claim and its callers' claims, even when their recovered code is equal.
    let mut partial = cfg3;
    let entry = partial
        .functions
        .keys()
        .find(|&&e| rebased.name_of(e).as_deref() == Some("renamed"))
        .copied()
        .unwrap();
    partial
        .unresolved
        .insert(entry, "regression translation failure".into());
    let partial_program = Program::new(&partial, &image3);
    assert!(!partial_program.comparison_issues().is_empty());
    let matches = diff(&old, &partial_program);
    assert!(matches!(
        pair_named(&matches, &old, &partial_program, "_start"),
        Match::Uncertain { .. }
    ));
    assert!(
        matches
            .iter()
            .any(|m| matches!(*m, Match::Uncertain { old: o, .. } if o == *answer))
    );

    partial.unresolved.clear();
    let (site, ret) = partial
        .blocks
        .iter()
        .find_map(|(&b, bb)| {
            bb.exits.iter().find_map(|exit| match exit.kind {
                biara_cfg::ExitKind::Call { ret, .. } => Some((b, ret)),
                _ => None,
            })
        })
        .unwrap();
    for exit in &mut std::sync::Arc::make_mut(partial.blocks.get_mut(&site).unwrap()).exits {
        if matches!(exit.kind, biara_cfg::ExitKind::Call { .. }) {
            exit.kind = biara_cfg::ExitKind::IndirectCall { ret, slot: None };
        }
    }
    partial.indirect_calls.insert(
        site,
        biara_cfg::IndirectTargets {
            targets: BTreeSet::from([entry]),
            complete: false,
        },
    );
    let incomplete_call = Program::new(&partial, &image3);
    assert!(
        incomplete_call
            .comparison_issues()
            .iter()
            .any(|issue| matches!(issue,
        biara_diff::ComparisonIssue::Incomplete { address: Some(a), .. } if *a == site))
    );
    assert!(
        diff(&incomplete_call, &incomplete_call)
            .iter()
            .any(|m| matches!(m, Match::Uncertain { .. }))
    );
    partial.indirect_calls.get_mut(&site).unwrap().complete = true;
    let complete_call = Program::new(&partial, &image3);
    assert!(
        diff(&complete_call, &complete_call)
            .iter()
            .all(|m| matches!(m, Match::Same { .. }))
    );

    std::sync::Arc::make_mut(partial.blocks.get_mut(&entry).unwrap()).exits[0].kind =
        biara_cfg::ExitKind::IndirectJump { slot: None };
    partial.jump_tables.insert(entry, BTreeSet::from([entry]));
    partial.incomplete_jump_tables.insert(entry);
    let incomplete_jump = Program::new(&partial, &image3);
    assert!(
        incomplete_jump
            .comparison_issues()
            .iter()
            .any(|issue| matches!(issue,
        biara_diff::ComparisonIssue::Incomplete { address: Some(a), .. } if *a == entry))
    );
    assert!(
        diff(&incomplete_jump, &incomplete_jump)
            .iter()
            .any(|m| matches!(m, Match::Uncertain { .. }))
    );

    // The immediate is a numeric value, even though it coincides with the
    // image's mapped base. Rebasing must not erase a simultaneous literal edit.
    let (literal_image, literal_cfg) = recover(
        arch,
        &build_source(
            arch,
            "mapped-literal-old",
            &source(0x400000, "<", "answer"),
            0x400000,
        ),
    );
    let (edited_image, edited_cfg) = recover(
        arch,
        &build_source(
            arch,
            "mapped-literal-new",
            &source(0x700000, "<", "answer"),
            0x700000,
        ),
    );
    let literal = Program::new(&literal_cfg, &literal_image);
    let edited = Program::new(&edited_cfg, &edited_image);
    assert!(matches!(
        pair_named(&diff(&literal, &edited), &literal, &edited, "answer"),
        Match::Changed { .. }
    ));

    for named in [false, true] {
        let data_source = |text: &str| {
            format!(
                r#"
            const char message[] = "{text}";
            __attribute__((noinline)) const char *answer(void) {{ return {object}; }}
            void _start(void) {{
                const char *result = answer();
                for (;;) __asm__ volatile("" : : "r"(result) : "memory");
            }}
        "#,
                object = if named {
                    "message".to_owned()
                } else {
                    format!("\"{text}\"")
                }
            )
        };
        let label = if named { "named" } else { "anonymous" };
        let (data_image1, data_cfg1) = recover(
            arch,
            &build_source(
                arch,
                &format!("data-{label}-old"),
                &data_source("old"),
                0x400000,
            ),
        );
        let (data_image2, data_cfg2) = recover(
            arch,
            &build_source(
                arch,
                &format!("data-{label}-new"),
                &data_source("new"),
                0x400000,
            ),
        );
        let data_old = Program::new(&data_cfg1, &data_image1);
        let data_new = Program::new(&data_cfg2, &data_image2);
        let pair = pair_named(&diff(&data_old, &data_new), &data_old, &data_new, "answer");
        assert!(
            !matches!(pair, Match::Same { .. }),
            "{arch}/{label}: {pair:?}"
        );
    }
}

#[test]
fn x86_64_meaningful_code() {
    regressions("x86_64");
}

#[test]
fn aarch64_meaningful_code() {
    regressions("aarch64");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_exit_constant_and_its_caller_change() {
    let source = |value| {
        format!(
            r#"
        __attribute__((noinline)) int answer(void) {{ __asm__ volatile("" ::: "memory"); return {value}; }}
        void _start(void) {{
            long result = answer();
            __asm__ volatile("syscall" : : "a"(60L), "D"(result) : "rcx", "r11", "memory");
            __builtin_unreachable();
        }}
    "#
        )
    };
    let paths = [
        build_source("x86_64", "native-exit-one", &source(1), 0x400000),
        build_source("x86_64", "native-exit-two", &source(2), 0x400000),
    ];
    for (path, expected) in paths.iter().zip([1, 2]) {
        assert_eq!(Command::new(path).status().unwrap().code(), Some(expected));
    }
    let (old_image, old_cfg) = recover("x86_64", &paths[0]);
    let (new_image, new_cfg) = recover("x86_64", &paths[1]);
    let old = Program::new(&old_cfg, &old_image);
    let new = Program::new(&new_cfg, &new_image);
    let matches = diff(&old, &new);
    for name in ["answer", "_start"] {
        assert!(matches!(
            pair_named(&matches, &old, &new, name),
            Match::Changed { .. }
        ));
    }
}

#[test]
fn rip_relative_address_and_equal_numeric_immediate_are_distinct_uses() {
    let assembly = |address: u64| {
        format!(
            r#"
        .intel_syntax noprefix
        .text
        .globl answer
        .type answer,@function
        answer:
            cmp DWORD PTR [rip + object], {address}
            sete al
            movzx eax, al
            ret
        .size answer, .-answer
        .globl _start
        .type _start,@function
        _start:
            call answer
        1:  jmp 1b
        .size _start, .-_start
        .section .rodata
        .type object,@object
        object: .long 7
        .size object,4
    "#
        )
    };
    let (old_image, old_cfg) = recover(
        "x86_64",
        &build_assembly("x86_64", "cmp-address-old", &assembly(0x410000), 0x400000),
    );
    let (new_image, new_cfg) = recover(
        "x86_64",
        &build_assembly("x86_64", "cmp-address-new", &assembly(0x710000), 0x700000),
    );
    let old = Program::new(&old_cfg, &old_image);
    let new = Program::new(&new_cfg, &new_image);
    for name in ["answer", "_start"] {
        assert!(matches!(
            pair_named(&diff(&old, &new), &old, &new, name),
            Match::Changed { .. }
        ));
    }
}

#[test]
fn anonymous_binary_readonly_objects_have_no_nul_inferred_extent() {
    for arch in ["x86_64", "aarch64"] {
        let assembly = |value| {
            if arch == "x86_64" {
                format!(
                    r#"
                    .intel_syntax noprefix
                    .text
                    .globl answer
                    .type answer,@function
                    answer: mov eax,DWORD PTR [rip + object]
                        ret
                    .size answer,.-answer
                    .globl _start
                    .type _start,@function
                    _start: call answer
                    1: jmp 1b
                    .size _start,.-_start
                    .section .rodata
                    .type object,@object
                    object: .long {value}
                    .size object,4
                "#
                )
            } else {
                format!(
                    r#"
                    .text
                    .globl answer
                    .type answer,%function
                    answer: adrp x0,object
                        add x0,x0,:lo12:object
                        ldr w0,[x0]
                        ret
                    .size answer,.-answer
                    .globl _start
                    .type _start,%function
                    _start: bl answer
                    1: b 1b
                    .size _start,.-_start
                    .section .rodata
                    .type object,%object
                    object: .long {value}
                    .size object,4
                "#
                )
            }
        };
        let (mut old_image, old_cfg) = recover(
            arch,
            &build_assembly(arch, "embedded-nul-old", &assembly(256), 0x400000),
        );
        let (mut new_image, new_cfg) = recover(
            arch,
            &build_assembly(arch, "embedded-nul-new", &assembly(512), 0x400000),
        );
        // Function symbols remain for pairing, but no data-object extent is
        // supplied, exactly as for a stripped readonly referent.
        old_image.symbols.retain(|s| s.is_function);
        new_image.symbols.retain(|s| s.is_function);
        let old = Program::new(&old_cfg, &old_image);
        let new = Program::new(&new_cfg, &new_image);
        assert!(!old.comparison_issues().is_empty());
        for name in ["answer", "_start"] {
            assert!(
                matches!(
                    pair_named(&diff(&old, &new), &old, &new, name),
                    Match::Uncertain { .. }
                ),
                "{arch}/{name}"
            );
        }
    }
}

#[test]
fn add_overwriting_adrp_register_invalidates_page_provenance() {
    let assembly = |offset, gap, value| {
        format!(
            r#"
        .text
        .globl answer
        .type answer,%function
        answer:
            adrp x0,first_object
            add x0,x0,#8
            add x1,x0,#{offset}
            ldr w0,[x1]
            ret
        .size answer,.-answer
        .globl _start
        .type _start,%function
        _start: bl answer
        1: b 1b
        .size _start,.-_start
        .section .rodata
        .space 8
        .type first_object,%object
        first_object: .long 7
        .size first_object,4
        .space {gap}
        .type second_object,%object
        second_object: .long 9
        .size second_object,4
        .space 4
        actual_value: .long {value}
    "#
        )
    };
    let (old_image, old_cfg) = recover(
        "aarch64",
        &build_assembly(
            "aarch64",
            "page-overwrite-old",
            &assembly(16, 4, 256),
            0x400000,
        ),
    );
    let (new_image, new_cfg) = recover(
        "aarch64",
        &build_assembly(
            "aarch64",
            "page-overwrite-new",
            &assembly(32, 20, 512),
            0x400000,
        ),
    );
    let old = Program::new(&old_cfg, &old_image);
    let new = Program::new(&new_cfg, &new_image);
    for name in ["answer", "_start"] {
        assert!(matches!(
            pair_named(&diff(&old, &new), &old, &new, name),
            Match::Changed { .. }
        ));
    }
}
