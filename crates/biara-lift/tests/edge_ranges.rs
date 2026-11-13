//! Behavioral regressions for shared control-flow-edge range refinement
//! (`cpp/edge_ranges.h`, consumed by `cpp/ranges.cpp` and
//! `cpp/jump_tables.cpp`).
//!
//! Each test builds `tests/edge_ranges/corpus.c` for x86-64 at -O0 and -O2
//! with the audit-corpus dynamic-libc flags (`-fno-builtin`,
//! `-fno-stack-protector`, `-fno-pie -no-pie`, real `main`), recovers the
//! CFG, lifts call arguments, and asserts observable behavior: `Arg::Range`
//! bounds on memcpy lengths, recovered indirect-call targets, and concrete
//! runtime ground truth (the corpus `main` sums every boundary length and
//! exits nonzero unless the sum is exactly 1130, so native exit 0 pins the
//! concrete values below, not just "it ran"). Nothing asserts IR shapes.
//! Every tight-bound assertion is paired with containment of feasible
//! extrema, so an unsafe underapproximation fails; bounds stuck at unknown
//! where the edge walk must establish them fail the other way. A bare
//! `Const` never satisfies a containment check: varying lengths must come
//! back as bounded ranges (or per-arm alternatives covering the feasible
//! set).
//!
//! Requires libtcg-x86_64.so (`scripts/build-libtcg.sh`).
#![cfg(target_os = "linux")]

#[path = "common/mod.rs"]
mod common;

use std::{collections::BTreeSet, fs, process::Command};

use biara_cfg::ExitKind;
use biara_lift::{Arg, CallSites, Callee, analysis_machine, audit::audit};
use biara_loader::Image;
use biara_tcg::Libtcg;

fn build(opt: u8) -> std::path::PathBuf {
    let dir = common::tmp().join(format!("edge-ranges-O{opt}"));
    fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("program");
    let output = Command::new(env!("BIARA_CLANG"))
        .args([
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
        ])
        .arg(format!("-O{opt}"))
        .arg("-o")
        .arg(&binary)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/edge_ranges/corpus.c"
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Concrete ground truth: main exits 0 iff every boundary length summed
    // to 1130 (0+94 + 63+16 + 2+46 + 0+64 + 256+257 + 0+32 + 300).
    assert!(
        Command::new(&binary).status().unwrap().success(),
        "native edge-range ground truth"
    );
    binary
}

/// The `memcpy` length in `caller`, resolved through wrappers.
fn length_of(sites: &CallSites, image: &Image, caller: &str) -> Arg {
    let entry = image.symbol(caller).unwrap().addr;
    let site = sites
        .sites()
        .iter()
        .find(|c| c.caller == entry && c.import().is_some_and(|n| n.starts_with("memcpy")))
        .unwrap_or_else(|| panic!("no memcpy call in {caller}"));
    let arg = site.args.get(2).cloned().unwrap_or(Arg::Unknown);
    sites.resolve_arg(&arg, site.caller)
}

/// Require `arg` to be a bounded range (or per-arm alternatives) containing
/// every value in `must_contain` with no value above `max_hi`. A bare
/// `Const` always fails: varying lengths must come back as intervals, never
/// a single folded value.
fn assert_contains(arg: &Arg, must_contain: &[u64], max_hi: u64, what: &str, opt: u8) {
    match arg {
        Arg::Range { lo, hi } => {
            for v in must_contain {
                assert!(
                    *lo <= *v && *v <= *hi,
                    "O{opt}: {what} range [{lo:#x}, {hi:#x}] excludes feasible {v:#x}: {arg}"
                );
            }
            assert!(
                *hi <= max_hi,
                "O{opt}: {what} range [{lo:#x}, {hi:#x}] exceeds bound {max_hi:#x}: {arg}"
            );
        }
        Arg::OneOf(vs) => {
            for v in must_contain {
                assert!(
                    vs.iter().any(|a| match a {
                        Arg::Range { lo, hi } => *lo <= *v && *v <= *hi,
                        // A constant arm covers exactly its one value.
                        Arg::Const(c) => c == v,
                        _ => false,
                    }),
                    "O{opt}: {what} alternatives {arg} exclude feasible {v:#x}"
                );
            }
            for a in vs {
                match a {
                    Arg::Range { hi, .. } => assert!(
                        *hi <= max_hi,
                        "O{opt}: {what} alternative range exceeds bound {max_hi:#x}: {arg}"
                    ),
                    Arg::Const(c) => assert!(
                        must_contain.contains(c),
                        "O{opt}: {what} constant arm {c:#x} is not feasible: {arg}"
                    ),
                    other => panic!("O{opt}: {what} alternative is unbounded: {other}"),
                }
            }
        }
        Arg::Const(c) => panic!(
            "O{opt}: {what} constant {c:#x} cannot cover varying lengths {must_contain:#x?}: {arg}"
        ),
        other => panic!("O{opt}: {what} should be bounded, got {other}"),
    }
}

fn check(opt: u8) {
    let binary = build(opt);
    let image = Image::load(&binary).unwrap();
    let machine = analysis_machine().unwrap();
    let lib = Libtcg::load(&Libtcg::find("x86_64").unwrap(), None).unwrap();
    let mut lib = lib.lock();
    let cfg = common::recover_program(&mut lib, &image);
    let mut sites = CallSites::new(&machine, lib.info(), &cfg).unwrap();
    sites.add(&cfg.functions.keys().copied().collect()).unwrap();

    // `guard_mul`: `n < 48` checked, `n * 2` passed. Baseline LVI sees no
    // comparison on `n * 2` (full); the edge walk must transfer the guard:
    // [0, 94] (n = 0 gives 0, n = 47 gives 94). Non-tautological: the old
    // `n + 8` shape is already [8, 56) at baseline and cannot catch a
    // missing refinement.
    let len = length_of(&sites, &image, "guard_mul");
    assert_contains(&len, &[0, 94], 94, "guard_mul length", opt);

    // `guard_xor`: `n < 48` checked, `n ^ 63` passed: [16, 63] (n = 0 gives
    // 63, n = 47 gives 16). Baseline full; refined both ends.
    let len = length_of(&sites, &image, "guard_xor");
    assert_contains(&len, &[16, 63], 63, "guard_xor length", opt);

    // `audit_edge`: `n < 24` checked, `n * 2` written: [0, 46] (n = 1 gives
    // 2, n = 23 gives 46).
    let len = length_of(&sites, &image, "audit_edge");
    assert_contains(&len, &[2, 46], 46, "audit_edge length", opt);

    // `disjoined`: arm A only admits 0, arm B only 64. The join must hull to
    // cover both, never narrow to one arm.
    let len = length_of(&sites, &image, "disjoined");
    assert_contains(&len, &[0, 64], 64, "disjoined length", opt);

    // `signed_wrap`: full-width `n` under a narrow signed-char guard.
    // n = 256/257 are feasible and must stay contained; a tight contiguous
    // [0, 127] full-width bound would be unsound and fails here. No upper
    // cap: the sound answer is wide.
    let len = length_of(&sites, &image, "signed_wrap");
    match &len {
        Arg::Range { lo, hi } => {
            assert!(
                *lo <= 256 && 256 <= *hi && *lo <= 257 && 257 <= *hi,
                "O{opt}: signed_wrap range [{lo:#x}, {hi:#x}] excludes feasible 256/257: {len}"
            );
        }
        Arg::Unknown => {}
        Arg::OneOf(vs) => {
            for v in [256, 257] {
                assert!(
                    vs.iter().any(|a| match a {
                        Arg::Range { lo, hi } => *lo <= v && v <= *hi,
                        Arg::Const(c) => *c == v,
                        _ => false,
                    }),
                    "O{opt}: signed_wrap alternatives {len} exclude feasible {v:#x}"
                );
            }
        }
        other => panic!("O{opt}: signed_wrap must stay wide, got {other}"),
    }

    // `loop_clamp`: saturates at 32; the loop walk must converge to [0, 32].
    let len = length_of(&sites, &image, "loop_clamp");
    assert_contains(&len, &[0, 32], 32, "loop_clamp length", opt);

    // `loop_open`: genuinely unbounded (n = 300 observed); must stay
    // unknown or wide enough to contain 300, never a tight small bound.
    let len = length_of(&sites, &image, "loop_open");
    match &len {
        Arg::Range { hi, .. } => assert!(
            *hi >= 300,
            "O{opt}: open loop must not invent a tight bound: {len}"
        ),
        Arg::Unknown => {}
        Arg::OneOf(vs) => assert!(
            vs.iter().any(|a| match a {
                Arg::Range { hi, .. } => *hi >= 300,
                Arg::Unknown => true,
                _ => false,
            }),
            "O{opt}: open loop must not invent a tight bound: {len}"
        ),
        other => panic!("O{opt}: open loop must stay wide, got {other}"),
    }

    // `table_edge`: `n < 3` guards `table[n]`; recovery must find exactly
    // {a, b, c} as exhaustive.
    let entry = image.symbol("table_edge").unwrap().addr;
    let site = *cfg.functions[&entry]
        .blocks
        .iter()
        .find(|&&pc| {
            cfg.blocks[&pc].exits.iter().any(|e| {
                matches!(
                    e.kind,
                    ExitKind::IndirectCall { .. } | ExitKind::IndirectJump { .. }
                )
            })
        })
        .unwrap_or_else(|| panic!("O{opt}: table_edge has no indirect transfer"));
    let (targets, complete) = if let Some(call) = cfg.indirect_calls.get(&site) {
        (&call.targets, call.complete)
    } else {
        (
            cfg.jump_tables
                .get(&site)
                .unwrap_or_else(|| panic!("O{opt}: table_edge site {site:#x} unresolved")),
            !cfg.incomplete_jump_tables.contains(&site),
        )
    };
    let expected = BTreeSet::from([
        image.symbol("handle_a").unwrap().addr,
        image.symbol("handle_b").unwrap().addr,
        image.symbol("handle_c").unwrap().addr,
    ]);
    assert_eq!(*targets, expected, "O{opt}: edge-bounded table");
    assert!(complete, "O{opt}: bounded table must be exhaustive");

    // `sparse_switch`: default arm over case gaps {1, 3}. The value reaching
    // the sink on the default path with n = 2 must stay feasible.
    let entry = image.symbol("sparse_switch").unwrap().addr;
    let sink = image.symbol("sparse_sink").unwrap().addr;
    let calls_to_sink: Vec<_> = sites
        .sites()
        .iter()
        .filter(|c| c.caller == entry && matches!(&c.callee, Callee::Function(f) if *f == sink))
        .collect();
    assert!(
        !calls_to_sink.is_empty(),
        "O{opt}: sparse_switch must call sparse_sink"
    );
    // Separate call/tail-call sites may implement individual switch arms.
    // A constant case need not contain 2; the default arm must.
    fn admits_gap(arg: &Arg) -> bool {
        match arg {
            Arg::Range { lo, hi } => *lo <= 2 && 2 <= *hi,
            Arg::OneOf(arms) => arms.iter().any(admits_gap),
            Arg::Const(c) => *c == 2,
            Arg::Unknown | Arg::Incoming(_) => true,
            _ => false,
        }
    }
    assert!(
        calls_to_sink
            .iter()
            .any(|call| admits_gap(&sites.resolve_arg(&call.args[0], call.caller))),
        "O{opt}: gap value 2 must stay feasible at sparse_sink"
    );

    // The import-write audit runs over the refined ranges (exercises the
    // audit path without pinning an exact finding set here).
    let _ = audit(
        &mut sites,
        &image.indirect_entries(),
        image.main,
        &|addr, buf| image.read_const(addr, buf),
        &|_| None,
    )
    .unwrap();
}

#[test]
fn o0() {
    check(0);
}

#[test]
fn o2() {
    check(2);
}
