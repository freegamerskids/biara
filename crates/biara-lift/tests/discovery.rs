//! Function discovery without symbols: tests/discovery/prog.c built for
//! x86-64 and AArch64 with the pinned clang, position-dependent and
//! position-independent (relocations as RELA or packed RELR), with and
//! without unwind tables, at -O0 and -O2, then stripped. Recovery from what
//! the stripped image offers (entry point, unwind entries, code pointers in
//! data and code) must find exactly the functions the unstripped binary's
//! symbols name: labels whose addresses are in data are no functions, and
//! a function nothing refers to is only found through unwind information.
//!
//! Requires libtcg-x86_64.so and libtcg-aarch64.so (scripts/build-libtcg.sh).
#![cfg(target_os = "linux")]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Command,
};

use biara_loader::Image;
use biara_tcg::Libtcg;
use common::{linker, llvm_tool, recover_program, tmp};

#[derive(Clone, Copy, Debug)]
enum Layout {
    Static,
    Pie,
    PieRelr,
}

/// Build and strip the corpus; the stripped binary and its functions
/// according to the unstripped one's symbols.
fn build(arch: &str, layout: Layout, unwind: bool, opt: u8) -> (PathBuf, BTreeMap<String, u64>) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/discovery/prog.c");
    let name = format!("discovery-{arch}-{layout:?}-{unwind}-O{opt}");
    let out = tmp().join(&name);
    let mut cc = Command::new(env!("BIARA_CLANG"));
    cc.args([&format!("--target={arch}-linux-gnu"), &format!("-O{opt}")])
        .args(["-ffreestanding", "-nostdlib"])
        .arg(format!("--ld-path={}", linker().display()));
    match layout {
        Layout::Static => cc.args(["-fno-pie", "-static"]),
        Layout::Pie => cc.args(["-fpie", "-static-pie"]),
        Layout::PieRelr => cc.args(["-fpie", "-static-pie", "-Wl,-z,pack-relative-relocs"]),
    };
    if unwind {
        cc.args(["-funwind-tables", "-fasynchronous-unwind-tables"]);
    } else {
        cc.args(["-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]);
    }
    let status = cc.arg("-o").arg(&out).arg(&src).status().unwrap();
    assert!(status.success(), "building {name}");

    let truth = Image::load(&out)
        .unwrap()
        .symbols
        .iter()
        .filter(|s| s.is_function)
        .map(|s| (s.name.clone(), s.addr))
        .collect();
    let stripped = tmp().join(format!("{name}.stripped"));
    let status = Command::new(llvm_tool("llvm-strip"))
        .arg("--strip-all")
        .arg(&out)
        .arg("-o")
        .arg(&stripped)
        .status()
        .unwrap();
    assert!(status.success(), "stripping {name}");
    (stripped, truth)
}

/// Entries of the functions recovered from `path`, as the CLI does for a
/// whole program.
fn discover(path: &Path) -> BTreeSet<u64> {
    let image = Image::load(path).unwrap();
    assert!(image.symbols.is_empty(), "{} has symbols", path.display());
    let lib = Libtcg::load(&Libtcg::find(image.arch).expect("libtcg"), None).unwrap();
    let cfg = recover_program(&mut lib.lock(), &image);
    assert!(cfg.unresolved.is_empty(), "{:x?}", cfg.unresolved);
    cfg.functions.keys().copied().collect()
}

fn check(arch: &str) {
    let mut failures = Vec::new();
    for layout in [Layout::Static, Layout::Pie, Layout::PieRelr] {
        for unwind in [true, false] {
            for opt in [0, 2] {
                let (stripped, mut functions) = build(arch, layout, unwind, opt);
                assert_eq!(functions.len(), 10, "{arch} {layout:?}: corpus functions");
                if !unwind {
                    functions.remove("orphan");
                }
                let truth: BTreeSet<u64> = functions.into_values().collect();
                let found = discover(&stripped);
                if found != truth {
                    failures.push(format!(
                        "{arch} {layout:?} unwind={unwind} -O{opt}: missed {:x?}, extra {:x?}",
                        truth.difference(&found).collect::<Vec<_>>(),
                        found.difference(&truth).collect::<Vec<_>>(),
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn x86_64() {
    check("x86_64");
}

#[test]
fn aarch64() {
    check("aarch64");
}

/// Batched candidate prefetch must not publish an interior label: each
/// `lea; ret` callback covers its interior `ret`, which data also points at.
/// Both share a prefetch wave, but sequential acceptance rejects the covered
/// address. Independent callbacks also keep stable sorted selection under a
/// small block budget. These are consumer-visible precision invariants, not
/// backend wiring.
#[test]
fn batched_candidates_reject_covered_interior_labels() {
    use biara_cfg::{Discovery, Options};
    use biara_lift::{ResolveOptions, analysis_machine, recover_resolving};

    // Four `lea rax,[rdi+rdi*2+i]; ret` callbacks, 16 apart with nop pads:
    // entry covers entry+1..entry+4, interior `ret` sits at entry+5. The
    // root is elsewhere, so no callback body exists before discovery: each
    // entry and its interior share the first prefetch wave.
    let base: u64 = 0x40_0000;
    let root: u64 = 0x40_0100;
    let entries: Vec<u64> = (0..4u64).map(|i| base + i * 0x10).collect();
    let mut blobs: Vec<(u64, Vec<u8>)> = vec![(root, vec![0xc3])];
    for (i, &entry) in entries.iter().enumerate() {
        let mut code = vec![0x48, 0x8d, 0x44, 0x7f, (i + 1) as u8, 0xc3];
        while code.len() < 16 {
            code.push(0x90);
        }
        blobs.push((entry, code));
    }
    let code_at = |pc: u64| -> Option<(&[u8], u64)> {
        blobs
            .iter()
            .find(|(start, code)| pc >= *start && pc < *start + code.len() as u64)
            .map(|(start, code)| (code.as_slice(), *start))
    };
    // Data holds both each entry and its interior `ret`: interiors must not
    // become functions even though they share the prefetch wave.
    let pointers: BTreeSet<u64> = entries.iter().flat_map(|&e| [e, e + 5]).collect();
    let opts = ResolveOptions {
        cfg: Options {
            os: "linux",
            discovery: Some(Discovery {
                code: vec![base..base + 0x40, root..root + 1],
                extents: Vec::new(),
                data_pointers: pointers,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let lib = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg"), None).unwrap();
    let machine = analysis_machine().unwrap();
    let cfg = recover_resolving(
        &mut *lib.lock(),
        &machine,
        &code_at,
        &|_, _| false,
        &[root],
        opts,
    )
    .unwrap();
    let found: BTreeSet<u64> = cfg.functions.keys().copied().collect();
    let mut want = entries.iter().copied().collect::<BTreeSet<_>>();
    want.insert(root);
    assert_eq!(found, want);
    assert_eq!(cfg.discovered, entries.iter().copied().collect());
    assert!(cfg.unresolved.is_empty());
}

#[test]
fn independent_candidates_keep_sorted_selection_under_budget() {
    use biara_cfg::{Discovery, Options};
    use biara_lift::{ResolveOptions, analysis_machine, recover_resolving};
    // Seven isolated one-byte `ret`s after a one-byte `ret` root: the root
    // reserves the first block, then sorted candidates fill the budget.
    let base: u64 = 0x50_0000;
    let bytes = [0xc3; 8];
    let code_at = |pc: u64| -> Option<(&[u8], u64)> {
        (pc >= base && pc < base + bytes.len() as u64).then_some((bytes.as_slice(), base))
    };
    let pointers: BTreeSet<u64> = (1..8u64).map(|i| base + i).collect();
    // Root takes 1 block; each further function takes 1 block.
    for (max_blocks, want) in [(2usize, 1usize), (3, 2)] {
        let opts = ResolveOptions {
            cfg: Options {
                os: "linux",
                max_blocks,
                discovery: Some(Discovery {
                    code: std::iter::once(base..base + 8).collect(),
                    extents: Vec::new(),
                    data_pointers: pointers.clone(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let lib = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg"), None).unwrap();
        let machine = analysis_machine().unwrap();
        let cfg = recover_resolving(
            &mut *lib.lock(),
            &machine,
            &code_at,
            &|_, _| false,
            &[base],
            opts,
        )
        .unwrap();
        let found: Vec<u64> = cfg.functions.keys().copied().collect();
        let mut want_vec: Vec<u64> = vec![base];
        want_vec.extend((1..=want as u64).map(|i| base + i));
        assert_eq!(found, want_vec, "max_blocks={max_blocks}");
        assert!(cfg.recovery.block_limit_reached);
    }
}
