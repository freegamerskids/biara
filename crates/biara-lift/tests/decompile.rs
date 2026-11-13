//! Decompilation to C, end to end: build the test corpus
//! (tests/aarch64/corpus.c) for AArch64 and x86-64 at -O0 and -O2, map it at
//! its link address in this process, decompile every corpus function, compile
//! the C for the host with the pinned clang (warnings are errors), load it and
//! compare every function with its Rust reference (tests/common/corpus.rs)
//! or, for x86-64, with the corpus function itself.
//!
//! Requires libtcg-x86_64.so and libtcg-aarch64.so (scripts/build-libtcg.sh
//! x86_64 aarch64); BIARA_LIBTCG_DIR and BIARA_CLANG are set by
//! .cargo/config.toml.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;

use std::{
    ffi::{CString, c_void},
    process::Command,
};

use biara_lift::{ResolveOptions, analysis_machine, prepare_c, recover_resolving};
use biara_tcg::Libtcg;
use common::{
    corpus::{self, FUNCTIONS, inputs},
    tmp,
};

/// A decompiled corpus build, compiled and loaded.
struct Built {
    source: String,
    handle: *mut c_void,
    /// C parameters of each corpus function, as indices of its two inputs.
    params: Vec<(&'static str, Vec<usize>)>,
    /// Where the corpus functions are when the host can run them (x86-64):
    /// the oracle instead of the Rust references, which saturate
    /// out-of-range float conversions where x86-64 does not.
    native: Vec<(&'static str, u64)>,
}

/// Decompile the corpus built for `target` at `-O{opt}` (linked at `base`),
/// compile and load the C.
fn build(arch: &str, target: &str, opt: u8, base: u64) -> Built {
    let image = corpus::build(target, opt, base);
    let host = arch == std::env::consts::ARCH;
    corpus::map(&image, host);
    let shared = Libtcg::load(&Libtcg::find(arch).expect("libtcg"), None).unwrap();
    let mut lib = shared.lock();
    let machine = analysis_machine().unwrap();
    let present: Vec<(&str, u64)> = FUNCTIONS
        .iter()
        .filter_map(|&(n, _)| image.symbol(n).map(|s| (n, s.addr)))
        .collect();
    let entries: Vec<u64> = present.iter().map(|&(_, a)| a).collect();
    let cfg = recover_resolving(
        &mut *lib,
        &machine,
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &entries,
        ResolveOptions::default(),
    )
    .unwrap();
    assert!(cfg.unresolved.is_empty(), "unresolved {:?}", cfg.unresolved);
    let info = lib.info().clone();
    let abis = biara_abi::analyze(&cfg, &info).unwrap();
    let name_of = |a: u64| image.function_at(a).map(|s| s.name.clone());
    let cx = inkwell::context::Context::create();
    let prepared = prepare_c(
        &cx,
        &machine,
        &info,
        &cfg,
        &abis,
        &name_of,
        "corpus",
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
    let transformed = prepared
        .transform(
            &machine,
            &|addr, buf| image.read_const(addr, buf),
            biara_lift::DecompileOptions::default(),
        )
        .unwrap();
    let mut bytes = Vec::new();
    let stats = transformed.render(&mut bytes).unwrap();
    let source = String::from_utf8(bytes).unwrap();
    assert_eq!(
        stats.unsupported, 0,
        "{target} -O{opt}: placeholders\n{source}",
    );

    // Parameters: the convention's argument registers up to the last one
    // used; the first two carry the inputs, any others get zero.
    let spec = cfg.spec(&info.arch).unwrap();
    let id = |n: &str| {
        info.globals
            .iter()
            .position(|g| g.name.as_deref() == Some(n))
    };
    let conv: Vec<u32> = spec
        .unknown_call
        .args
        .iter()
        .map(|n| id(n).unwrap() as u32)
        .collect();
    let params = present
        .iter()
        .map(|&(n, a)| {
            let args = &abis[&a].args;
            let used = conv
                .iter()
                .rposition(|g| args.contains(g))
                .map_or(0, |i| i + 1);
            (n, (0..used).collect())
        })
        .collect();

    // Helpers become function pointers this test fills in; the CPU state
    // the C refers to starts as libtcg's initial state.
    let dir = tmp().join(format!("decompile-{arch}-O{opt}"));
    std::fs::create_dir_all(&dir).unwrap();
    let c = dir.join("corpus.c");
    std::fs::write(&c, &source).unwrap();
    let cpu = source.contains("extern struct cpu_state biara_cpu;");
    let harness = dir.join("harness.c");
    std::fs::write(
        &harness,
        format!(
            "#include \"corpus.c\"\n{}",
            if cpu {
                "struct cpu_state biara_cpu;\n"
            } else {
                ""
            }
        ),
    )
    .unwrap();
    let helpers: Vec<(String, usize)> = cfg
        .helpers()
        .filter(|h| source.contains(&format!("{}(", h.symbol())))
        .map(|h| (h.name.clone(), h.addr))
        .collect();
    let so = dir.join("corpus.so");
    let status = Command::new(env!("BIARA_CLANG"))
        .args(["-std=gnu17", "-O1", "-shared", "-fPIC", "-fno-builtin"])
        .args(["-fno-strict-aliasing", "-Wall", "-Werror", "-Wno-unused"])
        .args(
            helpers
                .iter()
                .map(|(n, _)| format!("-Dhelper_{n}=(*biara_h_{n})")),
        )
        .arg(format!("--ld-path={}", common::linker().display()))
        .arg("-o")
        .arg(&so)
        .arg(&harness)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "{target} -O{opt}: compiling {}",
        c.display()
    );

    let path = CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
    let sym = |n: &str| {
        let n = CString::new(n).unwrap();
        unsafe { libc::dlsym(handle, n.as_ptr()) }
    };
    for (n, addr) in &helpers {
        let p = sym(&format!("biara_h_{n}")).cast::<usize>();
        assert!(!p.is_null(), "biara_h_{n}");
        unsafe { p.write(*addr) };
    }
    if cpu {
        let p = sym("biara_cpu").cast::<u8>();
        assert!(!p.is_null());
        let env = lib.env();
        unsafe { std::ptr::copy_nonoverlapping(env, p.add(256), info.env_size) };
    }
    drop(lib);
    Built {
        source,
        handle,
        params,
        native: if host { present } else { Vec::new() },
    }
}

fn run(b: &Built, label: &str) {
    for &(name, reference) in FUNCTIONS {
        let Some((_, params)) = b.params.iter().find(|(n, _)| *n == name) else {
            continue;
        };
        let n = CString::new(name).unwrap();
        let f = unsafe { libc::dlsym(b.handle, n.as_ptr()) };
        assert!(!f.is_null(), "{label}: no {name}");
        for (a, x) in inputs() {
            // Arguments by convention position; at most six registers.
            let mut v = [0u64; 6];
            for (k, &p) in params.iter().enumerate() {
                v[k] = [a, x].get(p).copied().unwrap_or(0);
            }
            type F = extern "C" fn(u64, u64, u64, u64, u64, u64) -> u64;
            assert!(params.len() <= 6, "{label}: {name} takes {params:?}");
            // Extra arguments are harmless in the host's C convention.
            let f: F = unsafe { std::mem::transmute::<*mut c_void, F>(f) };
            let got = f(v[0], v[1], v[2], v[3], v[4], v[5]);
            let expected = match b.native.iter().find(|(n, _)| *n == name) {
                Some(&(_, addr)) => {
                    let f: extern "C" fn(u64, u64) -> u64 = unsafe { std::mem::transmute(addr) };
                    f(a, x)
                }
                None => reference(a, x),
            };
            assert_eq!(
                got, expected,
                "{label}: {name}({a:#x}, {x:#x})\n{}",
                b.source
            );
        }
    }
}

#[test]
fn aarch64() {
    for (opt, base) in [(0, 0x5a10_0000_0000), (2, 0x5a12_0000_0000)] {
        let b = build("aarch64", "aarch64-linux-gnu", opt, base);
        let label = format!("aarch64 -O{opt}");
        run(&b, &label);
    }
}

#[test]
fn x86_64() {
    for (opt, base) in [(0, 0x5a14_0000_0000), (2, 0x5a16_0000_0000)] {
        let b = build("x86_64", "x86_64-linux-gnu", opt, base);
        let label = format!("x86_64 -O{opt}");
        run(&b, &label);
    }
}
