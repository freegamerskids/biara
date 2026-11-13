//! The sample program, end to end: build `examples/sample/sample.c`,
//! run the original binary, decompile the whole program to C, compile it,
//! run it in this process over the mapped image, and compare its output and
//! function results with the original's across arithmetic, recursion, imports
//! and indirect calls.
//!
//! Requires libtcg-x86_64.so (scripts/build-libtcg.sh x86_64);
//! BIARA_LIBTCG_DIR and BIARA_CLANG are set by .cargo/config.toml.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;

use std::{ffi::CString, path::PathBuf, process::Command};

use biara_lift::{ResolveOptions, analysis_machine, recover_resolving};
use biara_loader::Image;
use biara_tcg::Libtcg;
use common::{corpus, linker, tmp};

fn calc(op: u64, a: u64, b: u64) -> u64 {
    let (a, b) = (a as i64, b as i64);
    (match op as u32 {
        0 => a.wrapping_add(b),
        1 => a.wrapping_sub(b),
        2 => a.wrapping_mul(b),
        3 => {
            if b != 0 {
                a / b
            } else {
                0
            }
        }
        4 => {
            if b != 0 {
                a % b
            } else {
                0
            }
        }
        5 => a & b,
        6 => a | b,
        7 => a ^ b,
        _ => -1,
    }) as u64
}

fn apply(which: u64, a: u64, b: u64) -> u64 {
    match which & 3 {
        0 => a.wrapping_add(b),
        1 => a.wrapping_sub(b),
        2 => a.wrapping_mul(b),
        _ => (a ^ b) << 2,
    }
}

/// Build the sample as a non-PIE executable (absolute guest addresses).
fn build_sample() -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/sample.c");
    let out = tmp().join("sample");
    let status = Command::new(env!("BIARA_CLANG"))
        .args([
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fno-stack-protector",
            "-U_FORTIFY_SOURCE",
        ])
        .args([
            "-D_FORTIFY_SOURCE=0",
            "-Wno-format-security",
            "-no-pie",
            "-fno-pie",
        ])
        .arg(format!("--ld-path={}", linker().display()))
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap();
    assert!(status.success(), "building the sample");
    out
}

fn run_original(bin: &PathBuf, args: &[&str], stdin: Option<&PathBuf>) -> String {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(f) = stdin {
        cmd.stdin(std::fs::File::open(f).unwrap());
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: status={} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Call the decompiled `guest_main(argc, argv)` with stdout (and stdin)
/// redirected, and return what it printed.
fn run_guest(
    main: extern "C" fn(u64, *const u64) -> u64,
    args: &[&str],
    stdin: Option<&PathBuf>,
) -> String {
    unsafe {
        // The guest wants argv[0] (its name) too: the cases start at the command.
        let full: Vec<&str> = std::iter::once("sample")
            .chain(args.iter().copied())
            .collect();
        let argv: Vec<CString> = full.iter().map(|a| CString::new(*a).unwrap()).collect();
        let ptrs: Vec<u64> = argv.iter().map(|a| a.as_ptr() as u64).collect();
        // `struct s1`: argv[0..4] as fields.
        let mut s1 = [0u64; 4];
        s1[..ptrs.len().min(4)].copy_from_slice(&ptrs[..ptrs.len().min(4)]);

        let out = tmp().join("guest.out");
        let fd = libc::open(
            CString::new(out.to_str().unwrap()).unwrap().as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        assert!(fd >= 0);
        let saved_out = libc::dup(1);
        assert_eq!(libc::dup2(fd, 1), 1);
        let saved_in;
        if let Some(f) = stdin {
            let ifd = libc::open(
                CString::new(f.to_str().unwrap()).unwrap().as_ptr(),
                libc::O_RDONLY,
            );
            assert!(ifd >= 0);
            saved_in = libc::dup(0);
            assert_eq!(libc::dup2(ifd, 0), 0);
            libc::close(ifd);
        } else {
            saved_in = -1;
        }
        let rc = main(full.len() as u64, s1.as_ptr());
        libc::fflush(std::ptr::null_mut());
        libc::dup2(saved_out, 1);
        libc::close(saved_out);
        libc::close(fd);
        if saved_in >= 0 {
            libc::dup2(saved_in, 0);
            libc::close(saved_in);
        }
        assert_eq!(rc, 0, "{args:?}");
        std::fs::read_to_string(&out).unwrap()
    }
}

#[test]
fn sample() {
    let bin = build_sample();
    let empty = tmp().join("empty");
    std::fs::write(&empty, "").unwrap();
    let cases: Vec<(Vec<&str>, Option<PathBuf>)> = vec![
        (vec!["calc", "7", "5"], None),
        (vec!["apply", "7", "5"], None),
        (vec!["fib", "10"], None),
        (vec!["hello", "world"], None),
        (vec!["name"], Some(empty.clone())),
    ];
    let expected: Vec<String> = cases
        .iter()
        .map(|(a, s)| run_original(&bin, a, s.as_ref()))
        .collect();

    let image = Image::load(&bin).unwrap();
    let shared = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg"), None).unwrap();
    let mut lib = shared.lock();
    let machine = analysis_machine().unwrap();
    let discovery = biara_cfg::Discovery {
        code: image.code.clone(),
        extents: image.function_extents(),
        data_pointers: image.code_pointers.clone(),
    };
    let entries: Vec<u64> = image.function_starts().into_iter().collect();
    let cfg = recover_resolving(
        &mut *lib,
        &machine,
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &entries,
        ResolveOptions {
            cfg: biara_cfg::Options {
                os: image.os,
                imports: image.imports.clone(),
                discovery: Some(discovery),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    assert!(cfg.unresolved.is_empty(), "unresolved {:?}", cfg.unresolved);
    let info = lib.info().clone();
    let abis = biara_abi::analyze(&cfg, &info).unwrap();
    let name_of = |a: u64| image.function_at(a).map(|s| s.name.clone());
    let cx = inkwell::context::Context::create();
    let prepared = biara_lift::prepare_c(
        &cx,
        &machine,
        &info,
        &cfg,
        &abis,
        &name_of,
        "sample",
        &image.data,
    )
    .unwrap();
    drop(abis);
    let transformed = prepared
        .transform(
            &machine,
            &|addr, buf| image.read_const(addr, buf),
            biara_lift::DecompileOptions::default(),
        )
        .unwrap();
    // Keep `image` alive: the decompiled guest runs over the mapped image below.
    let mut source = Vec::new();
    let stats = transformed.render(&mut source).unwrap();
    let source = String::from_utf8(source).unwrap();
    assert_eq!(stats.unsupported, 0, "placeholders\n{source}");

    let dir = tmp().join("sample-c");
    std::fs::create_dir_all(&dir).unwrap();
    let c = dir.join("sample.c");
    std::fs::write(&c, &source).unwrap();
    let cpu = source.contains("extern struct cpu_state biara_cpu;");
    let harness = dir.join("harness.c");
    std::fs::write(
        &harness,
        format!(
            "#include \"sample.c\"\n{}",
            if cpu {
                "struct cpu_state biara_cpu;\n"
            } else {
                ""
            },
        ),
    )
    .unwrap();
    let so = dir.join("sample.so");
    let status = Command::new(env!("BIARA_CLANG"))
        .args([
            "-std=gnu17",
            "-O1",
            "-shared",
            "-fPIC",
            "-fno-builtin",
            "-nostdlib",
        ])
        .args(["-fno-strict-aliasing", "-Wall", "-Werror", "-Wno-unused"])
        .arg(format!("--ld-path={}", linker().display()))
        .arg("-o")
        .arg(&so)
        .arg(&harness)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {}", c.display());

    // Guest addresses are absolute: run over the mapped image.
    corpus::map(&image, false);
    let path = CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
    let sym = |n: &str| {
        let n = CString::new(n).unwrap();
        unsafe { libc::dlsym(handle, n.as_ptr()) }
    };
    if cpu {
        let state = sym("biara_cpu").cast::<u8>();
        assert!(!state.is_null(), "biara_cpu");
        unsafe {
            std::ptr::copy_nonoverlapping(lib.env(), state.add(256), info.env_size);
        }
    }

    // Pure functions against the reference, over edges and 64 random pairs.
    let mut pairs = vec![];
    for op in [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        0xff,
        u32::MAX as u64,
        u64::MAX,
    ] {
        pairs.push((op, 7, 5));
        pairs.push((op, 0, 0));
    }
    pairs.push((3, 7, 0));
    pairs.push((4, 7, 0));
    pairs.push((3, i64::MIN as u64, 1));
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..64 {
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        pairs.push((next() & 15, next(), next()));
    }
    type F3 = extern "C" fn(u64, u64, u64) -> u64;
    let f = |n: &str| {
        let p = sym(n);
        assert!(!p.is_null(), "no {n}");
        unsafe { std::mem::transmute::<*mut libc::c_void, F3>(p) }
    };
    let (dcalc, dapply) = (f("calc"), f("apply"));
    for (op, a, b) in &pairs {
        assert_eq!(
            dcalc(*op, *a, *b),
            calc(*op, *a, *b),
            "calc({op}, {a:#x}, {b:#x})"
        );
        assert_eq!(
            dapply(*op, *a, *b),
            apply(*op, *a, *b),
            "apply({op}, {a:#x}, {b:#x})"
        );
    }

    // The whole program: the same argv as the original, the same stdout.
    let guest: extern "C" fn(u64, *const u64) -> u64 =
        unsafe { std::mem::transmute(sym("guest_main")) };
    assert!(!sym("guest_main").is_null(), "no guest_main");
    for ((args, stdin), want) in cases.iter().zip(&expected) {
        let got = run_guest(guest, args, stdin.as_ref());
        assert_eq!(got, *want, "{args:?}");
    }
}
