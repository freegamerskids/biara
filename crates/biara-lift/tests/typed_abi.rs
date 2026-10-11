//! Execute ABI-form generated C, not the env-based lifting interface.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;

use biara_lift::{DecompileOptions, ResolveOptions, host_machine, prepare_c, recover_resolving};
use biara_loader::Image;
use biara_tcg::Libtcg;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    process::Command,
};

const FIXTURE: &str = r#"
typedef unsigned long U;
typedef float V __attribute__((vector_size(16)));
#define KEEP __attribute__((noinline,used))
KEEP double typed_d(double a, double b) { return a*b-a; }
KEEP float typed_f(float a, float b) { return a*b-b; }
KEEP V typed_v(V a, V b) { return a+b; }
KEEP double typed_direct(double a, double b) { return typed_d(a,b)+b; }
KEEP double typed_indirect(double (*f)(double,double), double a, double b) { return f(a,b); }
KEEP double typed_indirect_use(double a, double b) { return typed_indirect(typed_d,a,b)+a; }
KEEP unsigned __int128 typed_pair(U a, U b) { return ((unsigned __int128)b<<64)|a; }
KEEP U typed_pair_use(U a, U b) { unsigned __int128 p=typed_pair(a,b); return (U)p^(U)(p>>64); }
struct Big { U a,b,c; };
KEEP struct Big typed_big(U a) { return (struct Big){a,a+1,a+2}; }
KEEP U typed_big_use(U a) { struct Big p=typed_big(a); return p.a^p.b^p.c; }
#if defined(__aarch64__)
__asm__(".text\n.globl typed_raw\n.type typed_raw,%function\ntyped_raw:\nfmov d0,x0\nfmov x0,d0\nret\n.size typed_raw,.-typed_raw\n");
#else
__asm__(".text\n.globl typed_raw\n.type typed_raw,@function\ntyped_raw:\nmovq %rdi,%xmm0\nmovq %xmm0,%rax\nret\n.size typed_raw,.-typed_raw\n");
#endif
"#;
const WINDOWS_FIXTURE: &str = r#"
typedef unsigned long long U;
int _fltused = 0;
#define KEEP __attribute__((noinline,used))
KEEP double typed_mix(U a, double b, U c, float d) { return a*b+c+d; }
KEEP double typed_mix_call(double a, float b) { return typed_mix(5,a,7,b); }
"#;

fn exercise(arch: &str, target: &str, opt: u8, base: u64) {
    let windows = target.contains("windows");
    let dir = common::tmp().join(format!("typed-{arch}-{windows}-O{opt}"));
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = dir.join("fixture.c");
    std::fs::write(&fixture, if windows { WINDOWS_FIXTURE } else { FIXTURE }).unwrap();
    let binary = dir.join(if windows { "fixture.dll" } else { "fixture" });
    let mut cc = Command::new(env!("BIARA_CLANG"));
    cc.args([
        "-target",
        target,
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-builtin",
        "-ffp-contract=off",
    ])
    .arg(format!("-O{opt}"))
    .arg(&fixture);
    if windows {
        let object = dir.join("fixture.obj");
        assert!(
            cc.arg("-c")
                .arg("-o")
                .arg(&object)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new(common::linker().with_file_name("lld-link"))
                .args([
                    "/nologo",
                    "/dll",
                    "/noentry",
                    "/nodefaultlib",
                    "/machine:x64",
                    "/export:typed_mix",
                    "/export:typed_mix_call"
                ])
                .arg(format!("/base:{base:#x}"))
                .arg(format!("/out:{}", binary.display()))
                .arg(object)
                .status()
                .unwrap()
                .success()
        );
    } else {
        // The fixtures are mapped above 4 GiB; optimized function-address
        // materialization must not use the x86 small model's 32-bit relocation.
        if arch == "x86_64" {
            cc.arg("-mcmodel=large");
        }
        assert!(
            cc.args(["-fno-pie", "-no-pie", "-nostdlib"])
                .arg(format!("--ld-path={}", common::linker().display()))
                .arg(format!("-Wl,-Ttext={base:#x},-e,typed_d"))
                .arg("-o")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
    }
    let image = Image::load(&binary).unwrap();
    common::corpus::map(&image, false);
    let shared = Libtcg::load(&Libtcg::find(arch).unwrap(), None).unwrap();
    let mut lib = shared.lock();
    let machine = host_machine().unwrap();
    let entries: Vec<_> = image
        .symbols
        .iter()
        .filter(|s| s.is_function && s.name.starts_with("typed_"))
        .map(|s| s.addr)
        .collect();
    let mut options = ResolveOptions::default();
    options.cfg.os = image.os;
    let cfg = recover_resolving(
        &mut *lib,
        &machine,
        &|pc| image.code_at(pc),
        &|a, b| image.read_const(a, b),
        &entries,
        options,
    )
    .unwrap();
    let info = lib.info().clone();
    let abis = biara_abi::analyze(&cfg, &info).unwrap();
    if !windows {
        let raw = &abis[&image.symbol("typed_raw").unwrap().addr];
        assert!(
            raw.fp_arg_types.is_empty() && raw.fp_ret_types.is_empty(),
            "raw-bit moves must not become floats: {raw:?}"
        );
    }
    let cx = inkwell::context::Context::create();
    let prepared = prepare_c(
        &cx,
        &machine,
        &info,
        &cfg,
        &abis,
        &|a| image.function_at(a).map(|s| s.name.clone()),
        "typed",
        &BTreeMap::new(),
    )
    .unwrap();
    let mut transformed = prepared
        .transform(
            &machine,
            &|a, b| image.read_const(a, b),
            DecompileOptions::default(),
        )
        .unwrap();
    let facts = transformed.type_facts().unwrap();
    let d = facts
        .signatures
        .iter()
        .find(|s| s.name == if windows { "typed_mix" } else { "typed_d" })
        .unwrap();
    assert_eq!(
        d.params,
        if windows {
            vec![
                biara_lift::AbiTy::I64,
                biara_lift::AbiTy::F64,
                biara_lift::AbiTy::I64,
                biara_lift::AbiTy::F32,
            ]
        } else {
            vec![biara_lift::AbiTy::F64, biara_lift::AbiTy::F64]
        }
    );
    assert_eq!(d.result, biara_lift::AbiResult::One(biara_lift::AbiTy::F64));
    let mut bytes = Vec::new();
    let stats = transformed.render(&mut bytes).unwrap();
    let source = String::from_utf8(bytes).unwrap();
    assert_eq!(stats.unsupported, 0, "{arch} O{opt}: {source}");
    std::fs::write(dir.join("generated.c"), &source).unwrap();
    // A C adapter exercises the host vector ABI without Rust SIMD FFI.
    let harness = if windows {
        format!(
            r#"
#include "generated.c"
{}
int check_scalar(double a, double b) {{
    union {{ double f; uint64_t u; }} x,y;
    x.f=typed_mix(5,a,7,(float)b); y.f=5*a+7+(float)b;
    if(x.u!=y.u) return 1;
    x.f=typed_mix_call(a,(float)b); return x.u!=y.u ? 2 : 0;
}}
"#,
            if source.contains("extern struct cpu_state biara_cpu;") {
                "struct cpu_state biara_cpu;"
            } else {
                ""
            }
        )
    } else {
        format!(
            r#"
#include "generated.c"
{}
int check_scalar(double a, double b) {{
    union {{ double f; uint64_t u; }} x,y;
    x.f=typed_d(a,b); y.f=a*b-a; if(x.u!=y.u) return 1;
    x.f=typed_direct(a,b); y.f=(a*b-a)+b; if(x.u!=y.u) return 2;
    x.f=typed_indirect_use(a,b); y.f=(a*b-a)+a; if(x.u!=y.u) return 3;
    union {{ float f; uint32_t u; }} p,q;
    p.f=typed_f((float)a,(float)b); q.f=(float)a*(float)b-(float)b;
    return p.u!=q.u ? 4 : 0;
}}
int check_vector(void) {{
    biara_v4f a={{1.0f,-2.0f,4.0f,-8.0f}}, b={{0.5f,3.0f,-2.0f,0.0f}};
    biara_v4f v=typed_v(a,b);
    return v[0]!=1.5f || v[1]!=1.0f || v[2]!=2.0f || v[3]!=-8.0f;
}}
"#,
            if source.contains("extern struct cpu_state biara_cpu;") {
                "struct cpu_state biara_cpu;"
            } else {
                ""
            }
        )
    };
    let harness_path = dir.join("harness.c");
    std::fs::write(&harness_path, harness).unwrap();
    let helpers: Vec<_> = cfg
        .helpers()
        .filter(|h| source.contains(&format!("{}(", h.symbol())))
        .map(|h| (h.name.clone(), h.addr))
        .collect();
    let so = dir.join("generated.so");
    let status = Command::new(env!("BIARA_CLANG"))
        .args([
            "-std=gnu17",
            "-O1",
            "-ffp-contract=off",
            "-shared",
            "-fPIC",
            "-fno-builtin",
            "-fno-strict-aliasing",
            "-Wall",
            "-Werror",
            "-Wno-unused",
        ])
        .args(
            helpers
                .iter()
                .map(|(n, _)| format!("-Dhelper_{n}=(*biara_h_{n})")),
        )
        .arg(format!("--ld-path={}", common::linker().display()))
        .arg(&harness_path)
        .arg("-o")
        .arg(&so)
        .status()
        .unwrap();
    assert!(status.success(), "{arch} O{opt}: {}", dir.display());
    let path = CString::new(so.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", so.display());
    let sym = |name: &str| {
        let name = CString::new(name).unwrap();
        let p = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!p.is_null(), "symbol {name:?}");
        p
    };
    for (name, addr) in helpers {
        unsafe {
            sym(&format!("biara_h_{name}")).cast::<usize>().write(addr);
        }
    }
    if source.contains("extern struct cpu_state biara_cpu;") {
        unsafe {
            std::ptr::copy_nonoverlapping(
                lib.env(),
                sym("biara_cpu").cast::<u8>().add(256),
                info.env_size,
            );
        }
    }
    let scalar: extern "C" fn(f64, f64) -> i32 =
        unsafe { std::mem::transmute(sym("check_scalar")) };
    for (a, b) in [
        (0.0, 1.0),
        (-0.0, -1.0),
        (1.25, -3.5),
        (-8.0, 0.5),
        (1048576.0, 0.0625),
    ] {
        assert_eq!(scalar(a, b), 0, "{arch} O{opt}: scalar ({a},{b})");
    }
    if !windows {
        let vector: extern "C" fn() -> i32 = unsafe { std::mem::transmute(sym("check_vector")) };
        assert_eq!(vector(), 0, "{arch} O{opt}: vector");
        let pair: extern "C" fn(u64, u64) -> u64 =
            unsafe { std::mem::transmute(sym("typed_pair_use")) };
        let big: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(sym("typed_big_use")) };
        let raw: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(sym("typed_raw")) };
        for a in [0, 1, 0x8000000000000000, 0x7ff8000012345678, u64::MAX] {
            let b = a.rotate_left(17).wrapping_add(3);
            assert_eq!(pair(a, b), a ^ b, "{arch} O{opt}: register pair");
            assert_eq!(
                big(a),
                a ^ a.wrapping_add(1) ^ a.wrapping_add(2),
                "{arch} O{opt}: memory result"
            );
            assert_eq!(raw(a), a, "{arch} O{opt}: raw bits");
        }
    }
    unsafe {
        libc::dlclose(handle);
    }
    // ELF metadata segments can have the linker's default low address even
    // when .text is high. Each scenario owns its mappings; release them
    // before the next image maps that same header page.
    let pages: BTreeSet<_> = image
        .segments
        .iter()
        .flat_map(|s| ((s.addr & !4095)..(s.addr + s.size).next_multiple_of(4096)).step_by(4096))
        .collect();
    for page in pages {
        assert_eq!(unsafe { libc::munmap(page as *mut libc::c_void, 4096) }, 0);
    }
}

#[test]
fn typed_generated_c_executes() {
    for (i, (arch, target)) in [
        ("x86_64", "x86_64-linux-gnu"),
        ("aarch64", "aarch64-linux-gnu"),
    ]
    .into_iter()
    .enumerate()
    {
        for opt in [0, 2] {
            exercise(
                arch,
                target,
                opt,
                0x5b00_0000_0000 + ((i * 4 + opt as usize) as u64) * 0x1_0000_0000,
            );
        }
    }
    for opt in [0, 2] {
        exercise(
            "x86_64",
            "x86_64-pc-windows-msvc",
            opt,
            0x5b10_0000_0000 + (opt as u64) * 0x1_0000_0000,
        );
    }
}
