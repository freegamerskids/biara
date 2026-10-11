//! Function-local canonicalization at scale: execute 600 lifted functions
//! with distinct constants and branches at LLVM -O0 and -O2. This catches
//! cross-function analysis reuse and lost register/return-state updates.
//!
//! Requires libtcg-x86_64.so (scripts/build-libtcg.sh x86_64);
//! BIARA_LIBTCG_DIR and BIARA_CLANG are set by .cargo/config.toml.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

mod common;

use std::process::Command;

use biara_lift::{ResolveOptions, host_machine, recover_resolving};
use biara_loader::Image;
use biara_tcg::Libtcg;
use common::{linker, tmp};
use inkwell::{OptimizationLevel, context::Context};

const MANY: usize = 600;

#[test]
fn many() {
    let mut src = String::from("typedef unsigned long u64;\n");
    for i in 0..MANY {
        src += &format!("u64 f{i}(u64 x) {{ return (x & 1) ? x * 3 + {i} : x ^ {i}UL * 8; }}\n");
    }
    src += "int main(void) { return 0; }\n";
    let dir = tmp().join("many");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("many.c"), &src).unwrap();
    let bin = dir.join("many");
    let status = Command::new(env!("BIARA_CLANG"))
        .args(["--target=x86_64-linux-gnu", "-O2", "-no-pie", "-fno-pie"])
        .arg(format!("--ld-path={}", linker().display()))
        .arg("-o")
        .arg(&bin)
        .arg(dir.join("many.c"))
        .status()
        .unwrap();
    assert!(status.success(), "building the many-functions binary");

    let image = Image::load(&bin).unwrap();
    let shared = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg"), None).unwrap();
    let mut lib = shared.lock();
    let machine = host_machine().unwrap();
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
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let info = lib.info().clone();
    let abis = biara_abi::analyze(&cfg, &info).unwrap();
    let name_of = |a: u64| image.function_at(a).map(|s| s.name.clone());
    let cx = Context::create();
    let env = lib.env();
    let pristine = unsafe { std::slice::from_raw_parts(env, info.env_size) }.to_vec();
    let offset = |name: &str| {
        info.globals
            .iter()
            .find(|g| g.name.as_deref() == Some(name))
            .unwrap()
            .mem_offset as usize
    };
    let (rdi, rax, rsp, rip) = (offset("rdi"), offset("rax"), offset("rsp"), offset("rip"));
    const RETURN: u64 = 0xfeed_face_0000;
    let mut stack = [0u64; 128];
    stack[120] = RETURN;
    let sp = std::ptr::addr_of!(stack[120]) as u64;
    for opt in [0, 2] {
        let module = biara_lift::lift(&cx, &machine, &info, &cfg, Some(&abis), &name_of, "many")
            .expect("lifting 600 functions");
        if opt != 0 {
            biara_lift::optimize(&module, &machine, opt).unwrap();
        }
        let ee = module
            .create_jit_execution_engine(OptimizationLevel::None)
            .unwrap();
        for h in cfg.helpers() {
            if let Some(decl) = module.get_function(&h.symbol()) {
                ee.add_global_mapping(&decl, h.addr);
            }
        }
        for i in 0..MANY {
            let name = format!("f{i}");
            let entry = image.symbol(&name).unwrap().addr;
            let f = unsafe { ee.get_function::<unsafe extern "C" fn(*mut u8)>(&name) }.unwrap();
            for x in [0, 1, 2, u64::MAX, 1 << 63, 0xdead_beef] {
                unsafe {
                    std::ptr::copy_nonoverlapping(pristine.as_ptr(), env, pristine.len());
                    env.add(rdi).cast::<u64>().write_unaligned(x);
                    env.add(rsp).cast::<u64>().write_unaligned(sp);
                    env.add(rip).cast::<u64>().write_unaligned(entry);
                    f.call(env);
                }
                let read = |offset| unsafe { env.add(offset).cast::<u64>().read_unaligned() };
                let expected = if x & 1 != 0 {
                    x.wrapping_mul(3).wrapping_add(i as u64)
                } else {
                    x ^ (i as u64 * 8)
                };
                assert_eq!(read(rax), expected, "{name} -O{opt} x={x:#x}");
                assert_eq!(read(rip), RETURN, "{name} -O{opt}: return PC");
                assert_eq!(read(rsp), sp + 8, "{name} -O{opt}: stack balance");
            }
        }
    }
}
