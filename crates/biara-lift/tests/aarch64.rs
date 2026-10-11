//! AArch64 differential tests: build tests/aarch64/corpus.c for
//! aarch64-linux-gnu at -O0 and -O2 with the pinned clang, map the result at
//! its link address in this process, lift every corpus function through
//! libtcg-aarch64 -> CFG recovery -> LLVM, JIT it on the host and compare
//! with the Rust reference (tests/common/corpus.rs). Also checks the recovered control flow and
//! calling conventions.
//!
//! Requires libtcg-aarch64.so (scripts/build-libtcg.sh x86_64 aarch64);
//! BIARA_LIBTCG_DIR and BIARA_CLANG are set by .cargo/config.toml. Links with
//! the toolchain's rust-lld.
#![cfg(target_os = "linux")]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

use common::corpus::{self, *};

use biara_cfg::Cfg;
use biara_lift::{RUN, ResolveOptions, host_machine, lift, optimize, recover_resolving};
use biara_loader::Image;
use biara_tcg::Libtcg;
use inkwell::{OptimizationLevel, context::Context};
use parking_lot::Mutex;

const RETURN_SENTINEL: u64 = 0xdead_beef_0000;
/// Corpus link addresses: free in a typical x86-64 Linux address space.
const BASES: [(u8, u64); 2] = [(0, 0x5a00_0000_0000), (2, 0x5a02_0000_0000)];

// ---- corpus ----------------------------------------------------------------

struct Corpus {
    image: Image,
    lib: Arc<Mutex<Libtcg>>,
}

/// The corpus built at `-O{opt}`, mapped at its link address.
fn corpus(opt: u8) -> &'static Corpus {
    static CORPUS: [OnceLock<Corpus>; 2] = [OnceLock::new(), OnceLock::new()];
    let i = BASES.iter().position(|&(o, _)| o == opt).unwrap();
    CORPUS[i].get_or_init(|| {
        let image = corpus::build("aarch64-linux-gnu", opt, BASES[i].1);
        corpus::map(&image, false);
        let lib = Libtcg::load(&Libtcg::find("aarch64").expect("libtcg"), None).unwrap();
        Corpus { image, lib }
    })
}

impl Corpus {
    fn addr(&self, name: &str) -> u64 {
        self.image
            .symbol(name)
            .unwrap_or_else(|| panic!("no symbol {name}"))
            .addr
    }

    /// Recover the functions reachable from `entries`, jump tables included.
    fn recover(&self, lib: &mut Libtcg, entries: &[u64]) -> Cfg {
        let cfg = recover_resolving(
            lib,
            &host_machine().unwrap(),
            &|pc| self.image.code_at(pc),
            &|addr, buf| self.image.read_const(addr, buf),
            entries,
            ResolveOptions::default(),
        )
        .unwrap();
        assert!(cfg.unresolved.is_empty(), "unresolved {:?}", cfg.unresolved);
        cfg
    }
}

/// Lift `name` from both corpus builds and run it at LLVM -O0 and -O2 on
/// every input: x0 must match `reference`, the stack pointer and x19-x29
/// (callee-saved) must come back unchanged, and control must return to lr.
fn check(name: &str, reference: Ref) {
    for (opt, _) in BASES {
        let c = corpus(opt);
        let mut lib = c.lib.lock();
        let entry = c.addr(name);
        // Every corpus function: calls through pointers (t_tramp) reach
        // them by dispatch.
        let mut entries = vec![entry];
        entries.extend(
            FUNCTIONS
                .iter()
                .filter_map(|&(n, _)| c.image.symbol(n).map(|s| s.addr)),
        );
        let cfg = c.recover(&mut lib, &entries);

        let info = lib.info().clone();
        let reg = |n: &str| {
            info.globals
                .iter()
                .find(|g| g.name.as_deref() == Some(n))
                .unwrap_or_else(|| panic!("no global {n}"))
                .mem_offset as usize
        };
        let (x0, x1, sp, lr) = (reg("x0"), reg("x1"), reg("sp"), reg("lr"));
        let pc = info.globals[info.pc_global as usize].mem_offset as usize;
        let saved: Vec<usize> = (19..=29).map(|i| reg(&format!("x{i}"))).collect();

        let env = lib.env();
        let pristine = unsafe { std::slice::from_raw_parts(env, info.env_size) }.to_vec();
        let machine = host_machine().unwrap();

        // Plain lifting, and trusting the recovered calling conventions.
        let abis = biara_abi::analyze(&cfg, &info).unwrap();
        for (jit, abis) in [(0u8, None), (2, None), (0, Some(&abis)), (2, Some(&abis))] {
            let cx = Context::create();
            let module = lift(&cx, &machine, &info, &cfg, abis, &|_| None, name).unwrap();
            if jit > 0 {
                optimize(&module, &machine, jit).unwrap();
            }
            let ee = module
                .create_jit_execution_engine(OptimizationLevel::None)
                .unwrap();
            for h in cfg.helpers() {
                if let Some(decl) = module.get_function(&h.symbol()) {
                    ee.add_global_mapping(&decl, h.addr);
                }
            }
            let run = unsafe { ee.get_function::<unsafe extern "C" fn(*mut u8)>(RUN) }.unwrap();

            let mut stack = vec![0u128; 1024];
            let top = stack.as_mut_ptr_range().end as u64 - 256;
            for (a, b) in inputs() {
                let expected = reference(a, b);
                let w =
                    |off: usize, v: u64| unsafe { env.add(off).cast::<u64>().write_unaligned(v) };
                let r = |off: usize| unsafe { env.add(off).cast::<u64>().read_unaligned() };
                unsafe {
                    std::ptr::copy_nonoverlapping(pristine.as_ptr(), env, pristine.len());
                }
                w(x0, a);
                w(x1, b);
                w(sp, top);
                w(lr, RETURN_SENTINEL);
                w(pc, entry);
                for (i, &s) in saved.iter().enumerate() {
                    w(s, 0x5ead_0000 + i as u64);
                }
                unsafe { run.call(env) };
                let abi = if abis.is_some() { " abi" } else { "" };
                let at = format!("{name} -O{opt} JIT O{jit}{abi} ({a:#x}, {b:#x})");
                assert_eq!(r(pc), RETURN_SENTINEL, "{at}: did not return");
                assert_eq!(r(sp), top, "{at}: sp");
                for (i, &s) in saved.iter().enumerate() {
                    assert_eq!(r(s), 0x5ead_0000 + i as u64, "{at}: x{}", 19 + i);
                }
                assert_eq!(r(x0), expected, "{at}: x0");
            }
        }
    }
}

#[test]
fn arith() {
    check("t_arith", t_arith);
}

#[test]
fn loops() {
    check("t_loop", t_loop);
}

#[test]
fn conditions() {
    check("t_cond", t_cond);
}

#[test]
fn mul_div() {
    check("t_muldiv", t_muldiv);
}

#[test]
fn bit_ops() {
    check("t_bits", t_bits);
}

#[test]
fn flags() {
    check("t_flags", t_flags);
}

#[test]
fn switch() {
    check("t_switch", t_switch);
}

#[test]
fn byte_switch() {
    check("t_byteswitch", t_byteswitch);
    check("t_merged", t_merged);
}

#[test]
fn calls() {
    check("t_calls", t_calls);
}

#[test]
fn memory() {
    check("t_memory", t_memory);
}

#[test]
fn narrow_loads() {
    check("t_narrow", t_narrow);
}

#[test]
fn float() {
    check("t_float", t_float);
}

#[test]
fn words() {
    check("t_w32", t_w32);
}

#[test]
fn atomics() {
    check("t_atomic", t_atomic);
}

#[test]
fn tail() {
    check("t_tail", t_tail);
}

#[test]
fn structs() {
    check("t_structs", t_structs);
}

#[test]
fn trampoline() {
    check("t_tramp", t_tramp);
}

/// Returns (plain and through a reloaded lr), calls and tail calls, and the
/// AAPCS64 view of the corpus's call graph.
#[test]
fn control_flow_and_abi() {
    for (opt, _) in BASES {
        let c = corpus(opt);
        let mut lib = c.lib.lock();
        let (calls, many, fib, tail, arith) = (
            c.addr("t_calls"),
            c.addr("many"),
            c.addr("fib"),
            c.addr("t_tail"),
            c.addr("t_arith"),
        );
        let cfg = c.recover(&mut lib, &[calls, tail, arith]);
        let info = lib.info().clone();
        let at = format!("-O{opt}");

        assert_eq!(
            cfg.functions[&calls].calls,
            BTreeSet::from([many, fib]),
            "{at}"
        );
        assert!(cfg.functions.values().all(|f| f.returns), "{at}");
        if opt > 0 {
            assert_eq!(
                cfg.functions[&tail].tail_calls,
                BTreeSet::from([arith]),
                "{at}"
            );
        } else {
            assert_eq!(cfg.functions[&tail].calls, BTreeSet::from([arith]), "{at}");
        }

        let abis = biara_abi::analyze(&cfg, &info).unwrap();
        let reg = |n: &str| {
            info.globals
                .iter()
                .position(|g| g.name.as_deref() == Some(n))
                .unwrap() as u32
        };
        let names = |set: &BTreeSet<u32>| -> Vec<String> {
            (0..=30)
                .map(|i| {
                    if i == 30 {
                        "lr".to_string()
                    } else {
                        format!("x{i}")
                    }
                })
                .filter(|n| set.contains(&reg(n)))
                .collect()
        };
        let regs = |s: &str| -> Vec<String> { s.split(' ').map(String::from).collect() };

        // many(a..j): x0-x7 plus two stack arguments at the entry sp.
        let m = &abis[&many];
        assert_eq!(names(&m.args), regs("x0 x1 x2 x3 x4 x5 x6 x7"), "{at}");
        assert_eq!(m.stack_args, BTreeSet::from([0, 8]), "{at}");
        assert!(m.returns.contains(&reg("x0")), "{at}");
        assert!(m.frame.balanced, "{at}");

        let t = &abis[&calls];
        assert_eq!(names(&t.args), regs("x0 x1"), "{at}");
        assert!(t.frame.balanced, "{at}");
        let callee_saved: BTreeMap<String, bool> = (19..=29)
            .map(|i| format!("x{i}"))
            .map(|n| {
                let kept = t.preserved.contains(&reg(&n));
                (n, kept)
            })
            .collect();
        assert!(callee_saved.values().all(|&k| k), "{at}: {callee_saved:?}");

        let f = &abis[&fib];
        assert_eq!(names(&f.args), regs("x0"), "{at}");
        assert!(f.returns.contains(&reg("x0")), "{at}");
        assert!(f.preserved.contains(&reg("x19")), "{at}");
    }
}
