//! Lift hand-written x86-64 functions from this test binary through
//! libtcg -> TCG -> CFG recovery -> LLVM, then
//! - check the recovered control flow (calls, tail calls, split blocks,
//!   non-returning callees);
//! - JIT the lifted module against libtcg's CPU state and compare with
//!   running the same machine code natively.
//!
//! Requires libtcg-x86_64.so (scripts/build-libtcg.sh); BIARA_LIBTCG_DIR is
//! set by .cargo/config.toml.
#![cfg(target_arch = "x86_64")]

use std::{arch::global_asm, collections::BTreeSet, ptr::addr_of};

use biara_cfg::{Cfg, ExitKind};
use biara_lift::{RUN, ResolveOptions, host_machine, lift, optimize, recover_resolving};
use biara_tcg::Libtcg;
use inkwell::{OptimizationLevel, context::Context};

global_asm!(
    r#"
    .text
    .globl biara_t_begin
biara_t_begin:

    .globl biara_t_arith
biara_t_arith:
    lea rax, [rdi + rsi*4 + 7]
    imul rax, rsi
    sub rax, rdi
    xor rax, 0x5a5a
    shl rax, 3
    sar rax, 1
    ret

    .globl biara_t_loop
biara_t_loop:
    xor eax, eax
    mov rcx, rsi
    and rcx, 63
    xor edx, edx
2:  cmp rdx, rcx
    jae 3f
    lea r8, [rdx + rdx*2]
    xor r8, rdi
    add rax, r8
    inc rdx
    jmp 2b
3:  ret

    .globl biara_t_cond
biara_t_cond:
    xor eax, eax
    cmp rdi, rsi
    setl al
    mov rcx, rdi
    cmovb rcx, rsi
    shl rax, 32
    add rax, rcx
    test edi, 0x10
    jz 2f
    neg rax
2:  ret

    .globl biara_t_muldiv
biara_t_muldiv:
    mov rax, rdi
    mul rsi
    mov r8, rdx
    mov rcx, rsi
    or rcx, 1
    xor edx, edx
    mov rax, rdi
    div rcx
    add rax, r8
    imul rdx, rdx, 13
    xor rax, rdx
    mov r9, rdi
    add r9, rsi
    adc rax, 0
    sub r9, rdi
    sbb rax, rsi
    ret

    .globl biara_t_dirty_join
biara_t_dirty_join:
    mov r8, rdi
    xor r8, rsi
    test dil, 1
    jz 1f
    mov rax, rdi
    xor edx, edx
    mov rcx, rsi
    or rcx, 1
    div rcx
    add r8, rax
    jmp 2f
1:  rol r8, 9
2:  sub rsp, 8
    call biara_t_dirty_join_inner
    add rsp, 8
    ret
biara_t_dirty_join_inner:
    mov rax, r8
    rol rax, 13
    xor rax, rsi
    ret

    .globl biara_t_stack
biara_t_stack:
    push rbx
    push r12
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rsp]
    call biara_t_stack_inner
    add rax, rbx
    xor rax, r12
    add rsp, 32
    pop r12
    pop rbx
    ret
biara_t_stack_inner:
    mov rax, [rdi]
    mov rcx, [rdi + 8]
    rol rax, 13
    ror rcx, 7
    add rax, rcx
    mov dword ptr [rdi + 16], eax
    movzx edx, word ptr [rdi + 16]
    movsx r8, byte ptr [rdi + 17]
    add rax, rdx
    sub rax, r8
    ret

    .globl biara_t_bits
biara_t_bits:
    bswap rdi
    popcnt rax, rsi
    mov rcx, rdi
    or rcx, 1
    bsr rcx, rcx
    mov rdx, rsi
    or rdx, 0x100
    bsf rdx, rdx
    shl rcx, 8
    shl rdx, 16
    add rax, rcx
    add rax, rdx
    xor rax, rdi
    bt rsi, 5
    adc rax, 0
    movsxd r8, edi
    add rax, r8
    shld rax, rsi, 7
    ret

    .globl biara_t_flags
biara_t_flags:
    mov rax, rdi
    add rax, rsi
    pushfq
    pop rcx
    and ecx, 0x8d5
    mov rax, rdi
    sub rax, rsi
    pushfq
    pop rdx
    and edx, 0x8d5
    shl rdx, 16
    lea rax, [rcx + rdx]
    ret

    .globl biara_t_shift32
biara_t_shift32:
    mov eax, edi
    mov ecx, esi
    shl eax, cl
    mov edx, edi
    sar edx, cl
    xor eax, edx
    ror edx, 5
    add eax, edx
    adc eax, ecx
    ret

    .globl biara_t_tail
biara_t_tail:
    add rdi, 1
    jmp biara_t_arith

    .globl biara_t_split
biara_t_split:
    mov rax, rdi
    xor ecx, ecx
    .globl biara_t_split_loop
biara_t_split_loop:
    add rax, rcx
    inc rcx
    cmp rcx, 5
    jb biara_t_split_loop
    ret

    .globl biara_t_calls_trap
biara_t_calls_trap:
    test rdi, rdi
    jz 2f
    call biara_t_trap
    .globl biara_t_after_trap
biara_t_after_trap:
    mov eax, 99
    ret
2:  mov rax, rsi
    ret
    .globl biara_t_trap
biara_t_trap:
    ud2

    .globl biara_t_switch
biara_t_switch:
    cmp rdi, 4
    ja .Lsw_default
    lea rdx, [rip + .Lsw_table]
    movsxd rax, dword ptr [rdx + rdi*4]
    add rax, rdx
    jmp rax
.Lsw_0:
    lea rax, [rsi + 1]
    ret
.Lsw_1:
    lea rax, [rsi + rsi]
    ret
.Lsw_2:
    mov rax, rsi
    not rax
    ret
.Lsw_3:
    imul rax, rsi, 7
    ret
.Lsw_4:
    mov rax, rsi
    shr rax, 3
    ret
.Lsw_default:
    xor eax, eax
    ret
    .p2align 2
.Lsw_table:
    .long .Lsw_0 - .Lsw_table
    .long .Lsw_1 - .Lsw_table
    .long .Lsw_2 - .Lsw_table
    .long .Lsw_3 - .Lsw_table
    .long .Lsw_4 - .Lsw_table

    .globl biara_t_stackarg
biara_t_stackarg:
    mov rax, [rsp + 8]
    add rax, [rsp + 16]
    add rax, rdi
    ret

    .globl biara_t_caller
biara_t_caller:
    push rbx
    mov rbx, rsi
    push 7
    push 9
    call biara_t_stackarg
    add rsp, 16
    add rax, rbx
    pop rbx
    ret

    .globl biara_t_end
biara_t_end:
    "#,
);

unsafe extern "C" {
    static biara_t_begin: u8;
    static biara_t_end: u8;
    fn biara_t_arith(a: u64, b: u64) -> u64;
    fn biara_t_loop(a: u64, b: u64) -> u64;
    fn biara_t_cond(a: u64, b: u64) -> u64;
    fn biara_t_muldiv(a: u64, b: u64) -> u64;
    fn biara_t_dirty_join(a: u64, b: u64) -> u64;
    fn biara_t_stack(a: u64, b: u64) -> u64;
    fn biara_t_bits(a: u64, b: u64) -> u64;
    fn biara_t_flags(a: u64, b: u64) -> u64;
    fn biara_t_shift32(a: u64, b: u64) -> u64;
    fn biara_t_tail(a: u64, b: u64) -> u64;
    fn biara_t_split(a: u64, b: u64) -> u64;
    static biara_t_split_loop: u8;
    fn biara_t_calls_trap(a: u64, b: u64) -> u64;
    static biara_t_after_trap: u8;
    fn biara_t_trap(a: u64, b: u64) -> u64;
    fn biara_t_stackarg(a: u64, b: u64) -> u64;
    fn biara_t_caller(a: u64, b: u64) -> u64;
    fn biara_t_switch(a: u64, b: u64) -> u64;
}

type TestFn = unsafe extern "C" fn(u64, u64) -> u64;

const RETURN_SENTINEL: u64 = 0xdead_beef_0000;

fn inputs() -> Vec<(u64, u64)> {
    let edges = [
        0,
        1,
        2,
        3,
        4,
        7,
        0x10,
        31,
        32,
        63,
        64,
        0xff,
        0x8000_0000,
        u32::MAX as u64,
        i64::MAX as u64,
        i64::MIN as u64,
        u64::MAX,
    ];
    let mut v: Vec<(u64, u64)> = edges
        .iter()
        .flat_map(|&a| edges.iter().map(move |&b| (a, b)))
        .collect();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..64 {
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        v.push((next(), next()));
    }
    v
}

type Shared = std::sync::Arc<parking_lot::Mutex<Libtcg>>;

/// Recover the functions reachable from `entries` within the test corpus,
/// jump tables included.
fn recover_at(entries: &[u64]) -> (Shared, Cfg) {
    let shared = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg"), None).expect("load libtcg");
    let mut lib = shared.lock();
    let begin = addr_of!(biara_t_begin) as u64;
    let end = addr_of!(biara_t_end) as u64;
    let code = unsafe { std::slice::from_raw_parts(begin as *const u8, (end - begin) as usize) };
    let read = |a: u64, buf: &mut [u8]| {
        let ok = a >= begin && a + buf.len() as u64 <= end;
        if ok {
            buf.copy_from_slice(&code[(a - begin) as usize..][..buf.len()]);
        }
        ok
    };
    let cfg = recover_resolving(
        &mut *lib,
        &host_machine().unwrap(),
        &|pc| (begin..end).contains(&pc).then_some((code, begin)),
        &read,
        entries,
        ResolveOptions::default(),
    )
    .unwrap();
    drop(lib);
    (shared, cfg)
}

fn addr(f: TestFn) -> u64 {
    f as usize as u64
}

fn check(name: &str, f: TestFn) {
    let entry = addr(f);
    let (shared, cfg) = recover_at(&[entry]);
    let mut lib = shared.lock();
    assert!(
        cfg.unresolved.is_empty(),
        "{name}: unresolved {:?}",
        cfg.unresolved
    );

    let info = lib.info().clone();
    let reg = |n: &str| {
        info.globals
            .iter()
            .find(|g| g.name.as_deref() == Some(n))
            .unwrap_or_else(|| panic!("no global {n}"))
            .mem_offset as usize
    };
    let (rdi, rsi, rsp, rax, rip) = (reg("rdi"), reg("rsi"), reg("rsp"), reg("rax"), reg("rip"));

    let env = lib.env();
    let pristine = unsafe { std::slice::from_raw_parts(env, info.env_size) }.to_vec();
    let machine = host_machine().unwrap();

    // Plain lifting, and trusting the recovered calling conventions.
    let abis = biara_abi::analyze(&cfg, &info).unwrap();
    for (opt, abis) in [(0u8, None), (2, None), (0, Some(&abis)), (2, Some(&abis))] {
        let cx = Context::create();
        let module = lift(&cx, &machine, &info, &cfg, abis, &|_| None, name).unwrap();
        let opt_name = format!("{opt}{}", if abis.is_some() { " abi" } else { "" });
        if opt > 0 {
            optimize(&module, &machine, opt).unwrap();
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

        let mut stack = vec![0u64; 1024];
        for (a, b) in inputs() {
            let expected = unsafe { f(a, b) };

            let top = 1000;
            stack[top] = RETURN_SENTINEL;
            let sp = addr_of!(stack[top]) as u64;
            unsafe {
                std::ptr::copy_nonoverlapping(pristine.as_ptr(), env, pristine.len());
                let w = |off: usize, v: u64| env.add(off).cast::<u64>().write_unaligned(v);
                w(rdi, a);
                w(rsi, b);
                w(rsp, sp);
                w(rip, entry);
                run.call(env);
            }
            let r = |off: usize| unsafe { env.add(off).cast::<u64>().read_unaligned() };
            assert_eq!(
                r(rip),
                RETURN_SENTINEL,
                "{name} O{opt_name} ({a:#x}, {b:#x}): did not return"
            );
            assert_eq!(r(rsp), sp + 8, "{name} O{opt_name} ({a:#x}, {b:#x}): rsp");
            assert_eq!(r(rax), expected, "{name} O{opt_name} ({a:#x}, {b:#x}): rax");
        }
    }
}

#[test]
fn arith() {
    check("arith", biara_t_arith);
}

#[test]
fn loops() {
    check("loop", biara_t_loop);
}

#[test]
fn conditions() {
    check("cond", biara_t_cond);
}

#[test]
fn mul_div_carry() {
    check("muldiv", biara_t_muldiv);
}

#[test]
fn stack_and_calls() {
    check("stack", biara_t_stack);

    let (_, cfg) = recover_at(&[addr(biara_t_stack)]);
    let f = &cfg.functions[&addr(biara_t_stack)];
    assert_eq!(f.calls.len(), 1, "one direct call");
    let callee = *f.calls.first().unwrap();
    assert!(cfg.functions[&callee].returns);
    let ret = f
        .blocks
        .iter()
        .flat_map(|b| &cfg.blocks[b].exits)
        .find_map(|x| match x.kind {
            ExitKind::Call { target, ret } if target == callee => Some(ret),
            _ => None,
        })
        .expect("call exit");
    assert!(f.blocks.contains(&ret), "return site belongs to the caller");
    assert!(
        !f.blocks.contains(&callee),
        "callee body stays out of the caller"
    );
    let kinds: Vec<ExitKind> = cfg
        .blocks
        .values()
        .flat_map(|b| &b.exits)
        .map(|x| x.kind)
        .collect();
    assert!(kinds.contains(&ExitKind::Return));
    assert!(
        !kinds
            .iter()
            .any(|k| matches!(k, ExitKind::IndirectJump { .. })),
        "every ret is classified as a return"
    );
}

#[test]
fn helper_state_at_control_flow_join() {
    // r8 stays dirty across a helper that only accesses rax/rdx, then must
    // reach a callee from either predecessor of the join.
    check("dirty_join", biara_t_dirty_join);
}

#[test]
fn tail_call() {
    check("tail", biara_t_tail);

    let (_, cfg) = recover_at(&[addr(biara_t_tail), addr(biara_t_arith)]);
    let f = &cfg.functions[&addr(biara_t_tail)];
    assert_eq!(f.tail_calls, BTreeSet::from([addr(biara_t_arith)]));
    assert!(!f.blocks.contains(&addr(biara_t_arith)));
    assert!(f.returns, "returns through the tail-called function");
}

#[test]
fn branch_into_block_splits_it() {
    check("split", biara_t_split);

    let (_, cfg) = recover_at(&[addr(biara_t_split)]);
    let lp = addr_of!(biara_t_split_loop) as u64;
    assert!(cfg.blocks.contains_key(&lp));
    assert_eq!(cfg.blocks[&addr(biara_t_split)].end(), lp);
    let blocks: Vec<_> = cfg.blocks.values().collect();
    for w in blocks.windows(2) {
        assert!(
            w[0].end() <= w[1].pc(),
            "blocks {:#x} and {:#x} overlap",
            w[0].pc(),
            w[1].pc()
        );
    }
}

#[test]
fn noreturn_callee_cuts_return_site() {
    let (_, cfg) = recover_at(&[addr(biara_t_calls_trap)]);
    let f = &cfg.functions[&addr(biara_t_calls_trap)];
    assert!(!cfg.functions[&addr(biara_t_trap)].returns);
    assert!(!f.blocks.contains(&(addr_of!(biara_t_after_trap) as u64)));
    assert!(f.returns, "the other path returns");
}

#[test]
fn bit_ops() {
    check("bits", biara_t_bits);
}

#[test]
fn lazy_flags() {
    check("flags", biara_t_flags);
}

#[test]
fn shifts_32bit() {
    check("shift32", biara_t_shift32);
}

#[test]
fn jump_table() {
    check("switch", biara_t_switch);

    let (_, cfg) = recover_at(&[addr(biara_t_switch)]);
    let f = &cfg.functions[&addr(biara_t_switch)];
    let tables: Vec<&BTreeSet<u64>> = cfg.jump_tables.values().collect();
    assert_eq!(tables.len(), 1, "one indirect jump resolved");
    assert_eq!(
        tables[0].len(),
        5,
        "exactly the five cases, bounded by cmp/ja"
    );
    assert!(tables[0].iter().all(|t| f.blocks.contains(t)));
    assert!(f.blocks.iter().all(|b| {
        cfg.blocks[b].exits.iter().all(|x| {
            !matches!(x.kind, ExitKind::IndirectJump { .. }) || cfg.jump_tables.contains_key(b)
        })
    }));
}

#[test]
fn calling_conventions() {
    check("caller", biara_t_caller);

    let (shared, cfg) = recover_at(&[addr(biara_t_stack), addr(biara_t_caller)]);
    let info = shared.lock().info().clone();
    let abis = biara_abi::analyze(&cfg, &info).unwrap();
    let reg = |n: &str| {
        info.globals
            .iter()
            .position(|g| g.name.as_deref() == Some(n))
            .unwrap() as u32
    };
    // Argument registers in System V order, as seen by the analysis.
    let args = |f: u64| -> Vec<&str> {
        ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            .into_iter()
            .filter(|r| abis[&f].args.contains(&reg(r)))
            .collect()
    };

    // biara_t_stack(a, b): saves rbx and r12, 32 bytes of locals, passes a
    // pointer into its frame, uses the callee's rax.
    let stack = &abis[&addr(biara_t_stack)];
    assert_eq!(args(addr(biara_t_stack)), ["rdi", "rsi"]);
    assert!(stack.preserved.contains(&reg("rbx")));
    assert!(stack.preserved.contains(&reg("r12")));
    assert_eq!(stack.frame.size, 48);
    assert!(stack.frame.balanced);

    let inner = *cfg.functions[&addr(biara_t_stack)].calls.first().unwrap();
    assert_eq!(args(inner), ["rdi"]);
    assert!(abis[&inner].returns.contains(&reg("rax")));
    assert!(!abis[&inner].preserved.contains(&reg("rcx")));
    assert_eq!(abis[&inner].frame.size, 0);

    // biara_t_stackarg: rdi plus two stack arguments above the return address.
    let sa = &abis[&addr(biara_t_stackarg)];
    assert_eq!(args(addr(biara_t_stackarg)), ["rdi"]);
    assert_eq!(sa.stack_args, BTreeSet::from([8, 16]));
    assert!(sa.returns.contains(&reg("rax")));

    // biara_t_caller: rdi forwarded, rsi kept in rbx across the call.
    let c = &abis[&addr(biara_t_caller)];
    assert_eq!(args(addr(biara_t_caller)), ["rdi", "rsi"]);
    assert!(c.preserved.contains(&reg("rbx")));
    assert!(!c.preserved.contains(&reg("rax")));
    assert!(c.frame.balanced);
}
