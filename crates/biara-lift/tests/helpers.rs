//! The x87 footprint table (`biara_tcg::helper_footprint`) re-derived from
//! the helper bitcode: every listed helper's own body must write only
//! where its class allows, and every pointer it hands to a call must be
//! one through which no register global is reachable.
//!
//! Callees are deliberately *not* inspected: a callee can only reach the
//! caller's `env` through its pointer arguments, and rule (2) below
//! constrains those. This assumes callees neither manufacture `env`
//! pointers from integers nor are handed one disguised as an integer
//! (helpers receive `env` as a pointer, and no `env`-derived value is
//! stored or passed as one below).
//!
//! Requires `helpers-x86_64.bc` (`BIARA_LIBTCG_DIR`, set by
//! `.cargo/config.toml`; `scripts/build-libtcg.sh` builds it).

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;

use biara_tcg::{HelperFootprint, Libtcg, helper_footprint};
use inkwell::{
    context::Context,
    module::Module,
    values::{
        AsValueRef, BasicValue, BasicValueEnum, CallSiteValue, FunctionValue, InstructionOpcode,
        InstructionValue,
    },
};

fn split<'a>(
    env: BasicValueEnum<'a>,
    v: BasicValueEnum<'a>,
) -> Option<(i64, Option<(u32, BasicValueEnum<'a>)>)> {
    let mut total = 0i64;
    let mut index: Option<(u32, BasicValueEnum<'a>)> = None;
    let mut v = v;
    loop {
        if v.as_value_ref() == env.as_value_ref() {
            return Some((total, index));
        }
        let inst = v.as_instruction_value()?;
        if inst.get_opcode() != InstructionOpcode::GetElementPtr || inst.get_num_operands() != 2 {
            return None;
        }
        let next = inst.get_operand(0)?.value()?;
        let idx = inst.get_operand(1)?.value()?;
        let scale = inst
            .get_gep_source_element_type()
            .ok()
            .and_then(|t| match t {
                inkwell::types::BasicTypeEnum::ArrayType(a) => Some(a.len()),
                _ => None,
            })
            .unwrap_or(1);
        if let Some(c) = idx.into_int_value().get_sign_extended_constant() {
            total += c * scale as i64;
        } else {
            if index.is_some() {
                return None;
            }
            index = Some((scale, idx));
        }
        v = next;
    }
}

/// Upper bound of an index value: a constant, an `and`-mask (through
/// casts), or `fpstt` itself (a 3-bit x87 invariant: every writer masks;
/// `finit`/`fldenv` establish valid state).
fn bound(env: BasicValueEnum<'_>, v: BasicValueEnum<'_>) -> Option<i64> {
    if let Some(c) = v.into_int_value().get_sign_extended_constant() {
        return Some(c);
    }
    let inst = v.as_instruction_value()?;
    let operand = |k: u32| inst.get_operand(k).and_then(|o| o.value());
    match inst.get_opcode() {
        InstructionOpcode::And => match (operand(0), operand(1)) {
            (Some(_), Some(BasicValueEnum::IntValue(c))) => {
                c.get_zero_extended_constant().map(|m| m as i64)
            }
            (Some(BasicValueEnum::IntValue(c)), Some(_)) => {
                c.get_zero_extended_constant().map(|m| m as i64)
            }
            _ => None,
        },
        InstructionOpcode::ZExt | InstructionOpcode::SExt | InstructionOpcode::Trunc => {
            operand(0).and_then(|v| bound(env, v))
        }
        InstructionOpcode::Load => {
            // `fpstt` itself lives at env offset 736.
            match split(env, operand(0)?) {
                Some((736, None)) => Some(7),
                _ => None,
            }
        }
        _ => None,
    }
}

fn call_name(i: InstructionValue) -> Option<String> {
    CallSiteValue::try_from(i)
        .ok()?
        .get_called_fn_value()
        .map(|f| f.get_name().to_string_lossy().into_owned())
}

/// Guest-access calls and their width in bytes (`None` for reads).
fn access_width(name: &str) -> Option<Option<i64>> {
    match name {
        n if n.starts_with("access_ld") => Some(None),
        n if n.starts_with("access_prepare") => Some(None),
        "access_stq" => Some(Some(8)),
        "access_stw" => Some(Some(2)),
        "access_stl" => Some(Some(4)),
        _ => None,
    }
}

fn helpers(arch: &str) -> Module<'static> {
    // Leak the context: the module must outlive this function.
    let cx: &'static Context = Box::leak(Box::new(Context::create()));
    let dir = env!("BIARA_LIBTCG_DIR");
    Module::parse_bitcode_from_path(
        std::path::Path::new(&format!("{dir}/helpers-{arch}.bc")),
        cx,
    )
    .unwrap()
}

#[test]
fn footprints() {
    let module = helpers("x86_64");
    let lib = Libtcg::load(&Libtcg::find("x86_64").unwrap(), None).unwrap();
    let info = lib.lock().info().clone();
    let mut globals: Vec<(i64, i64)> = info
        .globals
        .iter()
        .filter(|g| g.kind == biara_tcg::TempKind::Global && g.mem_base == Some(info.env_global))
        .map(|g| {
            let w = (g.ty.bits() / 8).max(1) as i64;
            (g.mem_offset, g.mem_offset + w)
        })
        .collect();
    globals.sort();
    let global_end = globals.iter().map(|&(_, b)| b).max().unwrap();
    let overlaps_global = |lo: i64, hi: i64| globals.iter().any(|&(a, b)| lo < b && a < hi);
    let module: &'static Module<'static> = Box::leak(Box::new(module));
    // Every helper the table lists, by class. Guest reads/writes allowed
    // per class; `fstt_ST0`'s declared width is checked against the
    // `access_st*` calls below.
    let listed: &[(&str, HelperFootprint, i64)] = &[
        ("fpush", HelperFootprint::FpStack, 0),
        ("fpop", HelperFootprint::FpStack, 0),
        ("fincstp", HelperFootprint::FpStack, 0),
        ("fdecstp", HelperFootprint::FpStack, 0),
        ("fmov_ST0_STN", HelperFootprint::FpStack, 0),
        ("fmov_STN_ST0", HelperFootprint::FpStack, 0),
        ("fldt_ST0", HelperFootprint::FpLoad, 0),
        ("flds_ST0", HelperFootprint::FpLoad, 0),
        (
            "fstt_ST0",
            HelperFootprint::FpStore { addr: 1, width: 10 },
            10,
        ),
    ];
    let mut written;
    for (name, fp, width) in listed {
        assert_eq!(
            helper_footprint(name),
            Some(*fp),
            "{name}: footprint table changed, update this test"
        );
        let (reads, writes) = match fp {
            HelperFootprint::FpStack => (false, false),
            HelperFootprint::FpLoad => (true, false),
            HelperFootprint::FpStore { .. } => (true, true),
        };
        written = 0;
        let f: FunctionValue<'static> = module
            .get_function(&format!("helper_{name}"))
            .unwrap_or_else(|| panic!("helper_{name} missing from helper bitcode"));
        let env: BasicValueEnum<'static> = f.get_nth_param(0).unwrap();
        // Whether `v` folds to a helper-local alloca.
        let alloca_rooted = |mut v: BasicValueEnum<'static>| {
            loop {
                let Some(inst) = v.as_instruction_value() else {
                    return false;
                };
                match inst.get_opcode() {
                    InstructionOpcode::Alloca => return true,
                    InstructionOpcode::GetElementPtr
                    | InstructionOpcode::BitCast
                    | InstructionOpcode::PtrToInt
                    | InstructionOpcode::IntToPtr
                    | InstructionOpcode::AddrSpaceCast => {
                        let Some(next) = inst
                            .get_operand(0)
                            .and_then(|o| o.value())
                            .filter(|b| matches!(b, BasicValueEnum::PointerValue(_)))
                        else {
                            return false;
                        };
                        v = next;
                    }
                    _ => return false,
                }
            }
        };
        // Classify a store/call pointer: `Ok` with its env span if env-based.
        let span_of = |v: BasicValueEnum<'static>| {
            let (off, index) = split(env, v)?;
            let (lo, hi) = match index {
                None => (off, off + 1),
                Some((scale, idx)) => {
                    let b = bound(env, idx)?;
                    assert!(b < 8, "helper_{name}: index bound {b}");
                    (off, off + (b + 1) * scale as i64)
                }
            };
            Some((lo, hi))
        };
        for bb in f.get_basic_block_iter() {
            for i in bb.get_instructions() {
                match i.get_opcode() {
                    InstructionOpcode::Store => {
                        let ptr = i.get_operand(1).and_then(|o| o.value()).unwrap();
                        if alloca_rooted(ptr) {
                            continue;
                        }
                        // (1) Every store is through an env chain whose
                        // constant sum clears every register global.
                        let Some((lo, hi)) = span_of(ptr) else {
                            panic!("helper_{name}: opaque store {i:?}");
                        };
                        assert!(
                            lo >= global_end,
                            "helper_{name}: env store [{lo}, {hi}) below global end {global_end}"
                        );
                        assert!(
                            !overlaps_global(lo, hi),
                            "helper_{name}: env store [{lo}, {hi}) hits a register global"
                        );
                    }
                    InstructionOpcode::Call => {
                        let Some(callee) = call_name(i) else {
                            panic!("helper_{name}: indirect call {i:?}");
                        };
                        if callee.starts_with("llvm.memcpy")
                            || callee.starts_with("llvm.memmove")
                            || callee.starts_with("llvm.memset")
                        {
                            // A block copy/set: its destination obeys the
                            // same rule as a store (source reads kill
                            // nothing). (Call operands skip the callee:
                            // operand 0 is the destination.)
                            let dst = i.get_operand(0).and_then(|o| o.value()).unwrap();
                            if alloca_rooted(dst) {
                                continue;
                            }
                            let Some((lo, hi)) = span_of(dst) else {
                                panic!("helper_{name}: opaque {callee} destination in {i:?}");
                            };
                            assert!(
                                lo >= global_end,
                                "helper_{name}: {callee} [{lo}, {hi}) below global end"
                            );
                            assert!(
                                !overlaps_global(lo, hi),
                                "helper_{name}: {callee} [{lo}, {hi}) hits a register global"
                            );
                            continue;
                        }
                        if callee.starts_with("llvm.") {
                            continue;
                        }
                        if let Some(w) = access_width(&callee) {
                            match w {
                                None => {
                                    assert!(reads, "helper_{name}: unexpected guest read {callee}")
                                }
                                Some(w) => {
                                    assert!(
                                        writes,
                                        "helper_{name}: unexpected guest write {callee}"
                                    );
                                    written += w;
                                }
                            }
                            continue;
                        }
                        // (2) Every pointer argument is an alloca, a
                        // constant global, or an env chain clearing every
                        // register global. Non-pointer arguments (guest
                        // addresses as integers, FP stack indices) carry
                        // no `env` reach.
                        let called = CallSiteValue::try_from(i)
                            .ok()
                            .and_then(|c| c.get_called_fn_value())
                            .map(|f| f.as_value_ref());
                        for k in 0..i.get_num_operands() {
                            let op = i.get_operand(k).and_then(|o| o.value()).unwrap();
                            if Some(op.as_value_ref()) == called {
                                continue;
                            }
                            let BasicValueEnum::PointerValue(_) = op else {
                                continue;
                            };
                            if alloca_rooted(op) {
                                continue;
                            }
                            if op.as_instruction_value().is_none() {
                                // A constant global.
                                continue;
                            }
                            let Some((lo, hi)) = span_of(op) else {
                                panic!(
                                    "helper_{name}: opaque pointer argument {k} to {callee} in {i:?}"
                                );
                            };
                            assert!(
                                lo >= global_end,
                                "helper_{name}: argument {k} to {callee} [{lo}, {hi}) below global end"
                            );
                            assert!(
                                !overlaps_global(lo, hi),
                                "helper_{name}: argument {k} to {callee} hits a register global"
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(
            written, *width,
            "{name}: guest-write bytes != declared width"
        );
        let _ = reads;
    }
    // The table lists exactly these: anything added to it (or removed
    // from this test) fails here.
    let unlisted = [
        "fwait",
        "finit",
        "fldcw",
        "fstcw",
        "fldenv",
        "fstenv",
        "fldl_ST0",
        "fstl_ST0",
        "fld1_ST0",
        "fldz_ST0",
        "fldpi_ST0",
        "fadd_STN_ST0",
        "fsub_STN_ST0",
        "fmul_STN_ST0",
        "fdiv_STN_ST0",
        "fildl_ST0",
        "fildll_ST0",
        "fistl_ST0",
        "fistll_ST0",
        "fistt_ST0",
        "fbst_ST0",
        "fbld_ST0",
        "fcom_ST0_FT0",
        "fucom_ST0_FT0",
        "fsqrt_ST0",
        "fsin_ST0",
        "fcos_ST0",
    ];
    for name in unlisted {
        assert_eq!(
            helper_footprint(name),
            None,
            "{name}: newly footprinted, extend the checks above"
        );
    }
    // No x87 helpers on AArch64.
    let aarch64 = helpers("aarch64");
    for (name, _, _) in listed {
        assert!(
            aarch64.get_function(&format!("helper_{name}")).is_none(),
            "helper_{name} unexpectedly present on aarch64"
        );
    }
    let _ = BTreeSet::<String>::new();
}
