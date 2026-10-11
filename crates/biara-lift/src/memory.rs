//! Guest memory that alias analysis can see through.
//!
//! Lowering turns every guest address into `inttoptr i64 %addr`. Two things
//! then keep LLVM from forwarding a guest store to a later load:
//!
//! - Guest vs. CPU state: `env` is a `noalias` argument, but an `inttoptr`
//!   pointer may be based on anything that escaped, `env` included, so every
//!   register write-back clobbers every guest load. Guest memory never
//!   overlaps the CPU state, so guest and `env` accesses are put in two
//!   disjoint scopes (`!alias.scope` / `!noalias`, read by ScopedNoAliasAA).
//! - Guest vs. guest: once promotion and instcombine have folded the address
//!   arithmetic, a stack slot is `inttoptr (add %sp.in, -16)`, and BasicAA
//!   does not look through `inttoptr`. Rewriting each
//!   `inttoptr (add %base, C)` as `getelementptr i8, (inttoptr %base), C`
//!   gives slots off the same base a common underlying object and constant
//!   offsets, which BasicAA decomposes: a store to `[sp, #16]` no longer
//!   kills a load from `[sp, #24]`.
//!
//! Together they let GVN forward spills (and jump-table indices kept on the
//! stack at -O0) and DSE drop dead ones. Addresses are unchanged (no
//! `inbounds`); only the representation and the alias facts change.
//!
//! The SSA/canonicalization prefix runs through a reusable native function
//! pass manager. It clears analyses between functions, including while a
//! module is still being built, to avoid retaining whole-module analysis
//! state or repeatedly processing completed functions.

use std::{ffi::c_void, marker::PhantomData, ptr::NonNull};

use inkwell::{
    AddressSpace,
    basic_block::BasicBlock,
    module::Module,
    passes::PassBuilderOptions,
    targets::TargetMachine,
    values::{
        BasicValue, BasicValueEnum, FunctionValue, InstructionOpcode, InstructionValue, IntValue,
        MetadataValue,
    },
};

use crate::Error;

unsafe extern "C" {
    fn biara_trimmer_create(machine: *mut c_void) -> *mut c_void;
    fn biara_trimmer_run(trimmer: *mut c_void, function: *mut c_void);
    fn biara_trimmer_dispose(trimmer: *mut c_void);
}

/// The canonicalization prefix, reused one completed function at a time.
/// Analyses are cleared after each run: neither the raw IR nor cached
/// analyses accumulate across functions. The target machine outlives it.
pub(crate) struct Trimmer<'m> {
    raw: NonNull<c_void>,
    _machine: PhantomData<&'m TargetMachine>,
}

impl<'m> Trimmer<'m> {
    pub(crate) fn new(machine: &'m TargetMachine) -> Self {
        Self {
            raw: NonNull::new(unsafe { biara_trimmer_create(machine.as_mut_ptr().cast()) })
                .expect("LLVM trimmer allocation"),
            _machine: PhantomData,
        }
    }

    pub(crate) fn run(&mut self, function: FunctionValue<'_>) {
        use inkwell::values::AsValueRef;
        // LLVM owns the function; the shim neither retains nor deletes it.
        unsafe { biara_trimmer_run(self.raw.as_ptr(), function.as_value_ref().cast()) };
    }
}

impl Drop for Trimmer<'_> {
    fn drop(&mut self) {
        unsafe { biara_trimmer_dispose(self.raw.as_ptr()) };
    }
}

/// Promote registers to SSA values and fold address arithmetic, then rebase
/// guest pointers and scope memory accesses; the first step of every
/// pipeline. (Explicit `instcombine` verifies its fixpoint and aborts the
/// process on large lifted functions; the default pipelines do not.)
pub(crate) fn canonicalize(module: &Module<'_>, machine: &TargetMachine) -> Result<(), Error> {
    let mut trimmer = Trimmer::new(machine);
    for function in module
        .get_functions()
        .filter(|f| f.count_basic_blocks() != 0)
    {
        trimmer.run(function);
    }
    rebase_guest_pointers(module)?;
    scope_memory(module);
    Ok(())
}

/// `canonicalize`, then function-local cleanup that turns env and stack
/// loads into shared SSA values and exposes bounds checks: the IR the
/// analyses (jump tables, call sites) read. No inlining, so every guest
/// instruction stays in its function.
pub(crate) fn simplify(module: &Module<'_>, machine: &TargetMachine) -> Result<(), Error> {
    canonicalize(module, machine)?;
    module
        .run_passes(
            "function(simplifycfg,gvn,instcombine<no-verify-fixpoint>,simplifycfg)",
            machine,
            PassBuilderOptions::create(),
        )
        .map_err(|e| Error::Llvm(e.to_string()))
}

#[derive(Clone, Copy, PartialEq)]
enum Space {
    Guest,
    Env,
}

/// Tag every load and store of a lifted function (`void f(ptr %env)`) as a
/// guest or a CPU-state access: `!alias.scope` its own scope, `!noalias` the
/// other. Accesses whose pointer is neither (helpers' own memory after
/// inlining, phis of pointers) are left alone and alias conservatively.
fn scope_memory(module: &Module<'_>) {
    let cx = module.get_context();
    let domain = cx.metadata_node(&[cx.metadata_string("biara.memory").into()]);
    let scope = |name: &str| {
        let s = cx.metadata_node(&[cx.metadata_string(name).into(), domain.into()]);
        cx.metadata_node(&[s.into()])
    };
    let (guest, env) = (scope("biara.guest"), scope("biara.env"));
    let (scope_kind, noalias_kind) = (cx.get_kind_id("alias.scope"), cx.get_kind_id("noalias"));
    for f in module.get_functions() {
        let Some(env_arg) = lifted_env(f) else {
            continue;
        };
        for bb in f.get_basic_block_iter() {
            for inst in bb.get_instructions() {
                let ptr = match inst.get_opcode() {
                    InstructionOpcode::Load => 0,
                    InstructionOpcode::Store => 1,
                    _ => continue,
                };
                let Some(BasicValueEnum::PointerValue(p)) =
                    inst.get_operand(ptr).and_then(|o| o.value())
                else {
                    continue;
                };
                let (own, other): (MetadataValue<'_>, MetadataValue<'_>) =
                    match space(p.into(), env_arg) {
                        Some(Space::Guest) => (guest, env),
                        Some(Space::Env) => (env, guest),
                        None => continue,
                    };
                inst.set_metadata(own, scope_kind).unwrap();
                inst.set_metadata(other, noalias_kind).unwrap();
            }
        }
    }
}

/// The `env` argument of a lifted function (one pointer parameter, with a
/// body).
fn lifted_env(f: FunctionValue<'_>) -> Option<BasicValueEnum<'_>> {
    (f.count_params() == 1 && f.count_basic_blocks() > 0)
        .then(|| f.get_nth_param(0))
        .flatten()
        .filter(|p| p.is_pointer_value())
}

/// Whether `p` points into guest memory (derived from `inttoptr`) or into
/// the CPU state (derived from `env`), looking through GEPs.
fn space<'ctx>(mut p: BasicValueEnum<'ctx>, env: BasicValueEnum<'ctx>) -> Option<Space> {
    loop {
        if p == env {
            return Some(Space::Env);
        }
        let inst = p.as_instruction_value()?;
        match inst.get_opcode() {
            InstructionOpcode::IntToPtr => return Some(Space::Guest),
            InstructionOpcode::GetElementPtr => p = inst.get_operand(0)?.value()?,
            _ => return None,
        }
    }
}

/// Rewrite `inttoptr (add %base, C)` as `gep i8, (inttoptr %base), C`
/// throughout `module`. One `inttoptr %base` is shared per base and
/// function, placed right after `%base` is defined (or at the function entry
/// for arguments and globals).
pub(crate) fn rebase_guest_pointers(module: &Module<'_>) -> Result<(), Error> {
    let cx = module.get_context();
    let ptr = cx.ptr_type(AddressSpace::default());
    let i8t = cx.i8_type();
    let b = cx.create_builder();
    for f in module.get_functions() {
        let Some(entry) = f.get_first_basic_block() else {
            continue;
        };
        let mut sites = Vec::new();
        for bb in f.get_basic_block_iter() {
            let mut i = bb.get_first_instruction();
            while let Some(inst) = i {
                i = inst.get_next_instruction();
                if inst.get_opcode() == InstructionOpcode::IntToPtr
                    && let Some((base, off)) = base_offset(inst)
                {
                    sites.push((inst, base, off));
                }
            }
        }
        let mut bases: Vec<(IntValue<'_>, inkwell::values::PointerValue<'_>)> = Vec::new();
        for (inst, base, off) in sites {
            let base_ptr = match bases.iter().find(|(v, _)| *v == base) {
                Some(&(_, p)) => p,
                None => {
                    // Right after the definition; phis stay grouped at the
                    // top of their block, arguments go to the entry.
                    let at = match base.as_instruction() {
                        Some(def) if def.get_opcode() == InstructionOpcode::Phi => {
                            first_non_phi(def.get_parent().unwrap())
                        }
                        Some(def) => def.get_next_instruction(),
                        None => first_non_phi(entry),
                    };
                    b.position_before(&at.expect("a block ends in a terminator"));
                    let p = b.build_int_to_ptr(base, ptr, "")?;
                    bases.push((base, p));
                    p
                }
            };
            b.position_before(&inst);
            let off = cx.i64_type().const_int(off as u64, false);
            let gep = unsafe { b.build_gep(i8t, base_ptr, &[off], "")? };
            let Some(gep) = gep.as_instruction() else {
                continue;
            };
            inst.replace_all_uses_with(&gep);
            inst.erase_from_basic_block();
        }
    }
    Ok(())
}

/// `(%base, C)` when `inst` is `inttoptr (add %base, C)` with a non-constant
/// `%base` of 64 bits.
fn base_offset<'ctx>(inst: InstructionValue<'ctx>) -> Option<(IntValue<'ctx>, i64)> {
    let addr = inst.get_operand(0)?.value()?.into_int_value();
    let add = addr.as_instruction()?;
    if add.get_opcode() != InstructionOpcode::Add || addr.get_type().get_bit_width() != 64 {
        return None;
    }
    let operand = |i| match add.get_operand(i)?.value()? {
        BasicValueEnum::IntValue(v) => Some(v),
        _ => None,
    };
    let (x, c) = (operand(0)?, operand(1)?);
    let off = c.get_sign_extended_constant()?;
    (!x.is_const()).then_some((x, off))
}

fn first_non_phi(bb: BasicBlock<'_>) -> Option<InstructionValue<'_>> {
    bb.get_instructions()
        .find(|i| i.get_opcode() != InstructionOpcode::Phi)
}
