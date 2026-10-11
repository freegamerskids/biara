//! Lowering of TCG blocks into the LLVM function of their guest function.
//!
//! State model:
//! - `env` is the guest `CPUArchState *`; TCG globals are loads/stores at
//!   their `env` offsets, so lifted code and QEMU helpers share one layout.
//! - Straight-line EBB/TB temps are SSA values; temps crossing TCG labels or
//!   branches use slots. Constants are immediates.
//! - Guest memory (`qemu_ld/st`) is host memory at the guest address.
//! - Carry/borrow storage is allocated only when a carry operation uses it.
//! - Every exit stores the next pc (TCG does) and then follows its
//!   classification: branch to a block of this function, call a lifted
//!   function, or return. Anything not statically known leaves through
//!   `biara.dispatch` or returns with the pc in `env` ("escapes").
//! - Synchronization emits stores only for potentially dirty globals. Labels
//!   and guest-block entries conservatively admit all writes in the function;
//!   straight-line helper/call boundaries narrow that set after syncing.
//!   Listed helpers synchronize only their architectural register footprint;
//!   other state and opaque or nonreturning helpers remain conservative.
//!
//! Every instruction carries `!biara.pc !{i64 <guest pc>}`.

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet, HashMap},
};

use biara_abi::FunctionAbi;
use biara_cfg::{ArchSpec, Exit, ExitKind, RegSet};
use biara_tcg::{
    Block, Cond, ContextInfo, HelperType, MemOp, Op, Opcode, TempId, TempKind, Type, bswap,
    call_flags,
};
use inkwell::{
    AddressSpace, AtomicOrdering, IntPredicate,
    attributes::{Attribute, AttributeLoc},
    basic_block::BasicBlock,
    builder::Builder,
    context::Context,
    intrinsics::Intrinsic,
    module::Module,
    types::{BasicMetadataTypeEnum, BasicType, IntType},
    values::{
        BasicMetadataValueEnum, BasicValueEnum, FunctionValue, IntValue, MetadataValue,
        PointerValue, ValueKind,
    },
};

use crate::Error;

type R<T> = Result<T, Error>;

pub(crate) const PC_MD: &str = "biara.pc";

/// Where classified exits of one function's blocks lead.
pub(crate) struct Targets<'m, 'ctx> {
    /// Blocks of the function being emitted.
    pub blocks: HashMap<u64, BasicBlock<'ctx>>,
    /// Every lifted function, by entry.
    pub functions: &'m HashMap<u64, FunctionValue<'ctx>>,
    /// `void biara.dispatch(ptr env)`: call the function at env's pc, if any.
    pub dispatch: FunctionValue<'ctx>,
    /// `void biara.syscall(ptr env)`: perform the system call in env.
    pub syscall: FunctionValue<'ctx>,
    /// Resolved indirect-jump targets by jumping block (`Cfg::jump_tables`).
    pub tables: &'m BTreeMap<u64, BTreeSet<u64>>,
    /// Recovered callees by calling block, with residual unknown status.
    pub indirect_calls: &'m BTreeMap<u64, biara_cfg::IndirectTargets>,
    pub imports: &'m BTreeMap<u64, String>,
    /// `void biara.target(i64 pc, i64 site)` for indirect-target analysis.
    pub target_marker: Option<FunctionValue<'ctx>>,
    /// Analysis-only guest return boundary; reads env without changing it.
    pub return_marker: Option<FunctionValue<'ctx>>,
    /// Guest registers (TCG globals in env) promoted to function-local
    /// slots, synchronised with env around calls and returns.
    pub globals: BTreeMap<TempId, Promoted<'ctx>>,
    /// Union of explicit global writes in this function, plus synthesized
    /// post-call SP updates. A conservative incoming dirty set at joins.
    pub modified: &'m BTreeSet<TempId>,
    pub spec: &'static ArchSpec,
    /// Recovered calling conventions, by function entry (`None`: reload
    /// every register after every call). With them, calls are lowered as
    /// the analysis models them: a direct call to a function with a
    /// balanced frame keeps the registers it preserves in SSA form instead
    /// of reloading them from env, other calls those the convention leaves
    /// alone (`convention_kept`), and every call the stack pointer as a
    /// return leaves it.
    pub abis: Option<&'m BTreeMap<u64, FunctionAbi>>,
    /// Globals an unknown callee leaves unchanged by convention (the stack
    /// pointer and pc aside).
    pub convention_kept: &'m BTreeSet<TempId>,
    /// The stack pointer global and what returning from a callee adds to
    /// its value at the call (the return address it pops).
    pub sp: (TempId, i64),
}

/// A TCG global kept in an alloca for the duration of a function.
#[derive(Clone, Copy)]
pub(crate) struct Promoted<'ctx> {
    pub slot: PointerValue<'ctx>,
    /// Its location in env.
    pub home: PointerValue<'ctx>,
    pub ty: IntType<'ctx>,
}

enum LocalTemp<'ctx> {
    Ssa(Cell<Option<IntValue<'ctx>>>),
    Slot(PointerValue<'ctx>),
    Other,
}

#[derive(Clone, Copy)]
enum TempPlacement {
    Unused,
    Region(usize),
    Slot,
    Other,
}

/// Only values whose complete lifetime stays in one straight-line region
/// can bypass slots. Inputs precede outputs: read-before-write and reused
/// temporaries crossing a branch/label retain the original slot semantics.
fn straight_line_temps(block: &Block, exits: &[Exit]) -> Vec<TempPlacement> {
    let mut local: Vec<TempPlacement> = block
        .temps
        .iter()
        .map(|t| {
            if matches!(t.kind, TempKind::Ebb | TempKind::Tb)
                && matches!(t.ty, Type::I32 | Type::I64)
            {
                TempPlacement::Unused
            } else {
                TempPlacement::Other
            }
        })
        .collect();
    let mut region = 0usize;
    for (index, op) in block.ops.iter().enumerate() {
        if op.opcode == Opcode::SetLabel {
            region += 1;
        }
        for (input, ids) in [(true, block.inputs(op)), (false, block.outputs(op))] {
            for &id in ids {
                let i = id as usize;
                match local[i] {
                    TempPlacement::Unused => {
                        local[i] = if input {
                            TempPlacement::Slot
                        } else {
                            TempPlacement::Region(region)
                        };
                    }
                    TempPlacement::Region(start) if start != region => {
                        local[i] = TempPlacement::Slot
                    }
                    _ => {}
                }
            }
        }
        if matches!(
            op.opcode,
            Opcode::Br | Opcode::Brcond | Opcode::ExitTb | Opcode::GotoPtr
        ) || exits.iter().any(|exit| exit.op == index)
            || (op.opcode == Opcode::Call && block.helper(op).no_return())
        {
            region += 1;
        }
    }
    local
}

pub(crate) struct Lowering<'a, 'ctx> {
    cx: &'ctx Context,
    module: &'a Module<'ctx>,
    b: Builder<'ctx>,
    block: &'a Block,
    exits: &'a [Exit],
    targets: &'a Targets<'a, 'ctx>,
    func: FunctionValue<'ctx>,
    env: PointerValue<'ctx>,
    env_temp: TempId,
    pc_temp: TempId,
    temps: Vec<LocalTemp<'ctx>>,
    labels: Vec<Option<BasicBlock<'ctx>>>,
    allocas: BasicBlock<'ctx>,
    carry: Cell<Option<PointerValue<'ctx>>>,
    dirty: Vec<Cell<bool>>,
    pc: u64,
    pc_kind: u32,
    pc_md: Option<MetadataValue<'ctx>>,
}

impl<'a, 'ctx> Lowering<'a, 'ctx> {
    /// Emit `block` starting at `start` in `func`. Its allocas go to the end
    /// of `allocas` (the function's entry block, not yet terminated).
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        cx: &'ctx Context,
        module: &'a Module<'ctx>,
        info: &'a ContextInfo,
        func: FunctionValue<'ctx>,
        allocas: BasicBlock<'ctx>,
        start: BasicBlock<'ctx>,
        block: &'a Block,
        exits: &'a [Exit],
        targets: &'a Targets<'a, 'ctx>,
    ) -> R<()> {
        let env = func.get_nth_param(0).unwrap().into_pointer_value();
        let b = cx.create_builder();
        b.position_at_end(allocas);

        let local = straight_line_temps(block, exits);
        let mut temps = Vec::with_capacity(block.temps.len());
        for (i, t) in block.temps.iter().enumerate() {
            temps.push(match local[i] {
                TempPlacement::Unused | TempPlacement::Region(_) => LocalTemp::Ssa(Cell::new(None)),
                TempPlacement::Slot => {
                    LocalTemp::Slot(b.build_alloca(int_type(cx, t.ty)?, &format!("t{i}"))?)
                }
                TempPlacement::Other => LocalTemp::Other,
            });
        }
        b.position_at_end(start);

        let mut l = Lowering {
            cx,
            module,
            b,
            block,
            exits,
            targets,
            func,
            env,
            env_temp: info.env_global,
            pc_temp: info.pc_global,
            temps,
            labels: vec![None; block.nb_labels as usize],
            allocas,
            carry: Cell::new(None),
            dirty: (0..info.globals.len())
                .map(|i| Cell::new(targets.modified.contains(&(i as TempId))))
                .collect(),
            pc: block.pc,
            pc_kind: cx.get_kind_id(PC_MD),
            pc_md: None,
        };
        for (i, op) in block.ops.iter().enumerate() {
            // A terminal exit needs no synthetic dead block unless TCG
            // actually emits more operations before its next label. Keep
            // instruction markers so a later label retains the current pc.
            if l.terminated() && !matches!(op.opcode, Opcode::InsnStart | Opcode::SetLabel) {
                l.continue_in("dead");
            }
            l.op(i, op)?;
            l.tag()?;
        }
        if !l.terminated() {
            l.sync_out()?;
            l.b.build_return(None)?;
            l.tag()?;
        }
        Ok(())
    }

    fn exit_at(&self, op: usize) -> Option<ExitKind> {
        self.exits.iter().find(|x| x.op == op).map(|x| x.kind)
    }

    /// Leave the block along `kind`; the pc global already holds the target.
    fn emit_exit(&mut self, kind: Option<ExitKind>) -> R<()> {
        let t = self.targets;
        let call = |f: FunctionValue<'ctx>| self.b.build_call(f, &[self.env.into()], "");
        match kind {
            Some(ExitKind::Jump(dst)) => {
                if let Some(&bb) = t.blocks.get(&dst) {
                    self.b.build_unconditional_branch(bb)?;
                } else {
                    // A tail call; through `biara.dispatch` if the callee
                    // has no body here (an analysis module's).
                    self.sync_out()?;
                    call(t.functions.get(&dst).copied().unwrap_or(t.dispatch))?;
                    if let Some(marker) = t.return_marker {
                        call(marker)?;
                    }
                    self.b.build_return(None)?;
                }
            }
            Some(ExitKind::Call { target, ret }) => {
                // If the callee comes back to `ret`, the registers it keeps
                // still hold what was just written back (also when it has
                // no body here and `biara.dispatch` runs it). If it
                // escapes, env is reloaded by our caller anyway.
                let kept = t.abis.map(|abis| match abis.get(&target) {
                    Some(abi) if abi.analysis.converged && abi.frame.balanced => &abi.preserved,
                    _ => t.convention_kept,
                });
                let callee = t.functions.get(&target).copied();
                self.call_out(callee.unwrap_or(t.dispatch), kept)?;
                self.resume(ret)?;
            }
            Some(ExitKind::IndirectCall { ret, slot }) => {
                self.indirect_call(ret, slot.is_none_or(|s| !t.imports.contains_key(&s)))?;
            }
            Some(ExitKind::IndirectJump { slot }) => {
                self.indirect_jump(slot.is_none_or(|s| !t.imports.contains_key(&s)))?
            }
            Some(ExitKind::Syscall { next }) => {
                self.sync_out()?;
                call(t.syscall)?;
                self.sync_in()?;
                let pc_ty = self.ity(self.block.temp(self.pc_temp).ty)?;
                self.write(self.pc_temp, pc_ty.const_int(next, false))?;
                match t.blocks.get(&next) {
                    Some(&bb) => self.b.build_unconditional_branch(bb)?,
                    None => {
                        self.sync_out()?;
                        self.b.build_return(None)?
                    }
                };
            }
            Some(ExitKind::Return) | None => {
                self.sync_out()?;
                if matches!(kind, Some(ExitKind::Return))
                    && let Some(marker) = t.return_marker
                {
                    call(marker)?;
                }
                self.b.build_return(None)?;
            }
        }
        self.tag()?;
        Ok(())
    }

    fn indirect_call(&mut self, ret: u64, announce: bool) -> R<()> {
        let t = self.targets;
        let pc = self.read(self.pc_temp)?;
        if let (Some(marker), true) = (t.target_marker, announce) {
            self.b.build_call(
                marker,
                &[pc.into(), self.i64().const_int(self.block.pc, false).into()],
                "",
            )?;
        }
        let Some(resolved) = t.indirect_calls.get(&self.block.pc) else {
            self.call_out(t.dispatch, t.abis.map(|_| t.convention_kept))?;
            return self.resume(ret);
        };
        let here = self.b.get_insert_block().unwrap();
        let joined = self.cx.append_basic_block(self.func, "call_return");
        let unknown = self.cx.append_basic_block(self.func, "call_unknown");
        let mut cases = Vec::with_capacity(resolved.targets.len());
        for &dst in &resolved.targets {
            let Some(&callee) = t.functions.get(&dst) else {
                continue;
            };
            let bb = self
                .cx
                .append_basic_block(self.func, &format!("call_{dst:x}"));
            self.b.position_at_end(bb);
            self.join_dirty();
            let kept = t.abis.map(|abis| match abis.get(&dst) {
                Some(abi) if abi.analysis.converged && abi.frame.balanced => &abi.preserved,
                _ => t.convention_kept,
            });
            self.call_out(callee, kept)?;
            self.b.build_unconditional_branch(joined)?;
            self.tag()?;
            cases.push((pc.get_type().const_int(dst, false), bb));
        }
        self.b.position_at_end(here);
        self.b.build_switch(pc, unknown, &cases)?;
        self.tag()?;
        self.b.position_at_end(unknown);
        self.join_dirty();
        self.call_out(t.dispatch, t.abis.map(|_| t.convention_kept))?;
        self.b.build_unconditional_branch(joined)?;
        self.tag()?;
        self.b.position_at_end(joined);
        self.join_dirty();
        self.resume(ret)
    }

    /// `switch (pc)` over the block's resolved jump-table targets; anything
    /// else goes through `biara.dispatch` and returns. Jumps through a
    /// constant pointer slot (GOT) are filled in at load time and are not
    /// announced to the table analysis.
    fn indirect_jump(&mut self, announce: bool) -> R<()> {
        let t = self.targets;
        let pc = self.read(self.pc_temp)?;
        if let (Some(marker), true) = (t.target_marker, announce) {
            let site = self.i64().const_int(self.block.pc, false);
            self.b.build_call(marker, &[pc.into(), site.into()], "")?;
        }
        let mut cases = Vec::new();
        for &dst in t.tables.get(&self.block.pc).into_iter().flatten() {
            let bb = match (t.blocks.get(&dst), t.functions.get(&dst)) {
                (Some(&bb), _) => bb,
                (None, Some(&f)) => {
                    let bb = self
                        .cx
                        .append_basic_block(self.func, &format!("tail_{dst:x}"));
                    let here = self.b.get_insert_block().unwrap();
                    self.b.position_at_end(bb);
                    self.sync_out()?;
                    self.b.build_call(f, &[self.env.into()], "")?;
                    if let Some(marker) = t.return_marker {
                        self.b.build_call(marker, &[self.env.into()], "")?;
                    }
                    self.b.build_return(None)?;
                    self.tag()?;
                    self.b.position_at_end(here);
                    bb
                }
                (None, None) => continue,
            };
            cases.push((pc.get_type().const_int(dst, false), bb));
        }
        let unknown = self.cx.append_basic_block(self.func, "indirect");
        self.b.build_switch(pc, unknown, &cases)?;
        self.tag()?;
        self.b.position_at_end(unknown);
        self.sync_out()?;
        self.b.build_call(t.dispatch, &[self.env.into()], "")?;
        if let Some(marker) = t.return_marker {
            self.b.build_call(marker, &[self.env.into()], "")?;
        }
        self.b.build_return(None)?;
        Ok(())
    }

    /// After a call: continue at `ret` if the callee came back there,
    /// otherwise propagate the escape to our caller. Guest state has just
    /// been reloaded, so the escape needs no write-back.
    fn resume(&mut self, ret: u64) -> R<()> {
        let Some(&bb) = self.targets.blocks.get(&ret) else {
            self.b.build_return(None)?;
            return Ok(());
        };
        let pc = self.read(self.pc_temp)?;
        let back = self.b.build_int_compare(
            IntPredicate::EQ,
            pc,
            pc.get_type().const_int(ret, false),
            "returned",
        )?;
        let escape = self.cx.append_basic_block(self.func, "escape");
        self.b.build_conditional_branch(back, bb, escape)?;
        self.tag()?;
        self.b.position_at_end(escape);
        self.b.build_return(None)?;
        Ok(())
    }

    // ---- values ----------------------------------------------------------

    fn ity(&self, t: Type) -> R<IntType<'ctx>> {
        int_type(self.cx, t)
    }

    fn i64(&self) -> IntType<'ctx> {
        self.cx.i64_type()
    }

    fn global_ptr(&self, id: TempId) -> R<PointerValue<'ctx>> {
        if let Some(p) = self.targets.globals.get(&id) {
            return Ok(p.slot);
        }
        let t = self.block.temp(id);
        let base = t
            .mem_base
            .ok_or_else(|| self.unsupported("global without base"))?;
        self.host_ptr(base, t.mem_offset, t.name.as_deref().unwrap_or(""))
    }

    /// Flush potentially dirty promoted globals. Keep the compile-time set
    /// intact: exits can emit several alternative tail-call arms from one
    /// state. Helpers and returning calls clear it explicitly on their path.
    fn sync_out(&self) -> R<()> {
        for (id, p) in &self.targets.globals {
            if !self.dirty[*id as usize].get() {
                continue;
            }
            let v = self.b.build_load(p.ty, p.slot, "")?;
            self.b.build_store(p.home, v)?;
        }
        Ok(())
    }

    fn clear_dirty(&self) {
        for dirty in &self.dirty {
            dirty.set(false);
        }
    }

    /// A label may have arbitrary predecessors, including backward edges.
    /// Restore the union of all function writes rather than carrying the
    /// preceding emitted path's narrower set across a join.
    fn join_dirty(&self) {
        for (i, dirty) in self.dirty.iter().enumerate() {
            dirty.set(self.targets.modified.contains(&(i as TempId)));
        }
    }

    /// The spec constrains architectural registers only. Flags, pc and other
    /// globals remain conservative. Decode dynamic register masks directly,
    /// without allocating temporary name or register sets at every helper.
    fn helper_accesses(&self, op: &Op, id: TempId, set: Option<RegSet>) -> bool {
        let spec = self.targets.spec;
        let Some(name) = self.block.temp(id).name.as_deref() else {
            return true;
        };
        if !spec.registers.contains(&name) {
            return true;
        }
        match set {
            None => !spec.helper_regs_complete,
            Some(RegSet::Named(names)) => names.contains(&name),
            Some(RegSet::Fields { offsets, names }) => {
                let arg = self.block.inputs(op).get(1).map(|&id| self.block.temp(id));
                match arg {
                    Some(t) if t.kind == TempKind::Const => offsets.iter().any(|&offset| {
                        names.get(((t.value as u64 >> offset) & 31) as usize) == Some(&name)
                    }),
                    _ => names.contains(&name),
                }
            }
        }
    }

    fn sync_helper(&self, op: &Op, writeback: bool) -> R<()> {
        let name = &self.block.helper(op).name;
        let set = self
            .targets
            .spec
            .helper_regs
            .iter()
            .find(|(helper, _, _)| *helper == name)
            .map(|(_, reads, writes)| if writeback { *reads } else { *writes });
        for (id, p) in &self.targets.globals {
            if !self.helper_accesses(op, *id, set) {
                continue;
            }
            let dirty = &self.dirty[*id as usize];
            if writeback {
                if !dirty.get() {
                    continue;
                }
                let v = self.b.build_load(p.ty, p.slot, "")?;
                self.b.build_store(p.home, v)?;
            } else {
                let v = self.b.build_load(p.ty, p.home, "")?;
                self.b.build_store(p.slot, v)?;
            }
            dirty.set(false);
        }
        Ok(())
    }

    /// Reload every promoted global from env (after code that may have
    /// changed guest state through env).
    fn sync_in(&self) -> R<()> {
        self.sync_in_except(None)
    }

    /// `sync_in`, except for the globals in `kept`.
    fn sync_in_except(&self, kept: Option<&BTreeSet<TempId>>) -> R<()> {
        for (id, p) in &self.targets.globals {
            if kept.is_some_and(|k| k.contains(id)) {
                continue;
            }
            let v = self.b.build_load(p.ty, p.home, "")?;
            self.b.build_store(p.slot, v)?;
            self.dirty[*id as usize].set(false);
        }
        Ok(())
    }

    /// Call `f` with the guest state in env, then take back what it may
    /// have changed. ABI-aware lifting and call-site analysis use the
    /// returning-call stack model; resolution does not assume any other
    /// register is preserved by a calling convention.
    fn call_out(&self, f: FunctionValue<'ctx>, kept: Option<&BTreeSet<TempId>>) -> R<()> {
        self.sync_out()?;
        self.clear_dirty();
        let (sp_id, pop) = self.targets.sp;
        let sp = match self
            .targets
            .globals
            .get(&sp_id)
            .filter(|_| kept.is_some() || self.targets.return_marker.is_some())
        {
            Some(p) => Some((p, self.b.build_load(p.ty, p.slot, "")?.into_int_value())),
            None => None,
        };
        self.b.build_call(f, &[self.env.into()], "")?;
        self.sync_in_except(kept)?;
        if let Some((_, at_call)) = sp {
            let pop = at_call.get_type().const_int(pop as u64, true);
            let v = self.b.build_int_add(at_call, pop, "")?;
            self.write(sp_id, v)?;
        }
        Ok(())
    }

    /// Host pointer `base + off` for env-relative state.
    fn host_ptr(&self, base: TempId, off: i64, name: &str) -> R<PointerValue<'ctx>> {
        let off_v = self.i64().const_int(off as u64, true);
        if base == self.env_temp {
            Ok(unsafe {
                self.b
                    .build_gep(self.cx.i8_type(), self.env, &[off_v], name)?
            })
        } else {
            let a = self.read(base)?;
            let a = self.b.build_int_add(a, off_v, "")?;
            Ok(self
                .b
                .build_int_to_ptr(a, self.cx.ptr_type(AddressSpace::default()), name)?)
        }
    }

    fn read(&self, id: TempId) -> R<IntValue<'ctx>> {
        let t = self.block.temp(id);
        match t.kind {
            TempKind::Const => Ok(self.ity(t.ty)?.const_int(t.value as u64, false)),
            TempKind::Fixed => Ok(self.b.build_ptr_to_int(self.env, self.i64(), "env.int")?),
            TempKind::Global => {
                let p = self.global_ptr(id)?;
                Ok(self.b.build_load(self.ity(t.ty)?, p, "")?.into_int_value())
            }
            TempKind::Ebb | TempKind::Tb => match &self.temps[id as usize] {
                LocalTemp::Ssa(value) => value
                    .get()
                    .ok_or_else(|| self.unsupported("undefined SSA temp")),
                LocalTemp::Slot(p) => {
                    Ok(self.b.build_load(self.ity(t.ty)?, *p, "")?.into_int_value())
                }
                LocalTemp::Other => Err(self.unsupported("non-integer temp")),
            },
        }
    }

    fn write(&self, id: TempId, v: IntValue<'ctx>) -> R<()> {
        let t = self.block.temp(id);
        let p = match t.kind {
            TempKind::Global => self.global_ptr(id)?,
            TempKind::Ebb | TempKind::Tb => match &self.temps[id as usize] {
                LocalTemp::Ssa(value) => {
                    value.set(Some(self.fit(v, self.ity(t.ty)?, false)?));
                    return Ok(());
                }
                LocalTemp::Slot(p) => *p,
                LocalTemp::Other => return Err(self.unsupported("non-integer temp")),
            },
            TempKind::Fixed | TempKind::Const => {
                return Err(self.unsupported("write to read-only temp"));
            }
        };
        let v = self.fit(v, self.ity(t.ty)?, false)?;
        self.b.build_store(p, v)?;
        if t.kind == TempKind::Global && self.targets.globals.contains_key(&id) {
            self.dirty[id as usize].set(true);
        }
        Ok(())
    }

    /// Zero/sign-extend or truncate `v` to `ty`.
    fn fit(&self, v: IntValue<'ctx>, ty: IntType<'ctx>, signed: bool) -> R<IntValue<'ctx>> {
        let (from, to) = (v.get_type().get_bit_width(), ty.get_bit_width());
        Ok(if from == to {
            v
        } else if from > to {
            self.b.build_int_truncate(v, ty, "")?
        } else if signed {
            self.b.build_int_s_extend(v, ty, "")?
        } else {
            self.b.build_int_z_extend(v, ty, "")?
        })
    }

    /// Integer type of `bits` width (8..=128, power of two).
    fn bits(&self, bits: u32) -> R<IntType<'ctx>> {
        int_bits(self.cx, bits)
    }

    fn intrinsic(&self, name: &str, ty: IntType<'ctx>) -> R<FunctionValue<'ctx>> {
        Intrinsic::find(name)
            .and_then(|i| i.get_declaration(self.module, &[ty.into()]))
            .ok_or_else(|| Error::Llvm(format!("missing intrinsic {name}")))
    }

    fn call_int(
        &self,
        f: FunctionValue<'ctx>,
        args: &[BasicMetadataValueEnum<'ctx>],
    ) -> R<IntValue<'ctx>> {
        match self.b.build_call(f, args, "")?.try_as_basic_value() {
            ValueKind::Basic(v) => Ok(v.into_int_value()),
            _ => Err(Error::Llvm("intrinsic returned void".into())),
        }
    }

    fn cond(&self, c: Cond, a: IntValue<'ctx>, b: IntValue<'ctx>) -> R<IntValue<'ctx>> {
        use IntPredicate as P;
        let pred = match c {
            Cond::Never => return Ok(self.cx.bool_type().const_zero()),
            Cond::Always => return Ok(self.cx.bool_type().const_all_ones()),
            Cond::TstEq | Cond::TstNe => {
                let m = self.b.build_and(a, b, "")?;
                let p = if c == Cond::TstEq { P::EQ } else { P::NE };
                return Ok(self
                    .b
                    .build_int_compare(p, m, a.get_type().const_zero(), "")?);
            }
            Cond::Eq => P::EQ,
            Cond::Ne => P::NE,
            Cond::Lt => P::SLT,
            Cond::Ge => P::SGE,
            Cond::Gt => P::SGT,
            Cond::Le => P::SLE,
            Cond::Ltu => P::ULT,
            Cond::Geu => P::UGE,
            Cond::Gtu => P::UGT,
            Cond::Leu => P::ULE,
        };
        Ok(self.b.build_int_compare(pred, a, b, "")?)
    }

    fn cond_arg(&self, raw: u64) -> R<Cond> {
        Cond::from_raw(raw).ok_or_else(|| self.unsupported(&format!("condition {raw}")))
    }

    // ---- control flow ----------------------------------------------------

    fn label(&mut self, id: u64) -> BasicBlock<'ctx> {
        let slot = &mut self.labels[id as usize];
        *slot.get_or_insert_with(|| self.cx.append_basic_block(self.func, &format!("L{id}")))
    }

    fn terminated(&self) -> bool {
        self.b
            .get_insert_block()
            .and_then(|bb| bb.get_terminator())
            .is_some()
    }

    /// Materialize an unreachable continuation only for actual trailing ops.
    fn continue_in(&mut self, name: &str) -> BasicBlock<'ctx> {
        let bb = self.cx.append_basic_block(self.func, name);
        self.b.position_at_end(bb);
        bb
    }

    /// Attach the current guest pc to untagged instructions of this block.
    fn tag(&self) -> R<()> {
        let Some(md) = self.pc_md else { return Ok(()) };
        let mut cur = self
            .b
            .get_insert_block()
            .and_then(|bb| bb.get_last_instruction());
        while let Some(i) = cur {
            if i.get_metadata(self.pc_kind).is_some() {
                break;
            }
            i.set_metadata(md, self.pc_kind)
                .map_err(|e| Error::Llvm(format!("set_metadata: {e:?}")))?;
            cur = i.get_previous_instruction();
        }
        Ok(())
    }

    fn unsupported(&self, what: &str) -> Error {
        Error::Unsupported {
            pc: self.pc,
            what: what.to_owned(),
        }
    }

    // ---- ops -------------------------------------------------------------

    fn op(&mut self, index: usize, op: &Op) -> R<()> {
        let blk = self.block;
        let out = blk.outputs(op);
        let inp = blk.inputs(op);
        let k = blk.consts(op);
        let b = &self.b;

        match op.opcode {
            Opcode::InsnStart => {
                self.pc = k[0];
                let v = self.i64().const_int(k[0], false);
                self.pc_md = Some(self.cx.metadata_node(&[v.into()]));
            }
            Opcode::Discard | Opcode::GotoTb => {}
            Opcode::SetLabel => {
                let bb = self.label(k[0]);
                if !self.terminated() {
                    self.b.build_unconditional_branch(bb)?;
                }
                self.tag()?;
                self.b.position_at_end(bb);
                self.join_dirty();
            }
            Opcode::Br => {
                let bb = self.label(k[0]);
                self.b.build_unconditional_branch(bb)?;
                self.tag()?;
            }
            Opcode::Brcond => {
                let c = self.cond_arg(k[0])?;
                let v = self.cond(c, self.read(inp[0])?, self.read(inp[1])?)?;
                let target = self.label(k[1]);
                let next = self.cx.append_basic_block(self.func, "next");
                self.b.build_conditional_branch(v, target, next)?;
                self.tag()?;
                self.b.position_at_end(next);
            }
            Opcode::ExitTb | Opcode::GotoPtr => self.emit_exit(self.exit_at(index))?,
            Opcode::Mb => {
                b.build_fence(AtomicOrdering::SequentiallyConsistent, false, "")?;
            }

            Opcode::Mov => self.write(out[0], self.read(inp[0])?)?,
            Opcode::Add
            | Opcode::Sub
            | Opcode::Mul
            | Opcode::And
            | Opcode::Or
            | Opcode::Xor
            | Opcode::Andc
            | Opcode::Orc
            | Opcode::Eqv
            | Opcode::Nand
            | Opcode::Nor
            | Opcode::Divs
            | Opcode::Divu
            | Opcode::Rems
            | Opcode::Remu => {
                let (x, y) = (self.read(inp[0])?, self.read(inp[1])?);
                let v = match op.opcode {
                    Opcode::Add => b.build_int_add(x, y, "")?,
                    Opcode::Sub => b.build_int_sub(x, y, "")?,
                    Opcode::Mul => b.build_int_mul(x, y, "")?,
                    Opcode::And => b.build_and(x, y, "")?,
                    Opcode::Or => b.build_or(x, y, "")?,
                    Opcode::Xor => b.build_xor(x, y, "")?,
                    Opcode::Andc => b.build_and(x, b.build_not(y, "")?, "")?,
                    Opcode::Orc => b.build_or(x, b.build_not(y, "")?, "")?,
                    Opcode::Eqv => b.build_not(b.build_xor(x, y, "")?, "")?,
                    Opcode::Nand => b.build_not(b.build_and(x, y, "")?, "")?,
                    Opcode::Nor => b.build_not(b.build_or(x, y, "")?, "")?,
                    Opcode::Divs => b.build_int_signed_div(x, y, "")?,
                    Opcode::Divu => b.build_int_unsigned_div(x, y, "")?,
                    Opcode::Rems => b.build_int_signed_rem(x, y, "")?,
                    _ => b.build_int_unsigned_rem(x, y, "")?,
                };
                self.write(out[0], v)?;
            }
            Opcode::Neg => self.write(out[0], b.build_int_neg(self.read(inp[0])?, "")?)?,
            Opcode::Not => self.write(out[0], b.build_not(self.read(inp[0])?, "")?)?,
            Opcode::Shl | Opcode::Shr | Opcode::Sar => {
                let x = self.read(inp[0])?;
                // Out-of-range shifts are unspecified in TCG; mask like hosts do.
                let n = b.build_and(
                    self.read(inp[1])?,
                    x.get_type().const_int(op.ty.bits() as u64 - 1, false),
                    "",
                )?;
                let v = match op.opcode {
                    Opcode::Shl => b.build_left_shift(x, n, "")?,
                    Opcode::Shr => b.build_right_shift(x, n, false, "")?,
                    _ => b.build_right_shift(x, n, true, "")?,
                };
                self.write(out[0], v)?;
            }
            Opcode::Rotl | Opcode::Rotr => {
                let x = self.read(inp[0])?;
                let name = if op.opcode == Opcode::Rotl {
                    "llvm.fshl"
                } else {
                    "llvm.fshr"
                };
                let f = self.intrinsic(name, x.get_type())?;
                let v = self.call_int(f, &[x.into(), x.into(), self.read(inp[1])?.into()])?;
                self.write(out[0], v)?;
            }
            Opcode::Clz | Opcode::Ctz => {
                let x = self.read(inp[0])?;
                let name = if op.opcode == Opcode::Clz {
                    "llvm.ctlz"
                } else {
                    "llvm.cttz"
                };
                let f = self.intrinsic(name, x.get_type())?;
                let n = self.call_int(f, &[x.into(), self.cx.bool_type().const_zero().into()])?;
                let nz = b.build_int_compare(IntPredicate::NE, x, x.get_type().const_zero(), "")?;
                let v = b
                    .build_select(nz, n, self.read(inp[1])?, "")?
                    .into_int_value();
                self.write(out[0], v)?;
            }
            Opcode::Ctpop => {
                let x = self.read(inp[0])?;
                let f = self.intrinsic("llvm.ctpop", x.get_type())?;
                self.write(out[0], self.call_int(f, &[x.into()])?)?;
            }
            Opcode::Bswap16 | Opcode::Bswap32 | Opcode::Bswap64 => {
                let x = self.read(inp[0])?;
                let w = match op.opcode {
                    Opcode::Bswap16 => 16,
                    Opcode::Bswap32 => 32,
                    _ => 64,
                };
                let wt = self.bits(w)?;
                let n = self.fit(x, wt, false)?;
                let f = self.intrinsic("llvm.bswap", wt)?;
                let s = self.call_int(f, &[n.into()])?;
                let signed = op.opcode != Opcode::Bswap64 && k[0] & bswap::OS != 0;
                self.write(out[0], self.fit(s, x.get_type(), signed)?)?;
            }
            Opcode::Deposit => {
                let (x, y) = (self.read(inp[0])?, self.read(inp[1])?);
                let (pos, len) = (k[0] as u32, k[1] as u32);
                let ty = x.get_type();
                let field = mask(len) << pos;
                let keep = b.build_and(x, ty.const_int(!field as u64, false), "")?;
                let ins = b.build_left_shift(y, ty.const_int(pos as u64, false), "")?;
                let ins = b.build_and(ins, ty.const_int(field as u64, false), "")?;
                self.write(out[0], b.build_or(keep, ins, "")?)?;
            }
            Opcode::Extract | Opcode::Sextract => {
                let x = self.read(inp[0])?;
                let (pos, len) = (k[0] as u32, k[1] as u32);
                let ty = x.get_type();
                let bits = op.ty.bits();
                let v = if op.opcode == Opcode::Extract {
                    let s = b.build_right_shift(x, ty.const_int(pos as u64, false), false, "")?;
                    b.build_and(s, ty.const_int(mask(len) as u64, false), "")?
                } else {
                    let s =
                        b.build_left_shift(x, ty.const_int((bits - pos - len) as u64, false), "")?;
                    b.build_right_shift(s, ty.const_int((bits - len) as u64, false), true, "")?
                };
                self.write(out[0], v)?;
            }
            Opcode::Extract2 => {
                // N bits of t2:t1 starting at pos.
                let (lo, hi) = (self.read(inp[0])?, self.read(inp[1])?);
                let f = self.intrinsic("llvm.fshr", lo.get_type())?;
                let n = lo.get_type().const_int(k[0], false);
                self.write(out[0], self.call_int(f, &[hi.into(), lo.into(), n.into()])?)?;
            }
            Opcode::Divs2 | Opcode::Divu2 => {
                let signed = op.opcode == Opcode::Divs2;
                let (nl, nh, d) = (self.read(inp[0])?, self.read(inp[1])?, self.read(inp[2])?);
                let ty = nl.get_type();
                let wide = self.bits(2 * op.ty.bits())?;
                let n = self.concat(nl, nh, wide)?;
                let d = self.fit(d, wide, signed)?;
                let (q, r) = if signed {
                    (
                        b.build_int_signed_div(n, d, "")?,
                        b.build_int_signed_rem(n, d, "")?,
                    )
                } else {
                    (
                        b.build_int_unsigned_div(n, d, "")?,
                        b.build_int_unsigned_rem(n, d, "")?,
                    )
                };
                self.write(out[0], self.fit(q, ty, false)?)?;
                self.write(out[1], self.fit(r, ty, false)?)?;
            }
            Opcode::Mulu2 | Opcode::Muls2 | Opcode::Muluh | Opcode::Mulsh => {
                let signed = matches!(op.opcode, Opcode::Muls2 | Opcode::Mulsh);
                let (x, y) = (self.read(inp[0])?, self.read(inp[1])?);
                let ty = x.get_type();
                let wide = self.bits(2 * op.ty.bits())?;
                let p =
                    b.build_int_mul(self.fit(x, wide, signed)?, self.fit(y, wide, signed)?, "")?;
                let hi =
                    b.build_right_shift(p, wide.const_int(op.ty.bits() as u64, false), false, "")?;
                let hi = self.fit(hi, ty, false)?;
                if matches!(op.opcode, Opcode::Mulu2 | Opcode::Muls2) {
                    self.write(out[0], self.fit(p, ty, false)?)?;
                    self.write(out[1], hi)?;
                } else {
                    self.write(out[0], hi)?;
                }
            }
            Opcode::Setcond | Opcode::Negsetcond => {
                let c = self.cond_arg(k[0])?;
                let v = self.cond(c, self.read(inp[0])?, self.read(inp[1])?)?;
                let ty = self.ity(op.ty)?;
                let v = if op.opcode == Opcode::Setcond {
                    b.build_int_z_extend(v, ty, "")?
                } else {
                    b.build_int_s_extend(v, ty, "")?
                };
                self.write(out[0], v)?;
            }
            Opcode::Movcond => {
                let c = self.cond_arg(k[0])?;
                let v = self.cond(c, self.read(inp[0])?, self.read(inp[1])?)?;
                let s = b.build_select(v, self.read(inp[2])?, self.read(inp[3])?, "")?;
                self.write(out[0], s.into_int_value())?;
            }

            Opcode::Ld8u
            | Opcode::Ld8s
            | Opcode::Ld16u
            | Opcode::Ld16s
            | Opcode::Ld32u
            | Opcode::Ld32s
            | Opcode::Ld => {
                let (w, signed) = match op.opcode {
                    Opcode::Ld8u => (8, false),
                    Opcode::Ld8s => (8, true),
                    Opcode::Ld16u => (16, false),
                    Opcode::Ld16s => (16, true),
                    Opcode::Ld32u => (32, false),
                    Opcode::Ld32s => (32, true),
                    _ => (op.ty.bits(), false),
                };
                let p = self.host_ptr(inp[0], k[0] as i64, "")?;
                let v = b.build_load(self.bits(w)?, p, "")?.into_int_value();
                self.write(out[0], self.fit(v, self.ity(op.ty)?, signed)?)?;
            }
            Opcode::St8 | Opcode::St16 | Opcode::St32 | Opcode::St => {
                let w = match op.opcode {
                    Opcode::St8 => 8,
                    Opcode::St16 => 16,
                    Opcode::St32 => 32,
                    _ => op.ty.bits(),
                };
                let v = self.fit(self.read(inp[0])?, self.bits(w)?, false)?;
                let p = self.host_ptr(inp[1], k[0] as i64, "")?;
                self.b.build_store(p, v)?;
            }
            Opcode::ExtI32I64 | Opcode::ExtuI32I64 => {
                let v = self.fit(
                    self.read(inp[0])?,
                    self.i64(),
                    op.opcode == Opcode::ExtI32I64,
                )?;
                self.write(out[0], v)?;
            }
            Opcode::ExtrlI64I32 => {
                self.write(
                    out[0],
                    self.fit(self.read(inp[0])?, self.cx.i32_type(), false)?,
                )?;
            }
            Opcode::ExtrhI64I32 => {
                let x = self.read(inp[0])?;
                let h = b.build_right_shift(x, self.i64().const_int(32, false), false, "")?;
                self.write(out[0], self.fit(h, self.cx.i32_type(), false)?)?;
            }

            Opcode::Addco
            | Opcode::Addci
            | Opcode::Addcio
            | Opcode::Addc1o
            | Opcode::Subbo
            | Opcode::Subbi
            | Opcode::Subbio
            | Opcode::Subb1o => self.carry_op(op, out[0], inp[0], inp[1])?,

            Opcode::QemuLd => {
                let m = MemOp(k[0]);
                let v = self.guest_load(self.read(inp[0])?, m)?;
                self.write(out[0], self.fit(v, self.ity(op.ty)?, m.signed())?)?;
            }
            Opcode::QemuLd2 => {
                let v = self.guest_load(self.read(inp[0])?, MemOp(k[0]))?;
                let (lo, hi) = self.split(v)?;
                self.write(out[0], lo)?;
                self.write(out[1], hi)?;
            }
            Opcode::QemuSt => {
                let m = MemOp(k[0]);
                self.guest_store(self.read(inp[0])?, self.read(inp[1])?, m)?;
            }
            Opcode::QemuSt2 => {
                let wide = self.cx.i128_type();
                let v = self.concat(self.read(inp[0])?, self.read(inp[1])?, wide)?;
                self.guest_store(v, self.read(inp[2])?, MemOp(k[0]))?;
            }

            Opcode::Call => match self.exit_at(index) {
                Some(kind @ ExitKind::Syscall { .. }) => self.emit_exit(Some(kind))?,
                _ => self.call(op)?,
            },

            Opcode::PluginCb | Opcode::PluginMemCb | Opcode::Other => {
                return Err(self.unsupported(blk.op_name(op)));
            }
        }
        Ok(())
    }

    /// `hi:lo` as one integer of type `wide`.
    fn concat(
        &self,
        lo: IntValue<'ctx>,
        hi: IntValue<'ctx>,
        wide: IntType<'ctx>,
    ) -> R<IntValue<'ctx>> {
        let half = lo.get_type().get_bit_width() as u64;
        let lo = self.fit(lo, wide, false)?;
        let hi = self.fit(hi, wide, false)?;
        let hi = self
            .b
            .build_left_shift(hi, wide.const_int(half, false), "")?;
        Ok(self.b.build_or(hi, lo, "")?)
    }

    /// Low and high i64 halves of an i128.
    fn split(&self, v: IntValue<'ctx>) -> R<(IntValue<'ctx>, IntValue<'ctx>)> {
        let lo = self.fit(v, self.i64(), false)?;
        let hi = self
            .b
            .build_right_shift(v, v.get_type().const_int(64, false), false, "")?;
        Ok((lo, self.fit(hi, self.i64(), false)?))
    }

    fn guest_ptr(&self, addr: IntValue<'ctx>) -> R<PointerValue<'ctx>> {
        let a = self.fit(addr, self.i64(), false)?;
        Ok(self
            .b
            .build_int_to_ptr(a, self.cx.ptr_type(AddressSpace::default()), "")?)
    }

    fn guest_load(&self, addr: IntValue<'ctx>, m: MemOp) -> R<IntValue<'ctx>> {
        let ty = self.bits(8 * m.bytes())?;
        let p = self.guest_ptr(addr)?;
        let v = self.b.build_load(ty, p, "")?.into_int_value();
        v.as_instruction()
            .unwrap()
            .set_alignment(1)
            .map_err(|e| Error::Llvm(format!("{e:?}")))?;
        if m.bswap() && m.bytes() > 1 {
            let f = self.intrinsic("llvm.bswap", ty)?;
            return self.call_int(f, &[v.into()]);
        }
        Ok(v)
    }

    fn guest_store(&self, v: IntValue<'ctx>, addr: IntValue<'ctx>, m: MemOp) -> R<()> {
        let ty = self.bits(8 * m.bytes())?;
        let mut v = self.fit(v, ty, false)?;
        if m.bswap() && m.bytes() > 1 {
            let f = self.intrinsic("llvm.bswap", ty)?;
            v = self.call_int(f, &[v.into()])?;
        }
        let p = self.guest_ptr(addr)?;
        self.b
            .build_store(p, v)?
            .set_alignment(1)
            .map_err(|e| Error::Llvm(format!("{e:?}")))?;
        Ok(())
    }

    fn carry_slot(&self) -> R<PointerValue<'ctx>> {
        if let Some(slot) = self.carry.get() {
            return Ok(slot);
        }
        let b = self.cx.create_builder();
        b.position_at_end(self.allocas);
        let slot = b.build_alloca(self.cx.bool_type(), "carry")?;
        self.carry.set(Some(slot));
        Ok(slot)
    }

    fn carry_op(&self, op: &Op, out: TempId, x: TempId, y: TempId) -> R<()> {
        let b = &self.b;
        let (x, y) = (self.read(x)?, self.read(y)?);
        let ty = x.get_type();
        let i1 = self.cx.bool_type();
        let is_add = matches!(
            op.opcode,
            Opcode::Addco | Opcode::Addci | Opcode::Addcio | Opcode::Addc1o
        );
        let carry_in = match op.opcode {
            Opcode::Addco | Opcode::Subbo => None,
            Opcode::Addc1o | Opcode::Subb1o => Some(i1.const_all_ones()),
            _ => Some(
                b.build_load(i1, self.carry_slot()?, "carry")?
                    .into_int_value(),
            ),
        };
        let sets_carry = !matches!(op.opcode, Opcode::Addci | Opcode::Subbi);

        // Two overflow-checked steps: x op y, then op carry-in.
        let ovf = if is_add {
            "llvm.uadd.with.overflow"
        } else {
            "llvm.usub.with.overflow"
        };
        let f = self.intrinsic(ovf, ty)?;
        let step = |a: IntValue<'ctx>, c: IntValue<'ctx>| -> R<(IntValue<'ctx>, IntValue<'ctx>)> {
            let r = match b
                .build_call(f, &[a.into(), c.into()], "")?
                .try_as_basic_value()
            {
                ValueKind::Basic(BasicValueEnum::StructValue(s)) => s,
                _ => return Err(Error::Llvm("with.overflow result".into())),
            };
            let v = b.build_extract_value(r, 0, "")?.into_int_value();
            let o = b.build_extract_value(r, 1, "")?.into_int_value();
            Ok((v, o))
        };
        let (mut v, mut o) = step(x, y)?;
        if let Some(c) = carry_in {
            let (v2, o2) = step(v, self.fit(c, ty, false)?)?;
            v = v2;
            o = b.build_or(o, o2, "")?;
        }
        if sets_carry {
            b.build_store(self.carry_slot()?, o)?;
        }
        self.write(out, v)
    }

    fn helper_decl(&self, h: &biara_tcg::Helper) -> R<FunctionValue<'ctx>> {
        let sym = h.symbol();
        if let Some(f) = self.module.get_function(&sym) {
            return Ok(f);
        }
        let params: Vec<BasicMetadataTypeEnum> = h
            .params()
            .map(|p| self.helper_type(p).map(Into::into))
            .collect::<R<_>>()?;
        let fn_ty = match h.ret() {
            HelperType::Void => self.cx.void_type().fn_type(&params, false),
            t => self.helper_type(t)?.fn_type(&params, false),
        };
        let f = self.module.add_function(&sym, fn_ty, None);
        if h.no_return() {
            let k = Attribute::get_named_enum_kind_id("noreturn");
            f.add_attribute(AttributeLoc::Function, self.cx.create_enum_attribute(k, 0));
        }
        if h.flags & call_flags::NO_SIDE_EFFECTS != 0 {
            // A removable QEMU helper cannot write guest/CPU state. It may
            // still read memory; do not strengthen this to memory(none).
            let memory = Attribute::get_named_enum_kind_id("memory");
            f.add_attribute(
                AttributeLoc::Function,
                self.cx
                    .create_enum_attribute(memory, 0b01 | (0b01 << 2) | (0b01 << 4)),
            );
        }
        Ok(f)
    }

    fn helper_type(&self, t: HelperType) -> R<inkwell::types::BasicTypeEnum<'ctx>> {
        Ok(match t {
            HelperType::I32 | HelperType::S32 => self.cx.i32_type().into(),
            HelperType::I64 | HelperType::S64 => self.i64().into(),
            HelperType::I128 => self.cx.i128_type().into(),
            HelperType::Ptr => self.cx.ptr_type(AddressSpace::default()).into(),
            HelperType::Void => return Err(self.unsupported("void helper parameter")),
        })
    }

    fn call(&mut self, op: &Op) -> R<()> {
        let blk = self.block;
        let h = blk.helper(op);
        let f = self.helper_decl(h)?;
        let inp = blk.inputs(op);
        let out = blk.outputs(op);

        // i128 values travel as two i64 temps (low first).
        let mut args: Vec<BasicMetadataValueEnum> = Vec::with_capacity(inp.len());
        let mut i = 0;
        for p in h.params() {
            let take = if p == HelperType::I128 { 2 } else { 1 };
            let ts = inp
                .get(i..i + take)
                .ok_or_else(|| self.unsupported(&format!("call {}: argument count", h.name)))?;
            i += take;
            let v: BasicMetadataValueEnum = match p {
                HelperType::Ptr if ts[0] == self.env_temp => self.env.into(),
                HelperType::Ptr => self
                    .b
                    .build_int_to_ptr(
                        self.read(ts[0])?,
                        self.cx.ptr_type(AddressSpace::default()),
                        "",
                    )?
                    .into(),
                HelperType::I128 => self
                    .concat(self.read(ts[0])?, self.read(ts[1])?, self.cx.i128_type())?
                    .into(),
                HelperType::I32 | HelperType::S32 => self
                    .fit(self.read(ts[0])?, self.cx.i32_type(), false)?
                    .into(),
                HelperType::I64 => self.fit(self.read(ts[0])?, self.i64(), false)?.into(),
                HelperType::S64 => self.fit(self.read(ts[0])?, self.i64(), true)?.into(),
                HelperType::Void => unreachable!(),
            };
            args.push(v);
        }

        // TCG's contract (tcg_reg_alloc_call): NO_READ_GLOBALS helpers neither
        // see nor change globals in env; NO_WRITE_GLOBALS ones only read them;
        // the rest may also change them.
        let reads = h.flags & call_flags::NO_READ_GLOBALS == 0;
        let writes = reads && h.flags & call_flags::NO_WRITE_GLOBALS == 0;
        if reads {
            if h.no_return() {
                // Exception/escape consumers can inspect the complete state,
                // not just the registers the helper itself reads.
                self.sync_out()?;
            } else {
                self.sync_helper(op, true)?;
            }
        }
        let r = self.b.build_call(f, &args, "")?;
        // Helpers that only touch x87 FPU stack state leave every register
        // global alone: no reload, so values stay in SSA form across them.
        if writes && !h.no_return() && !h.preserves_globals() {
            self.sync_helper(op, false)?;
        }
        match (h.ret(), r.try_as_basic_value()) {
            (HelperType::Void, _) => {}
            (HelperType::I128, ValueKind::Basic(v)) => {
                let (lo, hi) = self.split(v.into_int_value())?;
                self.write(out[0], lo)?;
                self.write(out[1], hi)?;
            }
            (HelperType::Ptr, ValueKind::Basic(v)) => {
                let v = self
                    .b
                    .build_ptr_to_int(v.into_pointer_value(), self.i64(), "")?;
                self.write(out[0], v)?;
            }
            (_, ValueKind::Basic(v)) => self.write(out[0], v.into_int_value())?,
            _ => return Err(Error::Llvm(format!("call {}: missing result", h.name))),
        }

        if h.no_return() {
            self.b.build_unreachable()?;
            self.tag()?;
        }
        Ok(())
    }
}

fn int_type(cx: &Context, t: Type) -> R<IntType<'_>> {
    match t {
        Type::I32 => Ok(cx.i32_type()),
        Type::I64 => Ok(cx.i64_type()),
        Type::I128 => Ok(cx.i128_type()),
        other => Err(Error::Unsupported {
            pc: 0,
            what: format!("{other:?} value"),
        }),
    }
}

pub(crate) fn int_bits(cx: &Context, bits: u32) -> R<IntType<'_>> {
    match bits {
        8 => Ok(cx.i8_type()),
        16 => Ok(cx.i16_type()),
        32 => Ok(cx.i32_type()),
        64 => Ok(cx.i64_type()),
        128 => Ok(cx.i128_type()),
        other => Err(Error::Unsupported {
            pc: 0,
            what: format!("i{other} value"),
        }),
    }
}

/// `len` low bits set (len <= 64).
fn mask(len: u32) -> u128 {
    (1u128 << len) - 1
}
