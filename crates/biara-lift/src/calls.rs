//! Calls and what their arguments hold, read off the lifted IR after
//! function-local simplification (`memory::simplify`).
//!
//! An argument register's value at a call is what the lowering wrote back
//! to its env slot before the call (or, with no write since the function's
//! entry, the caller's own incoming value). That value is classified as a
//! constant (or one of a few), an address in the caller's frame (the stack
//! pointer at entry plus an offset), an incoming register or the word it
//! points to, or a prior call result. Internal return summaries substitute the
//! caller's arguments; allocation sizes and offsets survive allocator wrappers
//! and known memory-copy return aliases. Conflicting definitions at control-flow
//! joins, unresolved summaries and excessive traversal remain unknown rather
//! than inventing an object extent. Scalar values can also carry an unsigned
//! range from LazyValueInfo, refined through dominating control-flow edges
//! and width-correct arithmetic. Joins union alternatives; bounded walks
//! and unsupported relations fall back to conservative ranges. Per-function
//! CFG state is reused across queries rather than rebuilt per argument.
//! Analysis-only return markers retain normal guest returns and tail-call
//! results through LLVM simplification without mixing escaped-call exits into
//! a function's return summary. Runnable lifts contain no such markers.
//! Indirect-target recovery retains width-correct integer expressions and
//! actual named-register return summaries, then substitutes caller bindings.
//! Sparse memory-effect snapshots forward shared-frame reads only when all
//! reaching paths establish the same store, including covered narrow loads.
//! Unknown aliases, overlapping writes, calls, volatile/atomic effects and
//! cycles stop foreign-frame forwarding. Caller-local spills retain the
//! existing escape checks and returning-call stack model.
//!
//! `CallSites` lifts functions in batches as an analysis asks for them
//! (`audit` walks from a call up through its callers).

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
};

use biara_abi::FunctionAbi;
use biara_cfg::{Cfg, ExitKind};
use biara_tcg::{ContextInfo, TempId, TempKind};
use inkwell::{
    attributes::{Attribute, AttributeLoc},
    basic_block::BasicBlock,
    context::Context,
    targets::TargetMachine,
    types::BasicTypeEnum,
    values::{
        AsValueRef, BasicValue, BasicValueEnum, CallSiteValue, FunctionValue, InstructionOpcode,
        InstructionValue, IntValue, PhiValue, PointerValue,
    },
};

use crate::{
    DISPATCH, Error,
    call_memory::{self, Address, MemoryFacts, Read},
    integer::IntOp,
    lower::PC_MD,
    memory,
};

pub const RETURN_MARKER: &str = "biara.return";

/// A size interval established from allocation arguments, not access spacing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SizeRange {
    pub lo: u64,
    pub hi: u64,
}

/// What an argument register holds at a call.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Arg {
    Const(u64),
    /// One of these (constants and import results; a select or phi).
    OneOf(Vec<Arg>),
    /// The caller's stack pointer at its entry, plus this offset.
    Stack(i64),
    /// The value the named register had on entry to the caller.
    Incoming(String),
    /// The word at the named register's entry value plus `off` (an
    /// element of an array the caller was passed, such as `argv`).
    Deref {
        reg: String,
        off: i64,
    },
    /// What the call to `import` at `pc` returned.
    Returned {
        import: String,
        pc: u64,
    },
    /// A nullable heap allocation site with its established size interval.
    Allocation {
        function: u64,
        pc: u64,
        allocator: String,
        size: Option<SizeRange>,
    },
    /// A word loaded from guest memory; readonly resolution may establish it.
    Load {
        base: Box<Arg>,
        off: i64,
        bits: u32,
    },
    /// A lifted function's result at a call, before following its return
    /// summary and substituting the arguments of that call.
    FunctionResult {
        function: u64,
        pc: u64,
    },
    /// A named register reloaded after a known call. Its actual return-state
    /// summary, not a calling-convention assumption, supplies the value.
    RegisterResult {
        function: u64,
        pc: u64,
        reg: String,
    },
    /// Pointer arithmetic over an origin which remains identifiable.
    Offset {
        base: Box<Arg>,
        off: i64,
    },
    /// A pointer returned from a callee's own frame, not the caller's.
    Frame {
        function: u64,
        pc: u64,
        off: i64,
    },
    /// Somewhere in `lo..=hi` (unsigned).
    Range {
        lo: u64,
        hi: u64,
    },
    /// A scalar computation, retaining the LLVM integer width and operands.
    Expr {
        op: IntOp,
        bits: u32,
        args: Vec<Arg>,
    },
    /// None of the above could be shown: the register was reloaded after a
    /// call that may have written it, the value merges too many paths, or
    /// it comes from untracked state (a global, the heap, a callee's
    /// private computation). Conservative: the audit treats it as neither
    /// constant nor input, so any check on it fires (`bad_fmt_global` pins
    /// this direction; bash still shows it for heap-built formats such as
    /// `mklong` results).
    Unknown,
}

impl Arg {
    pub fn offset(self, off: i64) -> Self {
        if off == 0 {
            return self;
        }
        match self {
            Self::Const(c) => Self::Const(c.wrapping_add(off as u64)),
            Self::Stack(o) => Self::Stack(o.wrapping_add(off)),
            Self::Frame {
                function,
                pc,
                off: o,
            } => Self::Frame {
                function,
                pc,
                off: o.wrapping_add(off),
            },
            Self::Offset { base, off: o } => (*base).offset(o.wrapping_add(off)),
            Self::OneOf(vs) => Self::OneOf(vs.into_iter().map(|v| v.offset(off)).collect()),
            Self::Unknown => Self::Unknown,
            base => Self::Offset {
                base: Box::new(base),
                off,
            },
        }
    }

    pub(crate) fn expression(op: IntOp, bits: u32, args: Vec<Self>) -> Self {
        if !(1..=64).contains(&bits)
            || args.len() != op.arity()
            || args.iter().any(|a| matches!(a, Self::Unknown))
        {
            return Self::Unknown;
        }
        if bits == 64
            && matches!(op, IntOp::Add | IntOp::Sub)
            && let Self::Const(c) = args[1]
        {
            let off = if op == IntOp::Sub {
                (c as i64).wrapping_neg()
            } else {
                c as i64
            };
            return args.into_iter().next().unwrap().offset(off);
        }
        let mut values = [0; 3];
        for (i, arg) in args.iter().enumerate() {
            match arg {
                Self::Const(v) => values[i] = *v,
                _ => return Self::Expr { op, bits, args },
            }
        }
        op.apply(bits, &values[..args.len()])
            .map_or(Self::Unknown, Self::Const)
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Const(c) => write!(f, "{c:#x}"),
            Self::OneOf(vs) => {
                let vs: Vec<String> = vs.iter().map(Arg::to_string).collect();
                write!(f, "{{{}}}", vs.join(", "))
            }
            Self::FunctionResult { function, pc } => write!(f, "sub_{function:x}()@{pc:#x}"),
            Self::RegisterResult { function, pc, reg } => {
                write!(f, "sub_{function:x}().{reg}@{pc:#x}")
            }
            Self::Offset { base, off } => write!(f, "({base}){off:+#x}"),
            Self::Frame { function, pc, off } => write!(f, "frame({function:#x}@{pc:#x}){off:+#x}"),
            Self::Allocation {
                function,
                pc,
                allocator,
                size,
            } => {
                write!(f, "{allocator}()@{pc:#x} in {function:#x}")?;
                if let Some(size) = size {
                    write!(f, " size=[{:#x},{:#x}]", size.lo, size.hi)?;
                }
                Ok(())
            }
            Self::Load { base, off, bits } => write!(f, "i{bits}[{base}{off:+#x}]"),
            Self::Returned { import, pc } => write!(f, "{import}()@{pc:#x}"),
            Self::Stack(o) if *o < 0 => write!(f, "sp-{:#x}", o.unsigned_abs()),
            Self::Stack(o) => write!(f, "sp+{o:#x}"),
            Self::Incoming(r) => write!(f, "{r}@entry"),
            Self::Deref { reg, off } if *off < 0 => {
                write!(f, "[{reg}@entry-{:#x}]", off.unsigned_abs())
            }
            Self::Deref { reg, off } => write!(f, "[{reg}@entry+{off:#x}]"),
            Self::Range { lo, hi } => write!(f, "[{lo:#x}, {hi:#x}]"),
            Self::Expr { op, bits, args } => {
                write!(f, "{op:?}.i{bits}(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i != 0 {
                        f.write_str(", ")?;
                    }
                    arg.fmt(f)?;
                }
                f.write_str(")")
            }
            Self::Unknown => write!(f, "?"),
        }
    }
}

/// What a call reaches.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Callee {
    /// An import, through its PLT stub or GOT slot.
    Import(String),
    /// A function of the CFG, by entry.
    Function(u64),
    /// An indirect destination which cannot be made a single direct call.
    Indirect { target: Arg },
}

impl fmt::Display for Callee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Import(name) => f.write_str(name),
            Self::Function(entry) => write!(f, "sub_{entry:x}"),
            Self::Indirect { target } => write!(f, "*({target})"),
        }
    }
}

/// A call or tail call.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CallSite {
    /// Entry of the calling function.
    pub caller: u64,
    /// Address of the calling (or jumping) instruction.
    pub pc: u64,
    pub callee: Callee,
    /// The calling convention's argument registers, in order.
    pub args: Vec<Arg>,
    /// Named register values at this boundary, including hidden frame registers.
    pub registers: BTreeMap<std::sync::Arc<str>, Arg>,
}

impl CallSite {
    /// The import called, if the callee is one.
    pub fn import(&self) -> Option<&str> {
        match &self.callee {
            Callee::Import(name) => Some(name),
            Callee::Function(_) | Callee::Indirect { .. } => None,
        }
    }
}

unsafe extern "C" {
    fn biara_value_ranges(
        func: *mut std::ffi::c_void,
        n: usize,
        values: *const *mut std::ffi::c_void,
        ctx: *const *mut std::ffi::c_void,
        lo: *mut u64,
        hi: *mut u64,
        known: *mut i32,
    );
}

/// Every call to an import (through its PLT stub or GOT slot) in the
/// functions of `cfg`, by caller and pc.
pub fn import_calls(
    machine: &TargetMachine,
    info: &ContextInfo,
    cfg: &Cfg,
) -> Result<Vec<CallSite>, Error> {
    let mut sites = CallSites::new(machine, info, cfg)?;
    sites.add(&sites.import_callers())?;
    Ok(sites
        .sites
        .into_iter()
        .filter(|c| c.import().is_some())
        .collect())
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct CallFacts {
    pub lifted: BTreeSet<u64>,
    pub sites: Vec<CallSite>,
    pub returns: BTreeMap<u64, Arg>,
    pub(crate) memory: BTreeMap<u64, MemoryFacts>,
    register_returns: BTreeMap<u64, BTreeMap<String, Arg>>,
}

impl CallFacts {
    /// Merge independently lifted function summaries without losing private
    /// memory or named-register facts. Each function must have one producer
    /// in a resolution batch; later summaries replace an older function's facts.
    pub fn merge(&mut self, mut other: Self) {
        self.lifted.append(&mut other.lifted);
        self.sites.append(&mut other.sites);
        self.returns.append(&mut other.returns);
        self.memory.append(&mut other.memory);
        self.register_returns.append(&mut other.register_returns);
    }
}

/// The call sites of a growing set of functions of a CFG: `add` lifts a
/// batch (into a module of its own) and records every call in it.
pub struct CallSites<'a> {
    machine: &'a TargetMachine,
    info: &'a ContextInfo,
    cfg: &'a Cfg,
    /// Callee-saved registers keep their values across calls whose callee
    /// (PLT stubs included) is shown to preserve them.
    abis: Option<BTreeMap<u64, FunctionAbi>>,
    sp: TempId,
    /// Env slot offset of every register global.
    homes: HashMap<i64, TempId>,
    /// Env slot offset of the result register.
    ret: i64,
    /// The convention's argument registers and their env slot offsets.
    args: Vec<(TempId, i64)>,
    /// What callees may write of the caller's frame: from the stack pointer
    /// written back at the call plus `.0`, `.1` bytes (`CallConv::home`).
    home: (i64, i64),
    lifted: BTreeSet<u64>,
    sites: Vec<CallSite>,
    returns: BTreeMap<u64, Arg>,
    by_pc: BTreeMap<(u64, u64), std::ops::Range<usize>>,
    memory: BTreeMap<u64, MemoryFacts>,
    register_returns: BTreeMap<u64, BTreeMap<String, Arg>>,
    resolution_limited: Cell<bool>,
}

impl<'a> CallSites<'a> {
    pub fn new(
        machine: &'a TargetMachine,
        info: &'a ContextInfo,
        cfg: &'a Cfg,
    ) -> Result<Self, Error> {
        Self::with_abis(machine, info, cfg, Some(biara_abi::analyze(cfg, info)?))
    }

    /// Target discovery must not recursively require ABI recovery.
    pub(crate) fn for_resolution(
        machine: &'a TargetMachine,
        info: &'a ContextInfo,
        cfg: &'a Cfg,
    ) -> Result<Self, Error> {
        Self::with_abis(machine, info, cfg, None)
    }

    /// Annotation-driven ABI overrides: caller supplies the (already
    /// annotation-merged) map instead of re-running `biara_abi::analyze`.
    pub fn with_abis(
        machine: &'a TargetMachine,
        info: &'a ContextInfo,
        cfg: &'a Cfg,
        abis: Option<BTreeMap<u64, FunctionAbi>>,
    ) -> Result<Self, Error> {
        let spec = cfg.spec(&info.arch)?;
        let global = |name: &str| {
            info.globals
                .iter()
                .position(|g| g.name.as_deref() == Some(name))
                .map(|i| i as TempId)
                .ok_or_else(|| Error::Llvm(format!("no global {name}")))
        };
        let homes = info
            .globals
            .iter()
            .enumerate()
            .filter(|(_, g)| g.kind == TempKind::Global && g.mem_base == Some(info.env_global))
            .map(|(i, g)| (g.mem_offset, i as TempId))
            .collect();
        let ret = info.globals[global(spec.unknown_call.results[0])? as usize].mem_offset;
        let args = spec
            .unknown_call
            .args
            .iter()
            .map(|r| global(r).map(|g| (g, info.globals[g as usize].mem_offset)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            machine,
            info,
            cfg,
            abis,
            sp: global(spec.sp)?,
            homes,
            ret,
            args,
            home: (
                match spec.ret {
                    biara_cfg::ReturnConvention::Stack { word } => word as i64,
                    biara_cfg::ReturnConvention::LinkRegister(_) => 0,
                },
                spec.unknown_call.home as i64,
            ),
            lifted: BTreeSet::new(),
            sites: Vec::new(),
            returns: BTreeMap::new(),
            by_pc: BTreeMap::new(),
            memory: BTreeMap::new(),
            register_returns: BTreeMap::new(),
            resolution_limited: Cell::new(false),
        })
    }

    pub fn cfg(&self) -> &'a Cfg {
        self.cfg
    }

    /// Names of the argument registers, in the order of `CallSite::args`.
    pub fn arg_registers(&self) -> Vec<String> {
        self.args.iter().map(|&(g, _)| name(self.info, g)).collect()
    }

    /// Functions (PLT stubs aside) that call or tail-call an import.
    pub fn import_callers(&self) -> BTreeSet<u64> {
        let cfg = self.cfg;
        let reaches_import = |b: &u64| {
            cfg.blocks[b].exits.iter().any(|x| match x.kind {
                ExitKind::Call { target: t, .. } | ExitKind::Jump(t) => {
                    cfg.stub_import(t).is_some()
                }
                ExitKind::IndirectCall { slot: Some(s), .. }
                | ExitKind::IndirectJump { slot: Some(s) } => cfg.imports.contains_key(&s),
                _ => false,
            })
        };
        cfg.functions
            .values()
            .filter(|f| cfg.stub_import(f.entry).is_none() && f.blocks.iter().any(reaches_import))
            .map(|f| f.entry)
            .collect()
    }

    /// Functions whose call sites are recorded.
    pub fn lifted(&self) -> &BTreeSet<u64> {
        &self.lifted
    }

    /// Every call in the lifted functions, by caller and pc.
    pub fn sites(&self) -> &[CallSite] {
        &self.sites
    }
    pub fn into_facts(self) -> CallFacts {
        CallFacts {
            lifted: self.lifted,
            sites: self.sites,
            returns: self.returns,
            memory: self.memory,
            register_returns: self.register_returns,
        }
    }

    pub fn import_facts(&mut self, facts: CallFacts) {
        self.lifted.extend(facts.lifted);
        self.sites.extend(facts.sites);
        self.returns.extend(facts.returns);
        self.memory.extend(facts.memory);
        self.register_returns.extend(facts.register_returns);
        self.sites.sort_by_key(|site| (site.caller, site.pc));
        self.by_pc.clear();
        for (index, site) in self.sites.iter().enumerate() {
            self.by_pc
                .entry((site.pc, site.caller))
                .or_insert(index..index)
                .end = index + 1;
        }
    }

    /// Lift the functions of `entries` not lifted yet (PLT stubs and
    /// unknown entries aside) and record their call sites.
    pub fn add(&mut self, entries: &BTreeSet<u64>) -> Result<(), Error> {
        let cfg = self.cfg;
        let only: BTreeSet<u64> = entries
            .iter()
            .copied()
            .filter(|e| {
                cfg.functions.contains_key(e)
                    && cfg.stub_import(*e).is_none()
                    && !self.lifted.contains(e)
            })
            .collect();
        // Caller discovery can expose thousands of bodies at once. Keep raw
        // LLVM IR bounded by both body count and TCG instruction volume.
        let mut entries = only.into_iter().peekable();
        while entries.peek().is_some() {
            let mut batch = BTreeSet::new();
            let mut operations = 0usize;
            while let Some(&entry) = entries.peek() {
                let size = cfg.functions[&entry]
                    .blocks
                    .iter()
                    .map(|pc| cfg.blocks[pc].block.ops.len())
                    .fold(0usize, usize::saturating_add);
                if !batch.is_empty()
                    && (batch.len() == 32 || operations.saturating_add(size) > 65_536)
                {
                    break;
                }
                entries.next();
                batch.insert(entry);
                operations = operations.saturating_add(size);
            }
            let cx = Context::create();
            let analysis = crate::Analysis {
                only: &batch,
                target_markers: false,
            };
            let module = crate::lift_with(
                &cx,
                self.machine,
                self.info,
                cfg,
                self.abis.as_ref(),
                &|_| None,
                "calls",
                Some(analysis),
            )?;
            memory::simplify(&module, self.machine)?;
            self.collect_unindexed(&module);
        }
        self.index_sites();
        Ok(())
    }

    pub(crate) fn collect(&mut self, module: &inkwell::module::Module<'_>) {
        self.collect_unindexed(module);
        self.index_sites();
    }

    fn collect_unindexed(&mut self, module: &inkwell::module::Module<'_>) {
        let pc_kind = module.get_context().get_kind_id(PC_MD);
        for f in module.get_functions() {
            let Some(caller) = f
                .get_name()
                .to_str()
                .ok()
                .and_then(|n| n.strip_prefix("sub_"))
                .and_then(|h| u64::from_str_radix(h, 16).ok())
            else {
                continue;
            };
            if f.get_first_basic_block().is_some() && self.lifted.insert(caller) {
                self.function_sites(f, caller, pc_kind);
            }
        }
    }

    fn index_sites(&mut self) {
        self.sites.sort_by_key(|c| (c.caller, c.pc));
        self.by_pc.clear();
        for (index, site) in self.sites.iter().enumerate() {
            self.by_pc
                .entry((site.pc, site.caller))
                .or_insert(index..index)
                .end = index + 1;
        }
    }

    fn function_sites<'ctx>(&mut self, f: FunctionValue<'ctx>, caller: u64, pc_kind: u32) {
        fn returned_frame(arg: Arg, function: u64, pc: u64) -> Arg {
            match arg {
                Arg::Stack(off) => Arg::Frame { function, pc, off },
                Arg::OneOf(vs) => Arg::OneOf(
                    vs.into_iter()
                        .map(|v| returned_frame(v, function, pc))
                        .collect(),
                ),
                v => v,
            }
        }
        let (cfg, info) = (self.cfg, self.info);
        let arg_homes: Vec<i64> = self.args.iter().map(|&(_, off)| off).collect();
        let sp_home = info.globals[self.sp as usize].mem_offset;
        let fx = FunctionFacts::new(
            f,
            &self.homes,
            self.ret,
            (self.sp, sp_home),
            &arg_homes,
            self.home,
            self.abis.is_none(),
        );
        let returned = |call: InstructionValue<'ctx>| {
            let pc = pc_of(call, pc_kind)?;
            match callee(cfg, call, pc)? {
                Callee::Import(import) => Some(Arg::Returned { import, pc }),
                Callee::Function(function) => Some(Arg::FunctionResult { function, pc }),
                Callee::Indirect { .. } => None,
            }
        };
        let classify = |reaching: Reaching<'ctx>| match reaching {
            Reaching::Entry => None,
            Reaching::Call(c) => returned(c),
            Reaching::Unknown => None,
            Reaching::Stored(v) => Some(fx.argument(v, info, &returned)),
        };
        let mut ranges: Vec<(usize, usize, IntValue, InstructionValue)> = Vec::new();
        let mut returns = Vec::new();
        let mut register_returns: BTreeMap<String, Vec<Arg>> = BTreeMap::new();
        let register_value = |reaching, g| match reaching {
            Reaching::Entry if g == self.sp => Arg::Stack(0),
            Reaching::Entry => Arg::Incoming(name(info, g)),
            Reaching::Call(call) if self.homes[&self.ret] != g => {
                register_result(returned(call), name(info, g))
            }
            r => classify(r).unwrap_or(Arg::Unknown),
        };
        for bb in f.get_basic_blocks() {
            for inst in bb.get_instructions() {
                let return_boundary = inst.get_opcode() == InstructionOpcode::Call
                    && CallSiteValue::try_from(inst)
                        .ok()
                        .and_then(|call| call.get_called_fn_value())
                        .is_some_and(|callee| {
                            callee.get_name().to_bytes() == RETURN_MARKER.as_bytes()
                        });
                if return_boundary {
                    if let Some(pc) = pc_of(inst, pc_kind) {
                        let value = match fx.reaching_store(inst, self.ret) {
                            Reaching::Entry => Arg::Incoming(name(info, self.homes[&self.ret])),
                            r => classify(r).unwrap_or(Arg::Unknown),
                        };
                        let value = returned_frame(value, caller, pc);
                        if !returns.contains(&value) {
                            returns.push(value);
                        }
                        for (&off, &g) in &self.homes {
                            if info.globals[g as usize].ty.bits() > 64 {
                                continue;
                            }
                            let value = register_value(fx.reaching_store(inst, off), g);
                            let values = register_returns.entry(name(info, g)).or_default();
                            if !values.contains(&value) {
                                values.push(value);
                            }
                        }
                    }
                    continue;
                }
                if inst.get_opcode() != InstructionOpcode::Call {
                    continue;
                }
                let Some(pc) = pc_of(inst, pc_kind) else {
                    continue;
                };
                let Some(mut callee) = callee(cfg, inst, pc) else {
                    continue;
                };
                if let Callee::Indirect { target } = &mut callee {
                    let home = info.globals[info.pc_global as usize].mem_offset;
                    *target = classify(fx.reaching_store(inst, home)).unwrap_or(Arg::Unknown);
                }
                let mut values = Vec::with_capacity(self.args.len());
                for (i, &(g, off)) in self.args.iter().enumerate() {
                    let arg = match fx.reaching_store(inst, off) {
                        Reaching::Entry => Arg::Incoming(name(info, g)),
                        Reaching::Call(c) => register_value(Reaching::Call(c), g),
                        Reaching::Unknown => Arg::Unknown,
                        Reaching::Stored(v) => {
                            let arg = fx.argument(v, info, &returned);
                            // Refine uncertain expressions and joins as well
                            // as unknown leaves. Pure constants/ranges need
                            // no query; only proven bounds replace the facts.
                            if (matches!(arg, Arg::Unknown | Arg::Expr { .. })
                                || matches!(&arg, Arg::OneOf(arms) if arms.iter().any(|a|
                                    matches!(a, Arg::Unknown | Arg::Expr { .. }))))
                                && let BasicValueEnum::IntValue(iv) = v
                            {
                                ranges.push((self.sites.len(), i, iv, inst));
                            }
                            arg
                        }
                    };
                    values.push(arg);
                }
                let mut registers = BTreeMap::new();
                for (&off, &g) in &self.homes {
                    let Some(reg) = info.globals[g as usize].name.as_ref() else {
                        continue;
                    };
                    if info.globals[g as usize].ty.bits() > 64 {
                        continue;
                    }
                    let value = register_value(fx.reaching_store(inst, off), g);
                    if !matches!(value, Arg::Unknown) {
                        registers.insert(reg.clone(), value);
                    }
                }
                self.sites.push(CallSite {
                    caller,
                    pc,
                    callee,
                    args: values,
                    registers,
                });
            }
        }
        let summary = match returns.len() {
            0 => Arg::Unknown,
            1 => returns.pop().unwrap(),
            n if n <= MAX_ALTERNATIVES => Arg::OneOf(returns),
            _ => Arg::Unknown,
        };
        self.returns.insert(caller, summary);
        let closed = cfg.functions.get(&caller).is_some_and(|function| {
            function.blocks.iter().all(|b| {
                cfg.blocks[b].exits.iter().all(|exit| {
                    !matches!(exit.kind, ExitKind::IndirectJump { .. }
                    if cfg.jump_tables.get(b).is_none_or(BTreeSet::is_empty)
                        || cfg.incomplete_jump_tables.contains(b))
                        && exit
                            .kind
                            .local_successors()
                            .all(|pc| !cfg.unresolved.contains_key(&pc))
                })
            })
        });
        if closed {
            self.register_returns.insert(
                caller,
                register_returns
                    .into_iter()
                    .map(|(reg, values)| {
                        (
                            reg,
                            match values.len() {
                                1 => values.into_iter().next().unwrap(),
                                2..=MAX_ALTERNATIVES => Arg::OneOf(values),
                                _ => Arg::Unknown,
                            },
                        )
                    })
                    .collect(),
            );
        }
        let memory = call_memory::collect(
            f,
            |v| fx.address(v),
            |op| fx.home_offset(op).is_some(),
            |v| fx.argument(v, info, &returned),
            memory_barrier,
            |i| {
                let pc = pc_of(i, pc_kind)?;
                callee(cfg, i, pc).map(|_| pc)
            },
        );
        self.memory.insert(caller, memory);
        if ranges.is_empty() {
            return;
        }
        let vals: Vec<_> = ranges.iter().map(|r| r.2.as_value_ref().cast()).collect();
        let ctx: Vec<_> = ranges.iter().map(|r| r.3.as_value_ref().cast()).collect();
        let (mut lo, mut hi, mut known) = (
            vec![0; ranges.len()],
            vec![0; ranges.len()],
            vec![0; ranges.len()],
        );
        unsafe {
            biara_value_ranges(
                f.as_value_ref().cast(),
                ranges.len(),
                vals.as_ptr(),
                ctx.as_ptr(),
                lo.as_mut_ptr(),
                hi.as_mut_ptr(),
                known.as_mut_ptr(),
            );
        }
        for (k, &(site, i, ..)) in ranges.iter().enumerate() {
            if known[k] != 0 {
                self.sites[site].args[i] = Arg::Range {
                    lo: lo[k],
                    hi: hi[k],
                };
            }
        }
    }
    /// Follow internal return summaries and aliases. Missing summaries and
    /// recursive cycles remain unknown; unbound external inputs remain inputs.
    pub fn resolve_arg(&self, arg: &Arg, caller: u64) -> Arg {
        self.resolve_bound(arg, caller, 0, &[], 0, &mut 256)
    }

    pub(crate) fn substitute_arg(&self, arg: &Arg, callee: u64, call: &CallSite) -> Arg {
        self.resolve_bound(arg, callee, call.pc, &[call], 0, &mut 256)
    }

    fn calls_at(&self, function: u64, pc: u64) -> &[CallSite] {
        self.by_pc
            .get(&(pc, function))
            .map_or(&[], |range| &self.sites[range.clone()])
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_bound(
        &self,
        arg: &Arg,
        at: u64,
        pc: u64,
        bindings: &[&CallSite],
        depth: usize,
        budget: &mut usize,
    ) -> Arg {
        // Depth alone permits exponential expansion of branching return
        // summaries. All sibling paths share a finite per-query work budget.
        if depth >= 64 || bindings.len() > 16 || *budget == 0 {
            self.resolution_limited.set(true);
            return Arg::Unknown;
        }
        *budget -= 1;
        match arg {
            Arg::Incoming(reg) => {
                let Some(binding) = bindings
                    .iter()
                    .rev()
                    .find(|c| matches!(c.callee, Callee::Function(f) if f == at))
                else {
                    return arg.clone();
                };
                binding
                    .registers
                    .get(reg.as_str())
                    .or_else(|| {
                        self.args
                            .iter()
                            .position(|&(g, _)| {
                                self.info.globals[g as usize].name.as_deref() == Some(reg)
                            })
                            .and_then(|i| binding.args.get(i))
                    })
                    .map_or(Arg::Unknown, |arg| {
                        self.resolve_bound(
                            arg,
                            binding.caller,
                            binding.pc,
                            bindings,
                            depth + 1,
                            budget,
                        )
                    })
            }
            Arg::Deref { reg, off } => self.resolve_load(
                &Arg::Incoming(reg.clone()),
                (*off, 64),
                at,
                pc,
                bindings,
                depth + 1,
                budget,
            ),
            Arg::Load { base, off, bits } => {
                self.resolve_load(base, (*off, *bits), at, pc, bindings, depth + 1, budget)
            }
            Arg::Expr { op, bits, args } => Arg::expression(
                *op,
                *bits,
                args.iter()
                    .map(|arg| self.resolve_bound(arg, at, pc, bindings, depth + 1, budget))
                    .collect(),
            ),
            Arg::FunctionResult { function, pc } | Arg::RegisterResult { function, pc, .. } => {
                let Some(call) = self
                    .calls_at(at, *pc)
                    .iter()
                    .find(|c| matches!(c.callee, Callee::Function(f) if f == *function))
                else {
                    return Arg::Unknown;
                };
                let Some(summary) = self.result_summary(arg) else {
                    return Arg::Unknown;
                };
                if bindings.iter().any(|bound| std::ptr::eq(*bound, call)) {
                    return Arg::Unknown;
                }
                if bindings.len() == 16 {
                    self.resolution_limited.set(true);
                    return Arg::Unknown;
                }
                let mut next = [call; 16];
                next[..bindings.len()].copy_from_slice(bindings);
                next[bindings.len()] = call;
                self.resolve_bound(
                    summary,
                    *function,
                    0,
                    &next[..bindings.len() + 1],
                    depth + 1,
                    budget,
                )
            }
            Arg::Returned { import, pc } => {
                let Some(call) = self
                    .calls_at(at, *pc)
                    .iter()
                    .find(|c| c.import() == Some(import))
                else {
                    return arg.clone();
                };
                let base = import.split('@').next().unwrap_or(import);
                let base = base.strip_prefix("__").unwrap_or(base);
                let mut get = |i: usize| {
                    call.args.get(i).map_or(Arg::Unknown, |arg| {
                        self.resolve_bound(arg, at, *pc, bindings, depth + 1, budget)
                    })
                };
                match base {
                    "memcpy" | "memmove" | "memset" | "memcpy_chk" | "memmove_chk"
                    | "memset_chk" => get(0),
                    "malloc" | "calloc" | "realloc" | "aligned_alloc" => {
                        let size =
                            match base {
                                "calloc" => size_range(&get(0)).zip(size_range(&get(1))).and_then(
                                    |(a, b)| {
                                        Some(SizeRange {
                                            lo: a.lo.checked_mul(b.lo)?,
                                            hi: a.hi.checked_mul(b.hi)?,
                                        })
                                    },
                                ),
                                "realloc" | "aligned_alloc" => size_range(&get(1)),
                                _ => size_range(&get(0)),
                            };
                        Arg::Allocation {
                            function: at,
                            pc: *pc,
                            allocator: base.to_owned(),
                            size,
                        }
                    }
                    _ => arg.clone(),
                }
            }
            Arg::Stack(off) => {
                let Some(binding) = bindings
                    .iter()
                    .rev()
                    .find(|c| matches!(c.callee, Callee::Function(f) if f == at))
                else {
                    return arg.clone();
                };
                let sp = self.info.globals[self.sp as usize]
                    .name
                    .as_deref()
                    .unwrap_or_default();
                binding.registers.get(sp).map_or(Arg::Unknown, |value| {
                    self.resolve_bound(
                        &value.clone().offset(*off),
                        binding.caller,
                        binding.pc,
                        bindings,
                        depth + 1,
                        budget,
                    )
                })
            }
            Arg::Offset { base, off } => self
                .resolve_bound(base, at, pc, bindings, depth + 1, budget)
                .offset(*off),
            Arg::OneOf(values) => {
                let mut result = Vec::with_capacity(values.len());
                for value in values {
                    let value = self.resolve_bound(value, at, pc, bindings, depth + 1, budget);
                    if !result.contains(&value) {
                        result.push(value);
                    }
                }
                if result.len() == 1 {
                    result.pop().unwrap()
                } else {
                    Arg::OneOf(result)
                }
            }
            _ => arg.clone(),
        }
    }

    fn bind_pointer(
        &self,
        arg: &Arg,
        at: u64,
        binding: &CallSite,
        depth: usize,
        budget: &mut usize,
    ) -> Arg {
        if depth >= 64 || *budget == 0 {
            self.resolution_limited.set(true);
            return Arg::Unknown;
        }
        *budget -= 1;
        match arg {
            Arg::Incoming(reg) => binding
                .registers
                .get(reg.as_str())
                .cloned()
                .unwrap_or(Arg::Unknown),
            Arg::Stack(off) => binding
                .registers
                .get(
                    self.info.globals[self.sp as usize]
                        .name
                        .as_deref()
                        .unwrap_or_default(),
                )
                .cloned()
                .unwrap_or(Arg::Unknown)
                .offset(*off),
            Arg::Offset { base, off } => self
                .bind_pointer(base, at, binding, depth + 1, budget)
                .offset(*off),
            Arg::Expr { op, bits, args } => Arg::expression(
                *op,
                *bits,
                args.iter()
                    .map(|a| self.bind_pointer(a, at, binding, depth + 1, budget))
                    .collect(),
            ),
            Arg::FunctionResult { .. } | Arg::RegisterResult { .. } => {
                self.resolve_bound(arg, at, binding.pc, &[binding], depth + 1, budget)
            }
            _ => arg.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_load(
        &self,
        base: &Arg,
        load: (i64, u32),
        at: u64,
        pc: u64,
        bindings: &[&CallSite],
        depth: usize,
        budget: &mut usize,
    ) -> Arg {
        let (off, bits) = load;
        if depth >= 64 || *budget == 0 {
            self.resolution_limited.set(true);
            return Arg::Unknown;
        }
        *budget -= 1;
        let Some(binding) = bindings
            .iter()
            .rev()
            .find(|c| matches!(c.callee, Callee::Function(f) if f == at))
        else {
            let base = self.resolve_bound(base, at, pc, bindings, depth + 1, budget);
            return match base {
                Arg::Incoming(reg) if bits == 64 => Arg::Deref { reg, off },
                base => Arg::Load {
                    base: Box::new(base),
                    off,
                    bits,
                },
            };
        };
        let pointer = self
            .bind_pointer(base, at, binding, depth + 1, budget)
            .offset(off);
        let address = match &pointer {
            Arg::Stack(off) => Some(Address {
                reg: self.sp,
                off: *off,
            }),
            Arg::Incoming(reg) => self
                .homes
                .values()
                .find(|&&g| self.info.globals[g as usize].name.as_deref() == Some(reg))
                .map(|&reg| Address { reg, off: 0 }),
            Arg::Offset { base, off } => match &**base {
                Arg::Incoming(reg) => self
                    .homes
                    .values()
                    .find(|&&g| self.info.globals[g as usize].name.as_deref() == Some(reg))
                    .map(|&reg| Address { reg, off: *off }),
                _ => None,
            },
            _ => None,
        };
        if let Some(address) = address {
            match self
                .memory
                .get(&binding.caller)
                .map_or(Read::Unknown, |facts| {
                    facts.lookup(binding.pc, address, bits)
                }) {
                Read::Value {
                    value,
                    bits: stored,
                    shift,
                } => {
                    let value = extract_word(value.clone(), stored, shift, bits);
                    return self.resolve_bound(
                        &value,
                        binding.caller,
                        binding.pc,
                        bindings,
                        depth + 1,
                        budget,
                    );
                }
                Read::Entry => {
                    return self.resolve_load(
                        &pointer,
                        (0, bits),
                        binding.caller,
                        binding.pc,
                        bindings,
                        depth + 1,
                        budget,
                    );
                }
                Read::Unknown => return Arg::Unknown,
            }
        }
        // Only a concrete non-frame address can be deferred to readonly image
        // reads. An unresolved address must not lose the caller's write history.
        match pointer {
            Arg::Const(_) => Arg::Load {
                base: Box::new(pointer),
                off: 0,
                bits,
            },
            _ => Arg::Unknown,
        }
    }

    pub(crate) fn analysis_limited(&self) -> bool {
        self.resolution_limited.get() || self.memory.values().any(|facts| facts.limited)
    }

    /// Return summaries needed by a value, for demand-driven lifting.
    fn result_summary(&self, arg: &Arg) -> Option<&Arg> {
        match arg {
            Arg::FunctionResult { function, .. } => self.returns.get(function),
            Arg::RegisterResult { function, reg, .. } => {
                self.register_returns.get(function)?.get(reg)
            }
            _ => None,
        }
    }

    pub fn missing_summaries(&self, arg: &Arg) -> BTreeSet<u64> {
        fn visit(
            arg: &Arg,
            sites: &CallSites<'_>,
            out: &mut BTreeSet<u64>,
            seen: &mut BTreeSet<(bool, u64, Option<String>)>,
        ) {
            match arg {
                Arg::FunctionResult { function, pc } | Arg::RegisterResult { function, pc, .. } => {
                    let reg = match arg {
                        Arg::RegisterResult { reg, .. } => Some(reg.clone()),
                        _ => None,
                    };
                    if seen.insert((true, *function, reg)) {
                        if let Some(summary) = sites.result_summary(arg) {
                            visit(summary, sites, out, seen);
                        } else {
                            out.insert(*function);
                        }
                    }
                    if seen.insert((false, *pc, None)) {
                        for (_, range) in sites.by_pc.range((*pc, 0)..=(*pc, u64::MAX)) {
                            for call in &sites.sites[range.clone()] {
                                for arg in call.args.iter().chain(call.registers.values()) {
                                    visit(arg, sites, out, seen);
                                }
                            }
                        }
                    }
                }
                Arg::Returned { pc, .. } if seen.insert((false, *pc, None)) => {
                    for (_, range) in sites.by_pc.range((*pc, 0)..=(*pc, u64::MAX)) {
                        for call in &sites.sites[range.clone()] {
                            for arg in &call.args {
                                visit(arg, sites, out, seen);
                            }
                        }
                    }
                }
                Arg::Offset { base, .. } | Arg::Load { base, .. } => visit(base, sites, out, seen),
                Arg::OneOf(vs) | Arg::Expr { args: vs, .. } => {
                    for v in vs {
                        visit(v, sites, out, seen);
                    }
                }
                _ => {}
            }
        }
        let mut out = BTreeSet::new();
        visit(arg, self, &mut out, &mut BTreeSet::new());
        out
    }
}

fn register_result(result: Option<Arg>, reg: String) -> Arg {
    match result {
        Some(Arg::FunctionResult { function, pc }) => Arg::RegisterResult { function, pc, reg },
        _ => Arg::Unknown,
    }
}

fn name(info: &ContextInfo, g: TempId) -> String {
    info.globals[g as usize]
        .name
        .as_deref()
        .unwrap_or_default()
        .to_owned()
}

fn pc_of(inst: InstructionValue, kind: u32) -> Option<u64> {
    let md = inst.get_metadata(kind)?;
    md.get_node_values()?
        .first()?
        .into_int_value()
        .get_zero_extended_constant()
}

/// What a call instruction at guest `pc` reaches, from its block's exit:
/// a lifted function (`sub_<entry>`), or through `biara.dispatch` an
/// import's GOT slot or PLT stub (stubs get no bodies) or a function
/// outside the module.
fn callee(cfg: &Cfg, inst: InstructionValue, pc: u64) -> Option<Callee> {
    let called = CallSiteValue::try_from(inst).ok()?.get_called_fn_value()?;
    let called = called.get_name().to_bytes();
    if called != DISPATCH.as_bytes() && !called.starts_with(b"sub_") {
        return None;
    }
    if let Some(target) = std::str::from_utf8(called)
        .ok()
        .and_then(|n| n.strip_prefix("sub_"))
        .and_then(|n| u64::from_str_radix(n, 16).ok())
        .filter(|t| cfg.functions.contains_key(t))
    {
        return Some(match cfg.stub_import(target) {
            Some(import) => Callee::Import(import.to_owned()),
            None => Callee::Function(target),
        });
    }
    let (_, b) = cfg.blocks.range(..=pc).next_back()?;
    if b.insns.last() != Some(&pc) {
        return None;
    }
    b.exits.iter().find_map(|x| match x.kind {
        ExitKind::IndirectCall { slot, .. } | ExitKind::IndirectJump { slot } => {
            Some(match slot.and_then(|s| cfg.imports.get(&s)) {
                Some(import) => Callee::Import(import.clone()),
                None => Callee::Indirect {
                    target: Arg::Unknown,
                },
            })
        }
        ExitKind::Call { target: t, .. } | ExitKind::Jump(t) => match cfg.stub_import(t) {
            Some(import) => Some(Callee::Import(import.to_owned())),
            None => cfg
                .functions
                .contains_key(&t)
                .then_some(Callee::Function(t)),
        },
        _ => None,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reaching<'ctx> {
    Stored(BasicValueEnum<'ctx>),
    /// Not written since the function's entry.
    Entry,
    /// Not written since this call, which may have.
    Call(InstructionValue<'ctx>),
    Unknown,
}

/// Values that are one of more alternatives than this are not kept apart.
const MAX_ALTERNATIVES: usize = 8;

/// Instructions a search for a frame slot's store looks back through at
/// most.
const MAX_SLOT_WALK: usize = 4096;

/// A value as one of a few constants, call results and words loaded
/// through entry registers, or a register's entry value plus an offset.
enum Sym<'ctx> {
    OneOf(Vec<Leaf<'ctx>>),
    Reg(TempId, i64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Leaf<'ctx> {
    Const(u64),
    /// The result register as this call left it.
    Returned(InstructionValue<'ctx>, i64),
    /// The loaded word, followed by an offset added to that value.
    Loaded(TempId, i64, i64),
}

/// Extract a covered little-endian load from a single known scalar store.
fn extract_word(value: Arg, stored: u32, shift: u32, bits: u32) -> Arg {
    if !(1..=64).contains(&stored) || bits == 0 || bits > stored || shift > stored - bits {
        return Arg::Unknown;
    }
    let value = if shift == 0 {
        value
    } else {
        Arg::expression(
            IntOp::LShr,
            stored,
            vec![value, Arg::Const(u64::from(shift))],
        )
    };
    if bits == stored {
        value
    } else {
        Arg::expression(IntOp::Trunc, bits, vec![value])
    }
}

pub(crate) fn size_range(arg: &Arg) -> Option<SizeRange> {
    match arg {
        Arg::Const(n) => Some(SizeRange { lo: *n, hi: *n }),
        Arg::Range { lo, hi } => Some(SizeRange { lo: *lo, hi: *hi }),
        Arg::Expr {
            op: IntOp::And,
            bits,
            args,
        } if (1..=64).contains(bits) => {
            let mask = u64::MAX >> (64 - bits);
            args.iter()
                .filter_map(|arg| match arg {
                    Arg::Const(value) => Some(value & mask),
                    _ => None,
                })
                .min()
                .map(|hi| SizeRange { lo: 0, hi })
        }
        Arg::Expr {
            op: IntOp::Trunc,
            bits,
            ..
        } if (1..=64).contains(bits) => Some(SizeRange {
            lo: 0,
            hi: u64::MAX >> (64 - bits),
        }),
        Arg::Expr {
            op: IntOp::ZExt { from },
            bits,
            ..
        } if *from > 0 && from <= bits && *bits <= 64 => Some(SizeRange {
            lo: 0,
            hi: u64::MAX >> (64 - from),
        }),
        Arg::OneOf(vs) if !vs.is_empty() => {
            let mut ranges = vs.iter().map(size_range);
            let mut out = ranges.next()??;
            for range in ranges {
                let range = range?;
                out.lo = out.lo.min(range.lo);
                out.hi = out.hi.max(range.hi);
            }
            Some(out)
        }
        _ => None,
    }
}

fn symbolic_arg<'ctx>(
    sym: Sym<'ctx>,
    info: &ContextInfo,
    sp: TempId,
    returned: &impl Fn(InstructionValue<'ctx>) -> Option<Arg>,
) -> Option<Arg> {
    match sym {
        Sym::Reg(r, off) if r == sp => Some(Arg::Stack(off)),
        Sym::Reg(r, off) => Some(Arg::Incoming(name(info, r)).offset(off)),
        Sym::OneOf(leaves) => {
            let mut values = leaves
                .into_iter()
                .map(|leaf| match leaf {
                    Leaf::Const(c) => Some(Arg::Const(c)),
                    Leaf::Returned(call, off) => returned(call).map(|arg| arg.offset(off)),
                    Leaf::Loaded(r, off, add) => Some(
                        Arg::Deref {
                            reg: name(info, r),
                            off,
                        }
                        .offset(add),
                    ),
                })
                .collect::<Option<Vec<_>>>()?;
            match values.len() {
                0 => None,
                1 => values.pop(),
                _ => Some(Arg::OneOf(values)),
            }
        }
    }
}

struct FunctionFacts<'ctx> {
    env: PointerValue<'ctx>,
    entry: BasicBlock<'ctx>,
    /// Env offset of the result register.
    ret: i64,
    sp: TempId,
    /// Loads of a register's env slot in the entry block before anything
    /// can have changed it: the register's value on entry.
    entry_loads: HashMap<InstructionValue<'ctx>, TempId>,
    preds: HashMap<BasicBlock<'ctx>, Vec<BasicBlock<'ctx>>>,
    /// The lowest frame address (entry stack pointer plus this) the
    /// function stores to memory or passes in an argument register:
    /// callees and stores through unknown pointers may write the frame
    /// from there up.
    escape: Option<i64>,
    /// Whether the escaping address was stored to guest memory (a global
    /// channel: any later callee might read it) rather than only passed in
    /// argument registers (only its callees can use it).
    escape_global: bool,
    /// Env offsets of the argument registers (what a call may receive).
    arg_homes: Vec<i64>,
    /// `reaching_slot` answers by load.
    slots: RefCell<HashMap<InstructionValue<'ctx>, Option<BasicValueEnum<'ctx>>>>,
    /// Nested `reaching_slot` depth through `slot_safe_across`/`symbolic`
    /// (which re-enter `search_slot`): bailed out past the limit below, so
    /// huge functions cannot grow the call stack without bound.
    nesting: std::cell::Cell<u32>,
    /// Env offset of the stack pointer.
    sp_home: i64,
    /// `CallSites::home`.
    home: (i64, i64),
    /// Target resolution requires reaching-store evidence. ABI-aware audit
    /// facts also retain the legacy word-load origin for taint provenance;
    /// that origin alone is not evidence of a concrete target value.
    prove_memory: bool,
}

impl<'ctx> FunctionFacts<'ctx> {
    /// `sp`: the stack pointer global and its env offset; `arg_homes`: env
    /// offsets of the argument registers.
    fn new(
        f: FunctionValue<'ctx>,
        homes: &HashMap<i64, TempId>,
        ret: i64,
        (sp, sp_home): (TempId, i64),
        arg_homes: &[i64],
        home: (i64, i64),
        prove_memory: bool,
    ) -> Self {
        let env = f.get_nth_param(0).unwrap().into_pointer_value();
        let entry = f.get_first_basic_block().unwrap();
        let mut facts = Self {
            env,
            entry,
            ret,
            sp,
            entry_loads: HashMap::new(),
            preds: HashMap::new(),
            // Until known, nothing is safe from calls.
            escape: Some(i64::MIN),
            escape_global: true,
            arg_homes: arg_homes.to_vec(),
            slots: RefCell::default(),
            nesting: std::cell::Cell::new(0),
            sp_home,
            home,
            prove_memory,
        };
        let mut written = HashSet::new();
        for i in entry.get_instructions() {
            match i.get_opcode() {
                InstructionOpcode::Call if !is_intrinsic(i) && !is_transparent_helper(i) => {
                    break;
                }
                InstructionOpcode::Store => {
                    if let Some(off) = facts.home_offset(i.get_operand(1)) {
                        written.insert(off);
                    }
                }
                InstructionOpcode::Load => {
                    if let Some(off) = facts.home_offset(i.get_operand(0))
                        && !written.contains(&off)
                        && let Some(&g) = homes.get(&off)
                    {
                        facts.entry_loads.insert(i, g);
                    }
                }
                _ => {}
            }
        }
        for bb in f.get_basic_blocks() {
            let Some(t) = bb.get_terminator() else {
                continue;
            };
            for k in 0..t.get_num_operands() {
                if let Some(s) = t.get_operand(k).and_then(|o| o.block()) {
                    facts.preds.entry(s).or_default().push(bb);
                }
            }
        }
        // Other registers (the stack and frame pointers, flags computed
        // from them, callee-saved ones) are no way to hand a callee a
        // pointer.
        let mut escape = None;
        let mut escape_global = false;
        for bb in f.get_basic_blocks() {
            for i in bb.get_instructions() {
                if i.get_opcode() != InstructionOpcode::Store {
                    continue;
                }
                let dest = facts.home_offset(i.get_operand(1));
                // Only two channels hand a frame address out: guest memory
                // (any callee may read it back) and argument registers
                // (their callees receive it). Other env homes (spilled
                // registers, the stack pointer write-back) are internal.
                if dest.is_some_and(|h| !arg_homes.contains(&h)) {
                    continue;
                }
                let global = dest.is_none();
                if let Some(v) = i.get_operand(0).and_then(|o| o.value())
                    && let Some(Sym::Reg(r, e)) = facts.symbolic(v)
                    && r == sp
                {
                    escape = Some(escape.map_or(e, |m: i64| m.min(e)));
                    escape_global = escape_global || global;
                }
            }
        }
        facts.escape = escape;
        facts.escape_global = escape_global;
        // Answers given while nothing was safe from calls.
        facts.slots.get_mut().clear();
        facts
    }

    /// Offset into env of a pointer `env` or `getelementptr i8, env, C`.
    fn home_offset(&self, op: Option<inkwell::values::Operand<'ctx>>) -> Option<i64> {
        let v = op?.value()?;
        if v.as_value_ref() == self.env.as_value_ref() {
            return Some(0);
        }
        let gep = v.as_instruction_value()?;
        if gep.get_opcode() != InstructionOpcode::GetElementPtr
            || gep.get_num_operands() != 2
            || !is_i8(gep.get_gep_source_element_type().ok()?)
        {
            return None;
        }
        let base = gep.get_operand(0)?.value()?;
        if base.as_value_ref() != self.env.as_value_ref() {
            return None;
        }
        let off = gep.get_operand(1)?.value()?.into_int_value();
        off.get_sign_extended_constant()
    }

    /// The last definition of env slot `off` before `at`. A control-flow
    /// join retains provenance only when all incoming paths agree.
    fn reaching_store(&self, at: InstructionValue<'ctx>, off: i64) -> Reaching<'ctx> {
        let mut bb = at.get_parent().unwrap();
        let mut cur = at.get_previous_instruction();
        let mut seen = HashSet::new();
        let mut pending = Vec::new();
        let mut result = None;
        let mut walked = 0;
        loop {
            let mut found = None;
            while let Some(i) = cur {
                walked += 1;
                if walked > MAX_SLOT_WALK {
                    return Reaching::Unknown;
                }
                match i.get_opcode() {
                    InstructionOpcode::Store if self.home_offset(i.get_operand(1)) == Some(off) => {
                        found = Some(match i.get_operand(0).and_then(|o| o.value()) {
                            Some(v) => Reaching::Stored(v),
                            None => Reaching::Unknown,
                        });
                        break;
                    }
                    InstructionOpcode::Call if !is_intrinsic(i) && !is_transparent_helper(i) => {
                        found = Some(Reaching::Call(i));
                        break;
                    }
                    _ => {}
                }
                cur = i.get_previous_instruction();
            }
            let mut next = None;
            if found.is_none() {
                if bb == self.entry {
                    found = Some(Reaching::Entry);
                } else if let Some(preds) = self.preds.get(&bb).filter(|p| !p.is_empty()) {
                    for &p in preds {
                        if seen.insert(p)
                            && let Some(previous) = next.replace(p)
                        {
                            pending.push(previous);
                        }
                    }
                } else {
                    found = Some(Reaching::Unknown);
                }
            }
            if let Some(value) = found {
                if value == Reaching::Unknown || result.is_some_and(|old| old != value) {
                    return Reaching::Unknown;
                }
                result = Some(value);
            }
            match next.or_else(|| pending.pop()) {
                Some(p) => {
                    bb = p;
                    cur = p.get_last_instruction();
                }
                None => return result.unwrap_or(Reaching::Unknown),
            }
        }
    }

    /// `ptr` as the entry stack pointer plus a constant, by arithmetic
    /// alone (an address loaded from memory is not followed).
    fn frame_offset(&self, ptr: BasicValueEnum<'ctx>, depth: u32) -> Option<i64> {
        if depth > 16 {
            return None;
        }
        let inst = ptr.as_instruction_value()?;
        let operand = |k: u32| inst.get_operand(k).and_then(|o| o.value());
        let constant = |k: u32| match operand(k)? {
            BasicValueEnum::IntValue(c) if c.is_const() => c.get_sign_extended_constant(),
            _ => None,
        };
        let at = |k: u32| self.frame_offset(operand(k)?, depth + 1);
        let same = |vals: &mut dyn Iterator<Item = Option<BasicValueEnum<'ctx>>>| {
            let mut out = None;
            for v in vals {
                let o = self.frame_offset(v?, depth + 1)?;
                if out.is_some_and(|x| x != o) {
                    return None;
                }
                out = Some(o);
            }
            out
        };
        match inst.get_opcode() {
            InstructionOpcode::Load => (self.entry_loads.get(&inst) == Some(&self.sp)).then_some(0),
            InstructionOpcode::Add => match (constant(0), constant(1)) {
                (_, Some(c)) => at(0).map(|o| o.wrapping_add(c)),
                (Some(c), _) => at(1).map(|o| o.wrapping_add(c)),
                _ => None,
            },
            InstructionOpcode::Sub => Some(at(0)?.wrapping_sub(constant(1)?)),
            InstructionOpcode::IntToPtr | InstructionOpcode::PtrToInt => at(0),
            InstructionOpcode::GetElementPtr
                if inst.get_num_operands() == 2
                    && inst.get_gep_source_element_type().is_ok_and(is_i8) =>
            {
                Some(at(0)?.wrapping_add(constant(1)?))
            }
            InstructionOpcode::Select => same(&mut [operand(1), operand(2)].into_iter()),
            InstructionOpcode::Phi => {
                let phi = PhiValue::try_from(inst).ok()?;
                same(&mut (0..phi.count_incoming()).map(|k| phi.get_incoming(k).map(|(v, _)| v)))
            }
            _ => None,
        }
    }

    /// Whether the call `i` leaves the frame slot `[off, end)` alone: the
    /// slot lies at or above the stack pointer at the call (a callee's own
    /// frame is below it), no argument aliases the slot, and no frame
    /// address leaked to guest memory (which any callee could read back).
    fn slot_safe_across(&self, i: InstructionValue<'ctx>, off: i64, end: i64) -> bool {
        if self.escape_global {
            return false;
        }
        // Stack pointer at the call, as an entry-relative offset.
        let Reaching::Stored(sp) = self.reaching_store(i, self.sp_home) else {
            return false;
        };
        let Some(k) = self.frame_offset(sp, 0) else {
            return false;
        };
        if off < k {
            return false;
        }
        // No argument may alias the slot.
        for &h in &self.arg_homes {
            let Reaching::Stored(v) = self.reaching_store(i, h) else {
                continue;
            };
            if let Some(Sym::Reg(r, e)) = self.symbolic(v)
                && r == self.sp
                && e < end
                && off < e + 8
            {
                return false;
            }
        }
        true
    }

    fn reaching_slot(
        &self,
        at: InstructionValue<'ctx>,
        off: i64,
        bits: u32,
    ) -> Option<BasicValueEnum<'ctx>> {
        if let Some(&known) = self.slots.borrow().get(&at) {
            return known;
        }
        // `slot_safe_across` re-enters here through `symbolic`: cap the
        // nesting so pathological functions cannot exhaust the stack, and
        // answer conservatively inside (the caller then treats the slot as
        // clobbered).
        if self.nesting.get() >= 4 {
            return None;
        }
        self.nesting.set(self.nesting.get() + 1);
        let found = self.search_slot(at, off, bits);
        self.nesting.set(self.nesting.get() - 1);
        self.slots.borrow_mut().insert(at, found);
        found
    }

    fn search_slot(
        &self,
        at: InstructionValue<'ctx>,
        off: i64,
        bits: u32,
    ) -> Option<BasicValueEnum<'ctx>> {
        let end = off + i64::from(bits / 8);
        let safe = self.escape.is_none_or(|e| end <= e);
        let mut found: Option<InstructionValue> = None;
        let mut work = vec![(at.get_parent()?, at.get_previous_instruction())];
        let mut seen = HashSet::new();
        let mut budget = MAX_SLOT_WALK;
        'paths: while let Some((bb, mut cur)) = work.pop() {
            while let Some(i) = cur {
                budget = budget.checked_sub(1)?;
                match i.get_opcode() {
                    InstructionOpcode::Store if self.home_offset(i.get_operand(1)).is_none() => {
                        if i.get_volatile().unwrap_or(true)
                            || i.get_atomic_ordering().ok()
                                != Some(inkwell::AtomicOrdering::NotAtomic)
                        {
                            return None;
                        }
                        let width = match i.get_operand(0)?.value()? {
                            BasicValueEnum::IntValue(v) => v.get_type().get_bit_width(),
                            _ => return None,
                        };
                        match self.frame_offset(i.get_operand(1)?.value()?, 0) {
                            Some(o) if o == off && width == bits => {
                                if found.is_some_and(|f| f != i) {
                                    return None;
                                }
                                found = Some(i);
                                continue 'paths;
                            }
                            Some(o) if o < end && off < o + i64::from(width / 8) => return None,
                            Some(_) => {}
                            None if !safe => return None,
                            None => {}
                        }
                    }
                    InstructionOpcode::AtomicRMW
                    | InstructionOpcode::AtomicCmpXchg
                    | InstructionOpcode::Fence => return None,
                    InstructionOpcode::Call
                        if !is_intrinsic(i) && !is_transparent_helper(i) && !safe =>
                    {
                        // The callee can only write the slot through its own
                        // frame (below the stack pointer at the call) or an
                        // argument aliasing it; anything leaked to globals
                        // vetoes.
                        if !self.slot_safe_across(i, off, end) {
                            return None;
                        }
                    }
                    // An x87 store helper (`fstt_ST0`, ...): a guest store of
                    // known width to its address operand, handled exactly
                    // like one. (Transparent helpers never reach this arm.)
                    InstructionOpcode::Call if self.fp_store(i).is_some() => {
                        // The value written is x87 state (untracked): any
                        // overlap kills the slot, like an unknown store.
                        let (addr, width) = self.fp_store(i).unwrap();
                        match self.frame_offset(addr, 0) {
                            Some(o) if o < end && off < o + i64::from(width / 8) => return None,
                            Some(_) => {}
                            None if !safe => return None,
                            None => {}
                        }
                    }
                    InstructionOpcode::Call if !is_intrinsic(i) && self.home.1 > 0 => {
                        // The callee's home space, if it covers the slot.
                        let Reaching::Stored(sp) = self.reaching_store(i, self.sp_home) else {
                            return None;
                        };
                        let start = self.frame_offset(sp, 0)? + self.home.0;
                        if start < end && off < start + self.home.1 {
                            return None;
                        }
                    }
                    // memcpy, memset: wherever they write.
                    InstructionOpcode::Call if is_memory_intrinsic(i) => return None,
                    _ => {}
                }
                cur = i.get_previous_instruction();
            }
            // From before the function.
            if bb == self.entry {
                return None;
            }
            for &p in self.preds.get(&bb)? {
                if seen.insert(p) {
                    work.push((p, p.get_last_instruction()));
                }
            }
        }
        found?.get_operand(0)?.value()
    }

    /// An x87 store helper's (guest address operand, width in bits), if
    /// `i` calls one (`HelperFootprint::FpStore`).
    fn fp_store(&self, i: InstructionValue<'ctx>) -> Option<(BasicValueEnum<'ctx>, u32)> {
        let called = inkwell::values::CallSiteValue::try_from(i)
            .ok()?
            .get_called_fn_value()?;
        let name = called.get_name().to_str().ok()?;
        let (addr, width) = match biara_tcg::helper_footprint(name.strip_prefix("helper_")?) {
            Some(biara_tcg::HelperFootprint::FpStore { addr, width }) => (addr, width),
            _ => return None,
        };
        let v = i.get_operand(addr as u32)?.value()?;
        // The operand is the guest address as an integer.
        let bits = match v {
            BasicValueEnum::IntValue(_) => (width * 8) as u32,
            _ => return None,
        };
        Some((v, bits))
    }

    fn address(&self, pointer: BasicValueEnum<'ctx>) -> Option<Address> {
        match self.symbolic(pointer)? {
            Sym::Reg(reg, off) => Some(Address { reg, off }),
            _ => None,
        }
    }

    fn argument(
        &self,
        value: BasicValueEnum<'ctx>,
        info: &ContextInfo,
        returned: &impl Fn(InstructionValue<'ctx>) -> Option<Arg>,
    ) -> Arg {
        self.argument_at(value, info, returned, 0, &mut 128)
    }

    fn argument_at(
        &self,
        value: BasicValueEnum<'ctx>,
        info: &ContextInfo,
        returned: &impl Fn(InstructionValue<'ctx>) -> Option<Arg>,
        depth: usize,
        budget: &mut usize,
    ) -> Arg {
        if depth >= 32 || *budget == 0 {
            return Arg::Unknown;
        }
        *budget -= 1;
        let bits = match value {
            BasicValueEnum::IntValue(v) => v.get_type().get_bit_width(),
            BasicValueEnum::PointerValue(_) => 64,
            _ => return Arg::Unknown,
        };
        if !(1..=64).contains(&bits) {
            return Arg::Unknown;
        }
        if let BasicValueEnum::IntValue(v) = value
            && let Some(c) = v.get_zero_extended_constant()
        {
            return Arg::Const(c);
        }
        let Some(inst) = value.as_instruction_value() else {
            return Arg::Unknown;
        };
        let operand = |k| inst.get_operand(k).and_then(|o| o.value());
        if inst.get_opcode() == InstructionOpcode::Load {
            if inst.get_volatile().unwrap_or(true)
                || inst.get_atomic_ordering().ok() != Some(inkwell::AtomicOrdering::NotAtomic)
            {
                return Arg::Unknown;
            }
            if let Some(&g) = self.entry_loads.get(&inst) {
                return if g == self.sp {
                    Arg::Stack(0)
                } else {
                    Arg::Incoming(name(info, g))
                };
            }
            if let Some(home) = self.home_offset(inst.get_operand(0)) {
                return match self.reaching_store(inst, home) {
                    Reaching::Stored(v) => self.argument_at(v, info, returned, depth + 1, budget),
                    Reaching::Call(call) if home == self.ret => {
                        returned(call).unwrap_or(Arg::Unknown)
                    }
                    Reaching::Call(call) => info
                        .globals
                        .iter()
                        .find(|g| g.kind == TempKind::Global && g.mem_offset == home)
                        .and_then(|g| g.name.as_deref())
                        .map_or(Arg::Unknown, |reg| {
                            register_result(returned(call), reg.to_owned())
                        }),
                    _ => Arg::Unknown,
                };
            }
            if !self.prove_memory
                && bits == 64
                && let Some(origin) = self
                    .symbolic(value)
                    .and_then(|sym| symbolic_arg(sym, info, self.sp, returned))
            {
                return origin;
            }
            let Some(pointer) = operand(0) else {
                return Arg::Unknown;
            };
            if let Some(address) = self.address(pointer) {
                // Caller-local spills use the existing escape/stack-boundary
                // proof. Foreign frames instead require an uninterrupted
                // memory-effect chain.
                if address.reg == self.sp
                    && let Some(value) = self.reaching_slot(inst, address.off, bits)
                {
                    return self.argument_at(value, info, returned, depth + 1, budget);
                }
                let source = call_memory::read_ir(
                    inst,
                    (address, bits),
                    self.entry,
                    &self.preds,
                    |v| self.address(v),
                    |op| self.home_offset(op).is_some(),
                    memory_barrier,
                );
                return match source {
                    Read::Value {
                        value,
                        bits: stored,
                        shift,
                    } => extract_word(
                        self.argument_at(value, info, returned, depth + 1, budget),
                        stored,
                        shift,
                        bits,
                    ),
                    Read::Entry => {
                        let reg = name(info, address.reg);
                        if address.reg == self.sp {
                            Arg::Load {
                                base: Box::new(Arg::Stack(0)),
                                off: address.off,
                                bits,
                            }
                        } else if bits == 64 {
                            Arg::Deref {
                                reg,
                                off: address.off,
                            }
                        } else {
                            Arg::Load {
                                base: Box::new(Arg::Incoming(reg)),
                                off: address.off,
                                bits,
                            }
                        }
                    }
                    Read::Unknown => Arg::Unknown,
                };
            }
            let base = self.argument_at(pointer, info, returned, depth + 1, budget);
            return match base {
                Arg::Const(_) => Arg::Load {
                    base: Box::new(base),
                    off: 0,
                    bits,
                },
                _ => Arg::Unknown,
            };
        }
        // Retain the existing pointer-origin form for full-width offsets.
        if bits == 64
            && matches!(
                inst.get_opcode(),
                InstructionOpcode::Add | InstructionOpcode::Sub | InstructionOpcode::GetElementPtr
            )
            && let Some(arg) = self
                .symbolic(value)
                .filter(|s| matches!(s, Sym::Reg(..)))
                .and_then(|s| symbolic_arg(s, info, self.sp, returned))
        {
            return arg;
        }
        let op = match inst.get_opcode() {
            InstructionOpcode::Add => Some(IntOp::Add),
            InstructionOpcode::Sub => Some(IntOp::Sub),
            InstructionOpcode::Mul => Some(IntOp::Mul),
            InstructionOpcode::And => Some(IntOp::And),
            InstructionOpcode::Or => Some(IntOp::Or),
            InstructionOpcode::Xor => Some(IntOp::Xor),
            InstructionOpcode::Shl => Some(IntOp::Shl),
            InstructionOpcode::LShr => Some(IntOp::LShr),
            InstructionOpcode::AShr => Some(IntOp::AShr),
            InstructionOpcode::Trunc => Some(IntOp::Trunc),
            InstructionOpcode::ZExt | InstructionOpcode::SExt => {
                let from = operand(0).and_then(|v| match v {
                    BasicValueEnum::IntValue(v) => Some(v.get_type().get_bit_width()),
                    _ => None,
                });
                from.map(|from| {
                    if inst.get_opcode() == InstructionOpcode::ZExt {
                        IntOp::ZExt { from }
                    } else {
                        IntOp::SExt { from }
                    }
                })
            }
            InstructionOpcode::Call => CallSiteValue::try_from(inst)
                .ok()
                .and_then(|call| call.get_called_fn_value())
                .and_then(|f| {
                    let n = f.get_name().to_bytes();
                    if n.starts_with(b"llvm.fshl.") {
                        Some(IntOp::Fshl)
                    } else if n.starts_with(b"llvm.fshr.") {
                        Some(IntOp::Fshr)
                    } else {
                        None
                    }
                }),
            InstructionOpcode::IntToPtr
            | InstructionOpcode::PtrToInt
            | InstructionOpcode::BitCast => {
                return operand(0).map_or(Arg::Unknown, |v| {
                    self.argument_at(v, info, returned, depth + 1, budget)
                });
            }
            InstructionOpcode::GetElementPtr
                if inst.get_num_operands() == 2
                    && inst.get_gep_source_element_type().is_ok_and(is_i8) =>
            {
                Some(IntOp::Add)
            }
            InstructionOpcode::Select | InstructionOpcode::Phi => {
                let inputs: Vec<_> = if inst.get_opcode() == InstructionOpcode::Select {
                    [operand(1), operand(2)].into_iter().flatten().collect()
                } else if let Ok(phi) = PhiValue::try_from(inst) {
                    (0..phi.count_incoming())
                        .filter_map(|i| phi.get_incoming(i).map(|(v, _)| v))
                        .collect()
                } else {
                    return Arg::Unknown;
                };
                if inputs.len() > MAX_ALTERNATIVES {
                    return Arg::Unknown;
                }
                let mut values = Vec::new();
                for input in inputs {
                    let arg = self.argument_at(input, info, returned, depth + 1, budget);
                    if matches!(arg, Arg::Unknown) {
                        return arg;
                    }
                    if !values.contains(&arg) {
                        values.push(arg);
                    }
                }
                return match values.len() {
                    0 => Arg::Unknown,
                    1 => values.pop().unwrap(),
                    _ => Arg::OneOf(values),
                };
            }
            _ => None,
        };
        let Some(op) = op else { return Arg::Unknown };
        let mut args = Vec::with_capacity(op.arity());
        for k in 0..op.arity() {
            let Some(v) = operand(k as u32) else {
                return Arg::Unknown;
            };
            let arg = self.argument_at(v, info, returned, depth + 1, budget);
            if matches!(arg, Arg::Unknown) {
                return arg;
            }
            args.push(arg);
        }
        Arg::expression(op, bits, args)
    }

    fn symbolic(&self, v: BasicValueEnum<'ctx>) -> Option<Sym<'ctx>> {
        self.symbolic_at(v, 0)
    }

    fn symbolic_at(&self, v: BasicValueEnum<'ctx>, depth: u32) -> Option<Sym<'ctx>> {
        if depth > 16 {
            return None;
        }
        if let BasicValueEnum::IntValue(iv) = v
            && iv.is_const()
        {
            return iv
                .get_zero_extended_constant()
                .map(|c| Sym::OneOf(vec![Leaf::Const(c)]));
        }
        let inst = v.as_instruction_value()?;
        let operand = |k: u32| inst.get_operand(k).and_then(|o| o.value());
        let constant = |k: u32| {
            operand(k).and_then(|o| match o {
                BasicValueEnum::IntValue(c) if c.is_const() => c.get_sign_extended_constant(),
                _ => None,
            })
        };
        let plus = |s: Sym<'ctx>, c: i64| match s {
            Sym::OneOf(ls) => ls
                .into_iter()
                .map(|l| match l {
                    Leaf::Const(x) => Some(Leaf::Const(x.wrapping_add(c as u64))),
                    Leaf::Returned(call, off) => Some(Leaf::Returned(call, off.wrapping_add(c))),
                    Leaf::Loaded(reg, off, add) => {
                        Some(Leaf::Loaded(reg, off, add.wrapping_add(c)))
                    }
                })
                .collect::<Option<_>>()
                .map(Sym::OneOf),
            Sym::Reg(r, o) => Some(Sym::Reg(r, o.wrapping_add(c))),
        };
        // A select or phi of alternatives.
        let one_of = |vals: Vec<BasicValueEnum<'ctx>>| {
            let mut out: Vec<Leaf> = Vec::new();
            for v in vals {
                let Sym::OneOf(ls) = self.symbolic_at(v, depth + 1)? else {
                    return None;
                };
                for l in ls {
                    if !out.contains(&l) {
                        out.push(l);
                    }
                }
            }
            (out.len() <= MAX_ALTERNATIVES).then_some(Sym::OneOf(out))
        };
        match inst.get_opcode() {
            InstructionOpcode::Load => {
                if let Some(&g) = self.entry_loads.get(&inst) {
                    return Some(Sym::Reg(g, 0));
                }
                // The result register, reloaded after a call.
                if self.home_offset(inst.get_operand(0)) == Some(self.ret) {
                    return match self.reaching_store(inst, self.ret) {
                        Reaching::Call(c) => Some(Sym::OneOf(vec![Leaf::Returned(c, 0)])),
                        _ => None,
                    };
                }
                let bits = match inst.get_type() {
                    inkwell::types::AnyTypeEnum::IntType(t) => t.get_bit_width(),
                    _ => return None,
                };
                // A slot of the frame: what was stored there.
                // (Above the entry stack pointer: the caller's frame.)
                if let Some(o) = self.frame_offset(operand(0)?, 0) {
                    let v = (o < 0).then(|| self.reaching_slot(inst, o, bits))??;
                    return self.symbolic_at(v, depth + 1);
                }
                // A word of guest memory at an entry register plus an
                // offset.
                match self.symbolic_at(operand(0)?, depth + 1)? {
                    Sym::Reg(r, o) if bits == 64 && r != self.sp => {
                        Some(Sym::OneOf(vec![Leaf::Loaded(r, o, 0)]))
                    }
                    _ => None,
                }
            }
            InstructionOpcode::Add => match (constant(0), constant(1)) {
                (_, Some(c)) => plus(self.symbolic_at(operand(0)?, depth + 1)?, c),
                (Some(c), _) => plus(self.symbolic_at(operand(1)?, depth + 1)?, c),
                _ => None,
            },
            InstructionOpcode::Sub => {
                let c = constant(1)?;
                plus(self.symbolic_at(operand(0)?, depth + 1)?, c.wrapping_neg())
            }
            InstructionOpcode::Select => one_of(vec![operand(1)?, operand(2)?]),
            InstructionOpcode::Phi => {
                let phi = PhiValue::try_from(inst).ok()?;
                let vals = (0..phi.count_incoming())
                    .map(|k| phi.get_incoming(k).map(|(v, _)| v))
                    .collect::<Option<Vec<_>>>()?;
                one_of(vals)
            }
            InstructionOpcode::IntToPtr | InstructionOpcode::PtrToInt => {
                self.symbolic_at(operand(0)?, depth + 1)
            }
            InstructionOpcode::GetElementPtr
                if inst.get_num_operands() == 2
                    && inst.get_gep_source_element_type().is_ok_and(is_i8) =>
            {
                plus(self.symbolic_at(operand(0)?, depth + 1)?, constant(1)?)
            }
            _ => None,
        }
    }
}

fn is_i8(t: BasicTypeEnum) -> bool {
    matches!(t, BasicTypeEnum::IntType(i) if i.get_bit_width() == 8)
}

fn memory_barrier(inst: InstructionValue) -> bool {
    match inst.get_opcode() {
        InstructionOpcode::AtomicRMW
        | InstructionOpcode::AtomicCmpXchg
        | InstructionOpcode::Fence => true,
        InstructionOpcode::Call => {
            if is_memory_intrinsic(inst) {
                return true;
            }
            if is_intrinsic(inst) {
                return false;
            }
            !CallSiteValue::try_from(inst)
                .ok()
                .and_then(|c| c.get_called_fn_value())
                .is_some_and(|f| {
                    let n = f.get_name().to_bytes();
                    n == RETURN_MARKER.as_bytes()
                        || n == crate::tables::MARKER.as_bytes()
                        || f.get_enum_attribute(
                            AttributeLoc::Function,
                            Attribute::get_named_enum_kind_id("memory"),
                        )
                        .is_some_and(|attr| attr.get_enum_value() & 0b10_10_10 == 0)
                        || f.get_name()
                            .to_str()
                            .ok()
                            .and_then(|n| n.strip_prefix("helper_"))
                            .and_then(biara_tcg::helper_footprint)
                            .is_some_and(|effect| {
                                matches!(
                                    effect,
                                    biara_tcg::HelperFootprint::FpStack
                                        | biara_tcg::HelperFootprint::FpLoad
                                )
                            })
                })
        }
        _ => false,
    }
}

fn is_intrinsic(call: InstructionValue) -> bool {
    CallSiteValue::try_from(call)
        .ok()
        .and_then(|c| c.get_called_fn_value())
        .is_some_and(|f| f.get_name().to_bytes().starts_with(b"llvm."))
}

/// Register homes survive readonly helpers and helpers whose explicit
/// footprint preserves globals. Guest-memory writes have a separate barrier.
fn is_transparent_helper(call: InstructionValue) -> bool {
    CallSiteValue::try_from(call)
        .ok()
        .and_then(|c| c.get_called_fn_value())
        .is_some_and(|f| {
            f.get_name().to_str().ok().is_some_and(|n| {
                n == crate::tables::MARKER
                    || n == RETURN_MARKER
                    || n.strip_prefix("helper_")
                        .is_some_and(biara_tcg::preserves_globals)
            }) || f
                .get_enum_attribute(
                    AttributeLoc::Function,
                    Attribute::get_named_enum_kind_id("memory"),
                )
                .is_some_and(|attr| attr.get_enum_value() & 0b10_10_10 == 0)
        })
}

fn is_memory_intrinsic(call: InstructionValue) -> bool {
    CallSiteValue::try_from(call)
        .ok()
        .and_then(|c| c.get_called_fn_value())
        .is_some_and(|f| {
            let name = f.get_name().to_bytes();
            [&b"llvm.memcpy"[..], b"llvm.memmove", b"llvm.memset"]
                .iter()
                .any(|p| name.starts_with(p))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summaries<'a>(
        machine: &'a TargetMachine,
        info: &'a ContextInfo,
        cfg: &'a Cfg,
    ) -> CallSites<'a> {
        CallSites {
            machine,
            info,
            cfg,
            abis: None,
            sp: 0,
            homes: HashMap::new(),
            ret: 0,
            args: Vec::new(),
            home: (0, 0),
            lifted: BTreeSet::new(),
            sites: Vec::new(),
            returns: BTreeMap::new(),
            by_pc: BTreeMap::new(),
            memory: BTreeMap::new(),
            register_returns: BTreeMap::new(),
            resolution_limited: Cell::new(false),
        }
    }

    fn empty_info() -> ContextInfo {
        ContextInfo {
            arch: "x86_64".into(),
            cpu_model: "max".into(),
            guest_bits: 64,
            globals: Vec::new().into(),
            pc_global: 0,
            env_global: 0,
            insn_start_words: 1,
            env_size: 0,
        }
    }

    #[test]
    fn cyclic_return_bindings_preserve_known_arms_without_expanding_the_cycle() {
        let machine = crate::analysis_machine().unwrap();
        let info = empty_info();
        let cfg = Cfg::default();
        let mut sites = summaries(&machine, &info, &cfg);
        let result = Arg::FunctionResult {
            function: 2,
            pc: 10,
        };
        sites.sites.push(CallSite {
            caller: 1,
            pc: 10,
            callee: Callee::Function(2),
            args: Vec::new(),
            registers: BTreeMap::from([(
                "rdi".into(),
                Arg::OneOf(vec![Arg::Const(7), result.clone()]),
            )]),
        });
        sites.by_pc.insert((10, 1), 0..1);
        sites.returns.insert(2, Arg::Incoming("rdi".into()));
        assert_eq!(
            sites.resolve_arg(&result, 1),
            Arg::OneOf(vec![Arg::Const(7), Arg::Unknown])
        );
    }

    #[test]
    fn branching_return_summaries_share_a_budget_and_keep_small_queries_precise() {
        let machine = crate::analysis_machine().unwrap();
        let info = empty_info();
        let cfg = Cfg::default();
        let mut sites = summaries(&machine, &info, &cfg);
        for caller in 1..=10 {
            let pc = caller * 100;
            let child = Arg::FunctionResult {
                function: caller + 1,
                pc,
            };
            sites
                .by_pc
                .insert((pc, caller), sites.sites.len()..sites.sites.len() + 1);
            sites.sites.push(CallSite {
                caller,
                pc,
                callee: Callee::Function(caller + 1),
                args: Vec::new(),
                registers: BTreeMap::new(),
            });
            sites.returns.insert(
                caller,
                Arg::expression(IntOp::Add, 64, vec![child.clone(), child]),
            );
        }
        sites.returns.insert(11, Arg::Const(3));
        assert_eq!(
            sites.resolve_arg(
                &Arg::FunctionResult {
                    function: 2,
                    pc: 100
                },
                1
            ),
            Arg::Unknown
        );
        assert!(sites.analysis_limited());
        assert_eq!(
            sites.resolve_arg(
                &Arg::FunctionResult {
                    function: 11,
                    pc: 1000
                },
                10
            ),
            Arg::Const(3)
        );
    }

    #[test]
    fn foreign_load_requires_a_nonwriting_call() {
        let cx = Context::create();
        let module = cx.create_module("memory-effects");
        let builder = cx.create_builder();
        let pointer_type = cx.ptr_type(inkwell::AddressSpace::default());
        let function = module.add_function(
            "fragment",
            cx.void_type().fn_type(&[pointer_type.into()], false),
            None,
        );
        let peer = module.add_function("peer", cx.void_type().fn_type(&[], false), None);
        let entry = cx.append_basic_block(function, "entry");
        builder.position_at_end(entry);
        let pointer = function.get_first_param().unwrap().into_pointer_value();
        let value = cx.i64_type().const_int(0x1122334455667788, false);
        builder.build_store(pointer, value).unwrap();
        builder.build_call(peer, &[], "").unwrap();
        let loaded = builder.build_load(cx.i64_type(), pointer, "").unwrap();
        builder.build_return(None).unwrap();
        let query = Address { reg: 7, off: 0 };
        let read = || {
            call_memory::read_ir(
                loaded.as_instruction_value().unwrap(),
                (query, 64),
                entry,
                &HashMap::new(),
                |v| (v == pointer).then_some(query),
                |_| false,
                memory_barrier,
            )
        };
        assert_eq!(read(), Read::Unknown);

        peer.add_attribute(
            AttributeLoc::Function,
            cx.create_enum_attribute(Attribute::get_named_enum_kind_id("memory"), 0b01_01_01),
        );
        assert_eq!(
            read(),
            Read::Value {
                value: value.into(),
                bits: 64,
                shift: 0
            }
        );
    }
}
