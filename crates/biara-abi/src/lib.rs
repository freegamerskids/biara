//! Stack-frame and calling-convention recovery.
//!
//! Each function's TCG is evaluated symbolically over its CFG, from a state
//! in which every register holds its *entry value*. Values are constants,
//! entry values plus an offset (`sp - 16`, `rdi + 8`), values a callee left
//! in a register, or unknown. Stack memory at known offsets from the entry
//! stack pointer is tracked as well, so a register pushed in the prologue
//! and popped in the epilogue still holds its entry value.
//!
//! From that:
//! - frame: the stack pointer at each block entry, the slots accessed, the
//!   frame size, and whether every return leaves the stack balanced;
//! - arguments: registers whose entry value is *used* (computed with,
//!   dereferenced, branched on, passed to a callee that uses it, returned
//!   to a caller that uses it) - merely saving and restoring is not a use;
//!   stack arguments are slots above the return address read before
//!   written; registers handed on untouched to unknown code count when
//!   every caller sets them;
//! - return values: registers a caller uses after the call while they
//!   still hold what the callee left there;
//! - preserved registers: those holding their entry value at every return.
//!
//! Callees feed callers (arguments, preserved registers) and callers feed
//! callees (return values), so all functions are analysed in rounds until
//! nothing changes. Code that cannot be analysed (imports, indirect calls,
//! system calls, some helpers) follows `biara_cfg::ArchSpec`.
//! Only functions whose own or callee facts changed are reevaluated. Workers
//! read the previous round's immutable facts; caller/callee contributions are
//! merged deterministically before the next dependency round.
//!
//! Assumption: a callee never writes the caller's register save slots
//! (stack slots holding a register's entry value), even when it receives a
//! pointer into the caller's frame.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use biara_cfg::{ArchSpec, BasicBlock, Cfg, ExitKind, Function, RegSet, ReturnConvention};
use biara_tcg::{Block, ContextInfo, MemOp, Op, Opcode, TempId, TempKind, Type, call_flags};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Cfg(#[from] biara_cfg::Error),
    #[error("{arch}: context lacks global {name}")]
    Global { arch: String, name: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Frame {
    /// Stack pointer at each block entry, relative to its value at function
    /// entry; `None` where it is not statically known (including joins with
    /// incompatible offsets, stack realignment, and dynamic allocation).
    pub sp_at: BTreeMap<u64, Option<i64>>,
    /// Stack accesses by offset from the entry stack pointer: widest access
    /// in bytes.
    pub slots: BTreeMap<i64, u32>,
    /// Bytes of stack below the entry stack pointer the function uses.
    pub size: u64,
    /// Every return restores the entry stack pointer (after popping the
    /// return address where the architecture pushes one).
    pub balanced: bool,
}

/// Whole-program fixpoint status. Unconverged ABI facts are provisional:
/// consumers must not rely on their preservation or frame-balance claims.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AbiStatus {
    pub converged: bool,
    pub rounds: usize,
}

/// Observed scalar/vector type of one FP/vector state lane.
///
/// Recorded only from evidence: a scalar FP helper naming the lane width
/// (`float` vs `double`), or whole-lane vector traffic. Bit-pattern integer
/// traffic through the same state records nothing here, and conflicting
/// widths across paths remove the lane from the type maps into
/// [`FunctionAbi::fp_conflicts`]. The summary consumer selects signature
/// types from exactly these entries: no default-double guessing.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum LaneType {
    /// 4-byte lane use established by `float` evidence.
    Float32,
    /// 8-byte lane use established by `double` evidence.
    Float64,
    /// Whole 16-byte lane traffic established by vector evidence.
    Vector128,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FunctionAbi {
    pub frame: Frame,
    /// Registers whose entry value is used; stack pointer and pc excluded.
    pub args: BTreeSet<TempId>,
    /// Stack arguments: offsets from the entry stack pointer, at or above
    /// the first argument slot, read before written.
    pub stack_args: BTreeSet<i64>,
    /// Registers consumed by callers, or the first GPR result of an uncalled
    /// root without established FP return evidence. Result dependencies are
    /// included before argument facts are finalized, even in bounded analysis.
    pub returns: BTreeSet<TempId>,
    /// Registers holding their entry value at every return (stack pointer
    /// and pc excluded; see `Frame::balanced`). Trust only when
    /// `analysis.converged`; subject to the caller-save-slot assumption above.
    pub preserved: BTreeSet<TempId>,
    /// FP/vector state lanes whose entry value is used, by lane index into
    /// the convention's `fp_args` order. A lane counts only when float or
    /// vector evidence establishes it: a scalar FP helper naming the lane
    /// (noncommutative double operations distinguish operand order), a
    /// float/vector-indexed lane access, or a whole-lane vector move. Plain
    /// integer bit-pattern traffic through the same state never counts.
    /// The observed type per lane lives in `fp_arg_types`; lanes absent
    /// there have no established type and stay raw words.
    pub fp_args: BTreeSet<u32>,
    /// Observed type per FP/vector argument lane (lane index into the
    /// convention's `fp_args` order): `Float32` (4-byte lane use), `Float64`
    /// (8-byte lane use) or `Vector128` (whole 16-byte lane traffic). A
    /// lane with conflicting widths across paths is removed here and added
    /// to `fp_conflicts` instead; consumers must keep the raw word there.
    /// Never a default `Float64` guess: only recorded evidence appears.
    pub fp_arg_types: BTreeMap<u32, LaneType>,
    /// FP/vector result lanes consumed by callers, or an established first
    /// result lane of an uncalled root. Same evidence rule as `fp_args`;
    /// types live in `fp_ret_types`.
    pub fp_returns: BTreeSet<u32>,
    /// Observed type per FP/vector result lane, same encoding as
    /// `fp_arg_types`. Conflicting widths become `fp_conflicts` instead.
    pub fp_ret_types: BTreeMap<u32, LaneType>,
    /// FP/vector lanes with conflicting evidence (float on one path, raw
    /// bits or a different width on another): consumers must keep the raw
    /// word signature there rather than a typed one.
    pub fp_conflicts: BTreeSet<u32>,
    /// Declared argument lanes, recorded separately from declared result
    /// lanes: argument TempIds name integer registers the declaration
    /// assigns as pointers; result TempIds name the integer result
    /// register(s) the declaration assigns instead. Split because AAPCS64
    /// uses `x0` for both argument 0 and the scalar result: one shared
    /// per-physical-register set would alias a pointer argument into a
    /// pointer result (and a narrow argument into a narrow result).
    /// Set only by annotation application, never by recovery; empty by
    /// default so wire data without it deserializes unchanged. The lifter
    /// lowers pointer lanes to LLVM pointer types instead of raw words;
    /// integer/pointer transport stays bit-exact (inttoptr/ptrtoint).
    #[serde(default)]
    pub explicit_ptr_args: BTreeSet<TempId>,
    /// Declared result lanes assigned as pointers (see above): never
    /// aliases [`FunctionAbi::explicit_ptr_args`].
    #[serde(default)]
    pub explicit_ptr_rets: BTreeSet<TempId>,
    /// Declared narrow argument lanes by TempId to their width (8 or 16):
    /// the lifter lowers these to i8/i16 slots with bit-exact coerce at
    /// the register boundary. 32/64-bit lanes need no entry.
    #[serde(default)]
    pub explicit_narrow_args: BTreeMap<TempId, u32>,
    /// Declared narrow result lanes by TempId (see above): never aliases
    /// [`FunctionAbi::explicit_narrow_args`].
    #[serde(default)]
    pub explicit_narrow_rets: BTreeMap<TempId, u32>,
    /// Argument lanes whose declared C type is signed (per TempId).
    /// Transport is sign-agnostic (LLVM integers carry bits; boundary
    /// coercions use zero-extension), so this only selects the rendered
    /// spelling (`int16_t` vs `uint16_t`). Absent means unsigned.
    /// Never aliases the result set below. Set only by annotation
    /// application.
    #[serde(default)]
    pub explicit_signed_args: BTreeSet<TempId>,
    /// Result lanes whose declared C type is signed (see above).
    #[serde(default)]
    pub explicit_signed_rets: BTreeSet<TempId>,
    /// Declared boolean argument lanes (per TempId): `_Bool` transport is
    /// `i1` (zero-extended at the register boundary); the declared
    /// spelling stays `_Bool`. Never aliases the result set below.
    #[serde(default)]
    pub explicit_bool_args: BTreeSet<TempId>,
    /// Declared boolean result lanes (see above).
    #[serde(default)]
    pub explicit_bool_rets: BTreeSet<TempId>,
    /// Declared narrow/stack widths for spilled scalar stack slots, by
    /// entry-sp-relative byte offset: `(offset, declared width bits)`.
    /// Only set when the declaration assigns a scalar type narrower than
    /// the 64-bit stack slot to a stack parameter; the ABI former coerces
    /// bit-exactly at the slot boundary. Absent offsets keep `i64`.
    #[serde(default)]
    pub explicit_stack_narrow: BTreeMap<i64, u32>,
    /// Declared signedness for spilled scalar stack slots, by offset.
    #[serde(default)]
    pub explicit_stack_signed: BTreeSet<i64>,
    /// Declared boolean stack slots, by offset (`i1` transport).
    #[serde(default)]
    pub explicit_stack_bool: BTreeSet<i64>,
    /// Per-function struct bindings for explicit `struct name *`
    /// argument lanes: `(lane, struct name)` pairs naming which declared
    /// layout each pointer lane carries. Never aliases the result map
    /// below. The renderer uses the named declaration for that lane's
    /// pointees; unrelated layouts with matching shapes are never renamed
    /// or merged by this.
    #[serde(default)]
    pub explicit_struct_args: BTreeMap<TempId, String>,
    /// Per-function struct bindings for explicit `struct name *` result
    /// lanes (see above).
    #[serde(default)]
    pub explicit_struct_rets: BTreeMap<TempId, String>,
    /// Ordered declared formal widening: every declared parameter in
    /// declaration order that the convention places in a register or
    /// stack slot beyond recovered inference, as
    /// `(lane TempId or stack offset marker, kind, declared spelling)`.
    /// Encoded as three parallel vectors so the ABI map stays serde-plain:
    /// `explicit_order_lanes` holds register TempIds for register formals
    /// and `u32::MAX` for stack formals; `explicit_order_stack` holds the
    /// stack offset for stack formals and `0` otherwise;
    /// `explicit_order_spellings` holds the canonical C spelling per
    /// formal (`_Bool`, `int16_t`, `struct Header *`, ...). The lifter
    /// uses this to emit interleaved LLVM formals (not int-bank then
    /// FP-bank) and to attach `biara.c_type` attrs in order.
    #[serde(default)]
    pub explicit_order_lanes: Vec<u32>,
    #[serde(default)]
    pub explicit_order_stack: Vec<i64>,
    #[serde(default)]
    pub explicit_order_spellings: Vec<String>,
    /// Canonical declared C return spelling (`void`, `int16_t`, `double`,
    /// `struct Header *`, ...). Empty (default) means undeclared: the
    /// renderer keeps the recovered spelling. Set only by annotation
    /// application; consumed as the `biara.c_return` function attribute.
    #[serde(default)]
    pub explicit_return_spelling: String,
    /// Aggregate return shape established from evidence: `None` for a plain
    /// scalar, `Some(Pair)` when two result registers carry one value,
    /// `Some(Memory)` when hidden-`sret` evidence proves the caller passes
    /// a result pointer the callee stores through. A store through the
    /// first argument plus returning that same pointer is *not* proof: it
    /// also describes memset/setters, so it stays explicit observed
    /// pointer-write evidence (conventional slot + store widths) until
    /// caller/ABI evidence proves a hidden result. Two live result
    /// registers are likewise not an aggregate without evidence they carry
    /// one value; facts stay per-register. `Memory` never invents a source
    /// struct type: it records the store-through-pointer fact.
    pub ret_class: Option<biara_cfg::ReturnClass>,
    pub analysis: AbiStatus,
}

impl FunctionAbi {
    /// Compare the facts driving the fixpoint, excluding reporting metadata.
    fn same_facts(&self, other: &Self) -> bool {
        self.frame == other.frame
            && self.args == other.args
            && self.stack_args == other.stack_args
            && self.returns == other.returns
            && self.preserved == other.preserved
            && self.fp_args == other.fp_args
            && self.fp_arg_types == other.fp_arg_types
            && self.fp_returns == other.fp_returns
            && self.fp_ret_types == other.fp_ret_types
            && self.fp_conflicts == other.fp_conflicts
            && self.explicit_ptr_args == other.explicit_ptr_args
            && self.explicit_ptr_rets == other.explicit_ptr_rets
            && self.explicit_narrow_args == other.explicit_narrow_args
            && self.explicit_narrow_rets == other.explicit_narrow_rets
            && self.explicit_signed_args == other.explicit_signed_args
            && self.explicit_signed_rets == other.explicit_signed_rets
            && self.explicit_bool_args == other.explicit_bool_args
            && self.explicit_bool_rets == other.explicit_bool_rets
            && self.explicit_stack_narrow == other.explicit_stack_narrow
            && self.explicit_stack_signed == other.explicit_stack_signed
            && self.explicit_stack_bool == other.explicit_stack_bool
            && self.explicit_struct_args == other.explicit_struct_args
            && self.explicit_struct_rets == other.explicit_struct_rets
            && self.explicit_order_lanes == other.explicit_order_lanes
            && self.explicit_order_stack == other.explicit_order_stack
            && self.explicit_order_spellings == other.explicit_order_spellings
            && self.explicit_return_spelling == other.explicit_return_spelling
    }
}

/// Upper bound on whole-program rounds.
const MAX_ROUNDS: usize = 16;

/// Recover frames and register usage for every function in `cfg`.
///
/// Return values come from the callers; functions without direct callers
/// (entry points, exports, functions reached through pointers) are taken
/// to return the convention's result register when they change it.
pub fn analyze(cfg: &Cfg, info: &ContextInfo) -> Result<BTreeMap<u64, FunctionAbi>, Error> {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    analyze_rounds(cfg, info, MAX_ROUNDS, available.saturating_sub(1).max(1))
}

/// Analyze changed function dependencies with a captured shared CPU budget.
pub fn analyze_with_workers(
    cfg: &Cfg,
    info: &ContextInfo,
    workers: usize,
) -> Result<BTreeMap<u64, FunctionAbi>, Error> {
    analyze_rounds(cfg, info, MAX_ROUNDS, workers.max(1))
}

#[cfg(test)]
fn analyze_with_limit(
    cfg: &Cfg,
    info: &ContextInfo,
    max_rounds: usize,
) -> Result<BTreeMap<u64, FunctionAbi>, Error> {
    analyze_rounds(cfg, info, max_rounds, 1)
}

/// Whether recording typed lane `(lane, ty)` on `abi` would conflict with
/// established evidence: marks the conflict and drops the type.
fn lane_indicator_conflict(abi: &mut FunctionAbi, lane: u32, ty: LaneType) -> bool {
    if abi.fp_conflicts.contains(&lane) {
        return true;
    }
    if let Some(&t) = abi.fp_arg_types.get(&lane)
        && t != ty
    {
        abi.fp_arg_types.remove(&lane);
        abi.fp_args.insert(lane);
        abi.fp_conflicts.insert(lane);
        return true;
    }
    false
}

fn analyze_rounds(
    cfg: &Cfg,
    info: &ContextInfo,
    max_rounds: usize,
    workers: usize,
) -> Result<BTreeMap<u64, FunctionAbi>, Error> {
    let spec = cfg.spec(&info.arch)?;
    let cx = Ctx::new(cfg, info, spec)?;
    let called: BTreeSet<u64> = cfg
        .blocks
        .values()
        .flat_map(|b| &b.exits)
        .filter_map(|x| match x.kind {
            ExitKind::Call { target, .. } | ExitKind::Jump(target) => Some(target),
            _ => None,
        })
        .chain(cfg.functions.values().flat_map(|f| f.calls.iter().copied()))
        .collect();
    let mut abis: BTreeMap<u64, FunctionAbi> = BTreeMap::new();
    let mut analysis = AbiStatus::default();
    let mut learned: BTreeMap<u64, Learned> = BTreeMap::new();
    let mut dirty: BTreeSet<u64> = cfg.functions.keys().copied().collect();
    for round in 1..=max_rounds {
        analysis.rounds = round;
        let mut next: BTreeMap<u64, FunctionAbi> = BTreeMap::new();
        let mut ret_uses: BTreeSet<(u64, TempId)> = BTreeSet::new();
        let mut passthrough: BTreeMap<u64, BTreeSet<TempId>> = BTreeMap::new();
        // Argument registers every caller sets, by callee.
        let mut set_by_callers: BTreeMap<u64, BTreeSet<TempId>> = BTreeMap::new();
        // FP lanes every caller establishes, by callee: (lane, type).
        let mut fp_set_by_callers: BTreeMap<u64, BTreeSet<(u32, LaneType)>> = BTreeMap::new();
        // FP result lanes callers consume, by callee: (lane, type).
        let mut fp_ret_uses: BTreeMap<u64, BTreeMap<u32, LaneType>> = BTreeMap::new();
        let mut fp_ret_conflicts = BTreeSet::new();
        // FP lanes passed through to unknown code, by function.
        let mut fp_passthrough: BTreeMap<u64, BTreeSet<(u32, LaneType)>> = BTreeMap::new();
        let entries: Vec<_> = dirty.iter().copied().collect();
        let count = workers.min(entries.len()).max(1);
        let grain = entries.len().div_ceil(count).max(1);
        let compute = |batch: &[u64]| {
            batch
                .iter()
                .map(|entry| {
                    let f = &cfg.functions[entry];
                    let local = cx.function(f, &abis, !called.contains(entry));
                    (*entry, local)
                })
                .collect::<Vec<_>>()
        };
        let outputs = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(count.saturating_sub(1));
            for batch in entries.chunks(grain).skip(1) {
                let compute = &compute;
                handles.push(scope.spawn(move || compute(batch)));
            }
            let mut outputs = compute(&entries[..entries.len().min(grain)]);
            for handle in handles {
                outputs.extend(handle.join().expect("ABI worker panicked"));
            }
            outputs
        });
        learned.extend(outputs);
        for (&entry, local) in &learned {
            next.insert(entry, local.abi.clone());
            ret_uses.extend(&local.ret_uses);
            passthrough.insert(entry, local.passthrough.clone());
            for (callee, set) in &local.call_writes {
                set_by_callers
                    .entry(*callee)
                    .and_modify(|s| s.retain(|r| set.contains(r)))
                    .or_insert_with(|| set.clone());
            }
            fp_passthrough.insert(entry, local.fp_passthrough.clone());
            for (callee, set) in &local.fp_call_writes {
                fp_set_by_callers
                    .entry(*callee)
                    .and_modify(|s| s.retain(|t| set.contains(t)))
                    .or_insert_with(|| set.clone());
            }
            for &(callee, lane, ty) in &local.fp_ret_uses {
                let lanes = fp_ret_uses.entry(callee).or_default();
                if lanes.get(&lane).is_some_and(|&old| old != ty) {
                    fp_ret_conflicts.insert((callee, lane));
                }
                lanes.insert(lane, ty);
            }
        }
        for (callee, reg) in ret_uses {
            if let Some(a) = next.get_mut(&callee) {
                a.returns.insert(reg);
            }
        }
        for local in learned.values() {
            for &(callee, lane) in &local.fp_raw_ret_uses {
                if let Some(a) = next.get_mut(&callee) {
                    a.fp_returns.insert(lane);
                }
            }
        }
        for a in next.values_mut() {
            if a.returns.contains(&cx.unknown_ret)
                && cx.second_ret.is_some_and(|r| a.returns.contains(&r))
            {
                a.ret_class = Some(biara_cfg::ReturnClass::Pair);
            }
        }
        for (callee, lane) in fp_ret_conflicts {
            if let Some(abi) = next.get_mut(&callee) {
                abi.fp_conflicts.insert(lane);
                abi.fp_ret_types.remove(&lane);
                abi.fp_returns.insert(lane);
            }
        }
        for (callee, lanes) in &fp_ret_uses {
            if let Some(a) = next.get_mut(callee) {
                for (&lane, &ty) in lanes {
                    if a.fp_conflicts.contains(&lane) {
                        continue;
                    }
                    if a.fp_ret_types.get(&lane).is_some_and(|&old| old != ty) {
                        a.fp_conflicts.insert(lane);
                        a.fp_ret_types.remove(&lane);
                        a.fp_returns.insert(lane);
                        continue;
                    }
                    a.fp_ret_types.insert(lane, ty);
                    a.fp_returns.insert(lane);
                }
            }
        }
        // A register a function hands on to unknown code untouched is an
        // argument when its callers all set it (variadic wrappers and the
        // like: `error_tail(status, errnum, fmt, ap)` passing fmt and ap).
        for (entry, regs) in &passthrough {
            if let (Some(a), Some(set)) = (next.get_mut(entry), set_by_callers.get(entry)) {
                a.args.extend(regs.intersection(set));
            }
        }
        // Same for FP lanes, with types: a lane handed on untouched is an
        // argument when every caller establishes the same typed lane.
        for (entry, lanes) in &fp_passthrough {
            if let (Some(a), Some(set)) = (next.get_mut(entry), fp_set_by_callers.get(entry)) {
                for &(lane, ty) in set.intersection(lanes) {
                    if lane_indicator_conflict(a, lane, ty) {
                        continue;
                    }
                    a.fp_args.insert(lane);
                    a.fp_arg_types.insert(lane, ty);
                }
            }
        }
        if next.len() == abis.len()
            && next
                .iter()
                .all(|(entry, a)| abis.get(entry).is_some_and(|b| a.same_facts(b)))
        {
            analysis.converged = true;
            break;
        }
        let changed: BTreeSet<_> = next
            .iter()
            .filter(|(entry, abi)| abis.get(entry).is_none_or(|old| !abi.same_facts(old)))
            .map(|(&entry, _)| entry)
            .collect();
        dirty = cfg
            .functions
            .values()
            .filter(|function| {
                changed.contains(&function.entry)
                    || !function.calls.is_disjoint(&changed)
                    || !function.tail_calls.is_disjoint(&changed)
            })
            .map(|function| function.entry)
            .collect();
        abis = next;
    }
    for abi in abis.values_mut() {
        abi.analysis = analysis;
    }
    Ok(abis)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    Unknown,
    Const(u64),
    /// Entry value of global `.0`, plus `.1`.
    Entry(TempId, i64),
    /// What callee `.0` left in register `.1`.
    Ret(u64, TempId),
    /// Untyped bits from an incoming SIMD lane, plus byte displacement.
    FpEntry(u32, u32),
    /// Untyped bits a direct callee returned in a SIMD lane.
    FpRet(u64, u32, u32),
    /// A value produced by an operation that establishes its lane width.
    FpTyped(LaneType),
    FpConflict,
}

#[derive(Clone, Debug, PartialEq)]
struct State {
    /// By global index.
    regs: Vec<Val>,
    /// Word-sized stack slots by offset from the entry stack pointer.
    stack: BTreeMap<i64, Val>,
    /// Globals this function may have written since entry or the last
    /// call: what an unknown callee could be receiving as arguments.
    written: Vec<bool>,
    /// Four-byte CPU-state cells, including SIMD lanes and helper scratch.
    /// Copies preserve provenance; loads/stores alone establish no FP type.
    env: BTreeMap<i64, Val>,
}

impl State {
    fn join(&mut self, other: &State) -> bool {
        let mut changed = false;
        for (a, b) in self.regs.iter_mut().zip(&other.regs) {
            if a != b && *a != Val::Unknown {
                *a = Val::Unknown;
                changed = true;
            }
        }
        for (a, &b) in self.written.iter_mut().zip(&other.written) {
            changed |= b && !*a;
            *a |= b;
        }
        let before = self.stack.len();
        self.stack.retain(|k, v| other.stack.get(k) == Some(v));
        changed |= join_env(&mut self.env, &other.env);
        changed || self.stack.len() != before
    }
}

/// What one function evaluation learns besides its exit states.
#[derive(Default)]
struct Facts {
    uses: BTreeSet<TempId>,
    ret_uses: BTreeSet<(u64, TempId)>,
    slots: BTreeMap<i64, u32>,
    stack_args: BTreeSet<i64>,
    /// Argument registers still holding their entry value at a call to
    /// unknown code: arguments passed on, if callers set them.
    passthrough: BTreeSet<TempId>,
    /// Per direct call: the callee and the argument registers set for it.
    call_writes: Vec<(u64, BTreeSet<TempId>)>,
    /// FP/vector lane traffic with float/vector evidence, by lane index
    /// into the convention's `fp_args` order: (`lane`, `type`, `is_write`).
    /// Reads of the entry lane value are argument evidence; writes mark the
    /// lane established for callers. A lane with two different types across
    /// paths loses its type into `fp_conflicts`. Integer bit-pattern
    /// traffic through the same state never records here.
    fp_hits: Vec<(u32, LaneType, bool)>,
    /// FP/vector lane values a caller uses after the call, by callee and
    /// result-lane index: return-lane evidence with its observed type.
    fp_ret_uses: BTreeSet<(u64, u32, LaneType)>,
    fp_raw_args: BTreeSet<u32>,
    fp_raw_ret_uses: BTreeSet<(u64, u32)>,
    /// Per direct call: the callee and the argument-lane indices written
    /// before the call with observed types (argument evidence for the
    /// callee's lanes).
    fp_call_writes: Vec<(u64, BTreeSet<(u32, LaneType)>)>,
    /// FP lanes passed on untouched to unknown code: argument candidates
    /// when every caller establishes them, with the observed type.
    fp_passthrough: BTreeSet<(u32, LaneType)>,
    /// Stores through the conventional `sret` slot's entry value (SysV:
    /// first integer argument; AArch64: `x8`), with the widest store width
    /// in bytes. This is observed pointer-write evidence only: a store plus
    /// returning the same pointer also describes memset/setters, so
    /// `Memory` needs caller/ABI proof beyond this (see `function`).
    sret_stores: Vec<u32>,
}

/// What one function's analysis contributes to the next round.
struct Learned {
    abi: FunctionAbi,
    ret_uses: BTreeSet<(u64, TempId)>,
    passthrough: BTreeSet<TempId>,
    call_writes: Vec<(u64, BTreeSet<TempId>)>,
    fp_ret_uses: BTreeSet<(u64, u32, LaneType)>,
    fp_passthrough: BTreeSet<(u32, LaneType)>,
    fp_raw_ret_uses: BTreeSet<(u64, u32)>,
    fp_call_writes: Vec<(u64, BTreeSet<(u32, LaneType)>)>,
}

impl Facts {
    fn use_val(&mut self, v: Val) {
        match v {
            Val::Entry(g, _) => {
                self.uses.insert(g);
            }
            Val::Ret(c, r) => {
                self.ret_uses.insert((c, r));
            }
            Val::FpEntry(lane, _) => {
                self.fp_raw_args.insert(lane);
            }
            Val::FpRet(callee, lane, _) => {
                self.fp_raw_ret_uses.insert((callee, lane));
            }
            _ => {}
        }
    }

    /// Record a caller consuming a callee's typed FP result lane.
    /// Register-only `Val::Ret` reads record the integer use above; lane
    /// grading happens in `function` from the callee's established types.
    fn use_fp_ret(&mut self, callee: u64, lane: u32, ty: LaneType) {
        self.fp_ret_uses.insert((callee, lane, ty));
    }
}

/// How control leaves a block evaluation.
enum Out {
    /// To another block of this function.
    Block(u64, State),
    /// Back to the caller (return, tail call, unknown jump), in this state.
    Leave(State),
}

struct Ctx<'a> {
    cfg: &'a Cfg,
    nb_globals: usize,
    sp: TempId,
    pc: TempId,
    word: u64,
    pushes_return: bool,
    /// Lowest stack-argument offset (above the return address).
    arg_base: i64,
    /// Bytes above the return address every callee may write
    /// (`CallConv::home`).
    home: i64,
    unknown_args: Vec<TempId>,
    unknown_clobbers: BTreeSet<TempId>,
    /// The convention's result register.
    unknown_ret: TempId,
    syscall_args: Vec<TempId>,
    syscall_clobbers: BTreeSet<TempId>,
    helper_regs: HashMap<&'static str, (RegSet, RegSet)>,
    /// Globals of the registers `helper_regs` can name.
    helper_reg_ids: HashMap<&'static str, TempId>,
    helper_regs_complete: bool,
    /// FP/vector argument lanes in convention order.
    fp_lanes: &'static [biara_cfg::FpLane],
    /// FP/vector result lanes in convention order.
    fp_results: &'static [biara_cfg::FpLane],
    /// Hidden-`sret` slot, if the convention names one.
    sret: Option<TempId>,
    /// Second integer result register (pair evidence), if two exist.
    second_ret: Option<TempId>,
    env: Option<TempId>,
    spec: &'static ArchSpec,
}

impl<'a> Ctx<'a> {
    fn new(cfg: &'a Cfg, info: &ContextInfo, spec: &'static ArchSpec) -> Result<Self, Error> {
        let find = |name: &str| {
            info.globals
                .iter()
                .position(|g| g.name.as_deref() == Some(name))
                .map(|i| i as TempId)
                .ok_or_else(|| Error::Global {
                    arch: info.arch.clone(),
                    name: name.to_owned(),
                })
        };
        let all = |names: &[&str]| names.iter().map(|n| find(n)).collect::<Result<Vec<_>, _>>();
        let (word, pushes_return) = match spec.ret {
            ReturnConvention::Stack { word } => (word, true),
            ReturnConvention::LinkRegister(_) => (u64::from(info.guest_bits / 8), false),
        };
        let mut helper_regs = HashMap::new();
        let mut helper_reg_ids = HashMap::new();
        for &(name, reads, writes) in spec.helper_regs {
            helper_regs.insert(name, (reads, writes));
            for set in [reads, writes] {
                let (RegSet::Named(names) | RegSet::Fields { names, .. }) = set;
                for &n in names {
                    helper_reg_ids.insert(n, find(n)?);
                }
            }
        }
        Ok(Self {
            cfg,
            nb_globals: info.globals.len(),
            sp: find(spec.sp)?,
            pc: info.pc_global,
            word,
            pushes_return,
            arg_base: if pushes_return { word as i64 } else { 0 },
            home: spec.unknown_call.home as i64,
            unknown_args: all(spec.unknown_call.args)?,
            unknown_clobbers: all(spec.unknown_call.clobbers)?.into_iter().collect(),
            unknown_ret: find(spec.unknown_call.results[0])?,
            syscall_args: all(spec.syscall.args)?,
            syscall_clobbers: all(spec.syscall.clobbers)?.into_iter().collect(),
            helper_regs,
            helper_reg_ids,
            helper_regs_complete: spec.helper_regs_complete,
            fp_lanes: spec.unknown_call.fp_args,
            fp_results: spec.unknown_call.fp_results,
            // A missing sret-named global means the context has no such
            // slot: no hidden-pointer evidence can name it, so `None`.
            sret: spec.unknown_call.sret_slot.and_then(|n| {
                info.globals
                    .iter()
                    .position(|g| g.name.as_deref() == Some(n))
                    .map(|i| i as TempId)
            }),
            second_ret: spec.unknown_call.results.get(1).and_then(|n| {
                info.globals
                    .iter()
                    .position(|g| g.name.as_deref() == Some(*n))
                    .map(|i| i as TempId)
            }),
            env: Some(info.env_global),
            spec,
        })
    }

    fn entry_state(&self) -> State {
        State {
            regs: (0..self.nb_globals)
                .map(|g| Val::Entry(g as TempId, 0))
                .collect(),
            stack: BTreeMap::new(),
            written: vec![false; self.nb_globals],
            env: self
                .fp_lanes
                .iter()
                .flat_map(|bank| {
                    (0..bank.count).flat_map(move |i| {
                        (0..bank.vec_bytes).step_by(4).map(move |part| {
                            (
                                bank.base + i64::from(i) * bank.stride as i64 + i64::from(part),
                                Val::FpEntry(bank.slot + i, part),
                            )
                        })
                    })
                })
                .collect(),
        }
    }

    /// Analyse `f` given the previous round's results: its ABI, the
    /// (callee, register) return values it uses, and what it tells about
    /// pass-through arguments.
    fn function(&self, f: &Function, abis: &BTreeMap<u64, FunctionAbi>, root: bool) -> Learned {
        // Fixpoint of block entry states. Uses are collected along the way:
        // a state seen before a join describes real paths, and the join may
        // forget that a register still held an entry value on some of them.
        let mut facts = Facts::default();
        let mut ins: BTreeMap<u64, State> = BTreeMap::from([(f.entry, self.entry_state())]);
        let mut work = vec![f.entry];
        while let Some(a) = work.pop() {
            let Some(bb) = self.cfg.blocks.get(&a) else {
                continue;
            };
            let st = ins[&a].clone();
            for out in self.eval(f, bb, st, abis, &mut facts) {
                if let Out::Block(t, s) = out {
                    match ins.get_mut(&t) {
                        Some(cur) => {
                            if cur.join(&s) {
                                work.push(t);
                            }
                        }
                        None => {
                            ins.insert(t, s);
                            work.push(t);
                        }
                    }
                }
            }
        }

        // Exit states from the fixed entry states.
        let mut leaves = Vec::new();
        for (&a, st) in &ins {
            let Some(bb) = self.cfg.blocks.get(&a) else {
                continue;
            };
            for out in self.eval(f, bb, st.clone(), abis, &mut facts) {
                if let Out::Leave(s) = out {
                    leaves.push(s);
                }
            }
        }

        let prev = abis.get(&f.entry);
        // Explicit consumer-visible integer result: the result register was
        // written since entry (or the last call) and no longer holds its
        // entry value. Call clobbers and untouched callee-result slots do
        // not prove an integer return. Neither do input/callee FP bits
        // temporarily saved in a GPR: FP wrappers often leave those there.
        // FP-to-integer conversion chains do count as integer computations;
        // their stale FP intermediates must not outrank the final GPR.
        let is_explicit = |s: &State| {
            s.regs[self.unknown_ret as usize] != Val::Entry(self.unknown_ret, 0)
                && !matches!(
                    s.regs[self.unknown_ret as usize],
                    Val::FpEntry(_, _) | Val::FpRet(_, _, _)
                )
                && s.written[self.unknown_ret as usize]
        };
        let all_explicit = !leaves.is_empty() && leaves.iter().all(is_explicit);
        let any_explicit = leaves.iter().any(is_explicit);
        let mut returned_fp = BTreeMap::new();
        let mut returned_conflicts = BTreeSet::new();
        for (lane, off) in self.result_lanes() {
            let demanded = prev.is_some_and(|a| a.fp_returns.contains(&lane));
            // A default FP result needs no consumer, but an explicitly
            // computed integer return on every path proves the stale lane is
            // dead: skip the default (demands still grade below).
            let default = lane == 0
                && !leaves.is_empty()
                && ((root && !all_explicit)
                    || leaves.iter().all(|s| {
                        s.regs[self.unknown_ret as usize] == Val::Entry(self.unknown_ret, 0)
                    }));
            if !demanded && !default {
                continue;
            }
            let mut common = None;
            let mut unknown = false;
            for state in &leaves {
                let value = state.env.get(&off).copied().unwrap_or(Val::Unknown);
                let ty = match value {
                    Val::FpTyped(ty) => Some(ty),
                    Val::FpRet(callee, slot, _) => abis
                        .get(&callee)
                        .and_then(|a| a.fp_ret_types.get(&slot))
                        .copied(),
                    Val::FpConflict => {
                        returned_conflicts.insert(lane);
                        None
                    }
                    _ => prev.and_then(|a| a.fp_ret_types.get(&lane)).copied(),
                };
                if let Some(ty) = ty {
                    self.fp_use(value, ty, 0, &mut facts);
                    if common.is_some_and(|old| old != ty) {
                        returned_conflicts.insert(lane);
                    }
                    common = Some(ty);
                } else {
                    unknown = true;
                }
            }
            if demanded || common.is_some() || returned_conflicts.contains(&lane) {
                returned_fp.insert(lane, if unknown { None } else { common });
            }
        }
        // Uncalled roots have no consumer to demand their first result.
        // Established FP evidence replaces only a speculative GPR default.
        // Mixed paths retain an explicitly written GPR as well as any FP
        // result evidence; neither feasible return channel may be dropped.
        let default_result = root
            && f.returns
            && (returned_fp.is_empty() || any_explicit)
            && leaves
                .iter()
                .any(|s| s.regs[self.unknown_ret as usize] != Val::Entry(self.unknown_ret, 0));
        for state in &leaves {
            if let Some(previous) = prev {
                for &r in &previous.returns {
                    if !root || returned_fp.is_empty() || any_explicit || r != self.unknown_ret {
                        facts.use_val(state.regs[r as usize]);
                    }
                }
            }
            if default_result {
                facts.use_val(state.regs[self.unknown_ret as usize]);
            }
        }

        let sp_return = if self.pushes_return {
            self.word as i64
        } else {
            0
        };
        let preserved = (0..self.nb_globals as TempId)
            .filter(|&g| g != self.sp && g != self.pc)
            // Vacuously true for functions that never return.
            .filter(|&g| {
                leaves
                    .iter()
                    .all(|s| s.regs[g as usize] == Val::Entry(g, 0))
            })
            .collect();
        let balanced = leaves
            .iter()
            .all(|s| s.regs[self.sp as usize] == Val::Entry(self.sp, sp_return));

        let sp_at: BTreeMap<u64, Option<i64>> = f
            .blocks
            .iter()
            .map(|&a| {
                let sp = ins.get(&a).and_then(|s| match s.regs[self.sp as usize] {
                    Val::Entry(g, k) if g == self.sp => Some(k),
                    _ => None,
                });
                (a, sp)
            })
            .collect();
        let deepest = sp_at
            .values()
            .flatten()
            .copied()
            .chain(facts.slots.keys().copied())
            .min()
            .unwrap_or(0);

        let args = facts
            .uses
            .iter()
            .copied()
            .filter(|&g| g != self.sp && g != self.pc && Some(g) != self.env)
            .collect();
        // Grade FP/vector lane traffic into typed facts. A lane keeps a
        // type only when every observed access agrees; two widths on one
        // lane become a conflict and stay raw words. Caller-observed return
        // lanes (previous round's `fp_returns`) grade the same way.
        let mut fp_arg_types: BTreeMap<u32, LaneType> = BTreeMap::new();
        let mut fp_args: BTreeSet<u32> = BTreeSet::new();
        let mut fp_conflicts: BTreeSet<u32> = BTreeSet::new();
        fp_args.extend(&facts.fp_raw_args);
        for &(lane, ty, _) in &facts.fp_hits {
            match fp_arg_types.get(&lane) {
                Some(&t) if t != ty => {
                    fp_arg_types.remove(&lane);
                    fp_args.insert(lane);
                    fp_conflicts.insert(lane);
                }
                _ => {
                    if !fp_conflicts.contains(&lane) {
                        fp_arg_types.insert(lane, ty);
                        fp_args.insert(lane);
                    }
                }
            }
        }
        // Caller-observed return lanes: the previous round told this
        // function which result lanes its callers consume. Grade types the
        // same strict way; conflicts stay raw words.
        let mut fp_ret_types = BTreeMap::new();
        let mut fp_returns = BTreeSet::new();
        for (lane, ty) in returned_fp {
            fp_returns.insert(lane);
            if returned_conflicts.contains(&lane) {
                fp_conflicts.insert(lane);
            } else if let Some(ty) = ty {
                fp_ret_types.insert(lane, ty);
            }
        }
        // Only distinct hidden-result address slots establish memory
        // transport without conflating it with ordinary pointer setters.
        // x8 is a distinct AAPCS64 hidden-result address, unlike an
        // ordinary first pointer argument (which could be a setter).
        let ret_class =
            if self.spec.unknown_call.sret_slot == Some("x8") && !facts.sret_stores.is_empty() {
                Some(biara_cfg::ReturnClass::Memory)
            } else {
                prev.and_then(|a| a.ret_class)
            };
        let abi = FunctionAbi {
            frame: Frame {
                sp_at,
                slots: facts.slots,
                size: deepest.min(0).unsigned_abs(),
                balanced,
            },
            args,
            explicit_ptr_args: BTreeSet::new(),
            explicit_ptr_rets: BTreeSet::new(),
            explicit_narrow_args: BTreeMap::new(),
            explicit_narrow_rets: BTreeMap::new(),
            explicit_signed_args: BTreeSet::new(),
            explicit_signed_rets: BTreeSet::new(),
            explicit_bool_args: BTreeSet::new(),
            explicit_bool_rets: BTreeSet::new(),
            explicit_stack_narrow: BTreeMap::new(),
            explicit_stack_signed: BTreeSet::new(),
            explicit_stack_bool: BTreeSet::new(),
            explicit_struct_args: BTreeMap::new(),
            explicit_struct_rets: BTreeMap::new(),
            explicit_order_lanes: Vec::new(),
            explicit_order_stack: Vec::new(),
            explicit_order_spellings: Vec::new(),
            explicit_return_spelling: String::new(),
            stack_args: facts.stack_args,
            // Caller demands are merged after the round. Root defaults must
            // contribute dependencies before argument facts are finalized.
            returns: if default_result {
                BTreeSet::from([self.unknown_ret])
            } else {
                BTreeSet::new()
            },
            preserved,
            fp_args,
            fp_arg_types,
            fp_returns,
            fp_ret_types,
            fp_conflicts,
            ret_class,
            analysis: AbiStatus::default(),
        };
        Learned {
            abi,
            ret_uses: facts.ret_uses,
            passthrough: facts.passthrough,
            call_writes: facts.call_writes,
            fp_ret_uses: facts.fp_ret_uses,
            fp_raw_ret_uses: facts.fp_raw_ret_uses,
            fp_passthrough: facts.fp_passthrough,
            fp_call_writes: facts.fp_call_writes,
        }
    }

    /// Evaluate one block from `st`.
    fn eval(
        &self,
        f: &Function,
        bb: &BasicBlock,
        st: State,
        abis: &BTreeMap<u64, FunctionAbi>,
        facts: &mut Facts,
    ) -> Vec<Out> {
        let block = &bb.block;
        let mut temps: Vec<Val> = block
            .temps
            .iter()
            .enumerate()
            .map(|(i, t)| match t.kind {
                TempKind::Global | TempKind::Fixed => {
                    st.regs.get(i).copied().unwrap_or(Val::Unknown)
                }
                TempKind::Const => Val::Const(t.value as u64 & mask(t.ty)),
                _ => Val::Unknown,
            })
            .collect();
        let mut cur: Option<Local> =
            Some((std::mem::take(&mut temps), st.stack, st.written, st.env));
        let mut pending: HashMap<u64, Local> = HashMap::new();
        let mut outs = Vec::new();

        for (i, op) in block.ops.iter().enumerate() {
            if op.opcode == Opcode::SetLabel {
                let l = block.consts(op)[0];
                cur = match (cur.take(), pending.remove(&l)) {
                    (Some(mut a), Some(b)) => {
                        join_local(&mut a, &b);
                        Some(a)
                    }
                    (a, b) => a.or(b),
                };
                continue;
            }
            let Some((t, stack, written, env)) = cur.as_mut() else {
                continue;
            };
            for &o in block.outputs(op) {
                if (o as usize) < self.nb_globals {
                    written[o as usize] = true;
                }
            }
            let out = block.outputs(op);
            let inp = block.inputs(op);
            let k = block.consts(op);
            let m = mask(op.ty);

            match op.opcode {
                Opcode::InsnStart | Opcode::GotoTb | Opcode::Mb => {}
                Opcode::Discard => t[out[0] as usize] = Val::Unknown,
                Opcode::Brcond => {
                    facts.use_val(t[inp[0] as usize]);
                    facts.use_val(t[inp[1] as usize]);
                    let snapshot = (t.clone(), stack.clone(), written.clone(), env.clone());
                    merge(&mut pending, k[1], snapshot);
                }
                Opcode::Br => {
                    let snapshot = cur.take().unwrap();
                    merge(&mut pending, k[0], snapshot);
                }
                Opcode::ExitTb | Opcode::GotoPtr => {
                    let (t, stack, written, env) = cur.take().unwrap();
                    let kind = bb.exits.iter().find(|x| x.op == i).map(|x| x.kind);
                    self.exit(
                        f,
                        bb,
                        kind,
                        self.to_state(&t, stack, written, env),
                        abis,
                        facts,
                        &mut outs,
                    );
                }
                Opcode::Call => {
                    let h = block.helper(op);
                    let kind = bb.exits.iter().find(|x| x.op == i).map(|x| x.kind);
                    if matches!(kind, Some(ExitKind::Syscall { .. })) {
                        let (t, stack, written, env) = cur.take().unwrap();
                        self.exit(
                            f,
                            bb,
                            kind,
                            self.to_state(&t, stack, written, env),
                            abis,
                            facts,
                            &mut outs,
                        );
                        continue;
                    }
                    if self.spec.is_pointer_auth(block, op) {
                        t[out[0] as usize] = t[inp[1] as usize];
                        continue;
                    }
                    for &a in inp {
                        // A `Val::Ret` read is the caller consuming a
                        // callee's result; when the callee's previous-round
                        // facts type a result lane and this read feeds a
                        // typed lane access, `fp_hits` grades it. The
                        // integer use always records too.
                        facts.use_val(t[a as usize]);
                    }
                    self.fp_helper(block, op, t, env, facts);
                    if h.flags & call_flags::NO_READ_GLOBALS == 0 {
                        if let Some(&(reads, writes)) = self.helper_regs.get(h.name.as_str()) {
                            for name in reads.names(block, op) {
                                facts.use_val(t[self.helper_reg_ids[name] as usize]);
                            }
                            if h.flags & call_flags::NO_WRITE_GLOBALS == 0 {
                                for name in writes.names(block, op) {
                                    let id = self.helper_reg_ids[name] as usize;
                                    t[id] = Val::Unknown;
                                    written[id] = true;
                                }
                            }
                        } else if !self.helper_regs_complete {
                            for (id, value) in t[..self.nb_globals].iter_mut().enumerate() {
                                let id = id as TempId;
                                if block.temp(id).kind != TempKind::Global || id == self.sp {
                                    continue;
                                }
                                if let ReturnConvention::LinkRegister(name) = self.spec.ret
                                    && block.temp(id).name.as_deref() == Some(name)
                                {
                                    continue;
                                }
                                facts.use_val(*value);
                                if h.flags & call_flags::NO_WRITE_GLOBALS == 0 {
                                    *value = Val::Unknown;
                                    written[id as usize] = true;
                                }
                            }
                        }
                    }
                }
                Opcode::Mov => t[out[0] as usize] = t[inp[0] as usize],
                Opcode::Add | Opcode::Sub => {
                    let (a, b) = (t[inp[0] as usize], t[inp[1] as usize]);
                    let add = op.opcode == Opcode::Add;
                    t[out[0] as usize] = match (a, b) {
                        (Val::Const(x), Val::Const(y)) => Val::Const(
                            if add {
                                x.wrapping_add(y)
                            } else {
                                x.wrapping_sub(y)
                            } & m,
                        ),
                        (Val::Entry(g, o), Val::Const(y)) => {
                            let y = sext(y, op.ty);
                            Val::Entry(
                                g,
                                if add {
                                    o.wrapping_add(y)
                                } else {
                                    o.wrapping_sub(y)
                                },
                            )
                        }
                        (Val::Const(x), Val::Entry(g, o)) if add => {
                            Val::Entry(g, o.wrapping_add(sext(x, op.ty)))
                        }
                        _ => {
                            facts.use_val(a);
                            facts.use_val(b);
                            Val::Unknown
                        }
                    };
                }
                Opcode::QemuLd => {
                    let size = MemOp(k[0]).bytes();
                    let addr = t[inp[0] as usize];
                    t[out[0] as usize] = match addr {
                        Val::Entry(g, off) if g == self.sp => {
                            note_slot(facts, off, size);
                            match stack.get(&off) {
                                Some(&v) if is_fp(v) => {
                                    read_env(stack, off, size).unwrap_or(Val::Unknown)
                                }
                                Some(&v) if u64::from(size) == self.word => v,
                                Some(&v) => {
                                    facts.use_val(v);
                                    Val::Unknown
                                }
                                None => {
                                    let end = off + i64::from(size);
                                    let lo = off - self.word as i64 + 1;
                                    let partial: Vec<Val> =
                                        stack.range(lo..end).map(|(_, &v)| v).collect();
                                    for v in &partial {
                                        facts.use_val(*v);
                                    }
                                    if partial.is_empty() && off >= self.arg_base {
                                        facts.stack_args.insert(off);
                                    }
                                    Val::Unknown
                                }
                            }
                        }
                        other => {
                            facts.use_val(other);
                            Val::Unknown
                        }
                    };
                }
                Opcode::QemuLd2 => {
                    // A 128-bit guest load consumed as `lo:hi` halves: when
                    // both halves derive from the two result registers of
                    // one callee, that is pair evidence (one 128-bit value
                    // across `rax:rdx`/`x0:x1`), never two live registers.
                    // (QEMU emits no `QemuLd2` for FP lanes; this arm is
                    // integer-pair only. FP pairs grade through lane hits.)
                    let _ = k;
                    for &o in out {
                        t[o as usize] = Val::Unknown;
                    }
                }
                Opcode::QemuSt => {
                    let size = MemOp(k[0]).bytes();
                    let (val, addr) = (t[inp[0] as usize], t[inp[1] as usize]);
                    match addr {
                        Val::Entry(g, off) if g == self.sp => {
                            // The return address a call pushes belongs to
                            // the callee's frame, not ours.
                            if val != Val::Const(bb.end()) || !calls_out(bb) {
                                note_slot(facts, off, size);
                            }
                            let end = off + i64::from(size);
                            stack.retain(|&s, v| {
                                s + if is_fp(*v) { 4 } else { self.word as i64 } <= off || s >= end
                            });
                            if is_fp(val) && size >= 4 {
                                write_env(stack, off, size, val);
                            } else if u64::from(size) == self.word {
                                stack.insert(off, val);
                            } else {
                                facts.use_val(val);
                            }
                        }
                        other => {
                            // Stores through the conventional `sret` slot's
                            // entry value are hidden-result evidence
                            // (widths recorded); stores through any other
                            // register are plain uses. This alone never
                            // proves `Memory`: memset/setters also store
                            // through their first argument and return it.
                            if let Some(sret) = self.sret
                                && matches!(other, Val::Entry(g, _) if g == sret)
                            {
                                facts.sret_stores.push(size);
                            }
                            facts.use_val(other);
                            facts.use_val(val);
                        }
                    }
                }
                Opcode::QemuSt2 => {
                    // A 128-bit guest store of a `lo:hi` pair: plain uses.
                    // (Integer-pair only, like `QemuLd2`.)
                    for &a in inp {
                        facts.use_val(t[a as usize]);
                    }
                }
                Opcode::Ld8u
                | Opcode::Ld8s
                | Opcode::Ld16u
                | Opcode::Ld16s
                | Opcode::Ld32u
                | Opcode::Ld32s
                | Opcode::Ld => {
                    let width = match op.opcode {
                        Opcode::Ld8u | Opcode::Ld8s => 1,
                        Opcode::Ld16u | Opcode::Ld16s => 2,
                        Opcode::Ld32u | Opcode::Ld32s => 4,
                        _ => op.ty.bits() / 8,
                    };
                    t[out[0] as usize] = self
                        .env_offset(block, t[inp[0] as usize], k[0])
                        .and_then(|off| read_env(env, off, width))
                        .unwrap_or(Val::Unknown);
                }
                Opcode::St8 | Opcode::St16 | Opcode::St32 | Opcode::St => {
                    let width = match op.opcode {
                        Opcode::St8 => 1,
                        Opcode::St16 => 2,
                        Opcode::St32 => 4,
                        _ => op.ty.bits() / 8,
                    };
                    if let Some(off) = self.env_offset(block, t[inp[1] as usize], k[0]) {
                        write_env(env, off, width, t[inp[0] as usize]);
                    }
                    facts.use_val(t[inp[0] as usize]);
                }
                _ => {
                    // Constant-fold what exit classification also folds;
                    // everything else computes with its inputs.
                    let folded = match (
                        op.opcode,
                        inp.first().map(|&a| t[a as usize]),
                        inp.get(1).map(|&b| t[b as usize]),
                    ) {
                        (Opcode::And, Some(Val::Const(x)), Some(Val::Const(y))) => {
                            Some(Val::Const(x & y))
                        }
                        (Opcode::Or, Some(Val::Const(x)), Some(Val::Const(y))) => {
                            Some(Val::Const(x | y))
                        }
                        (Opcode::Xor, Some(Val::Const(x)), Some(Val::Const(y))) => {
                            Some(Val::Const(x ^ y))
                        }
                        (Opcode::Extract, Some(Val::Const(x)), None) => {
                            Some(Val::Const((x >> k[0]) & low_bits(k[1])))
                        }
                        (Opcode::ExtuI32I64 | Opcode::ExtrlI64I32, Some(Val::Const(x)), None) => {
                            Some(Val::Const(x & 0xffff_ffff))
                        }
                        (
                            Opcode::ExtuI32I64 | Opcode::ExtrlI64I32,
                            Some(Val::FpTyped(LaneType::Float32)),
                            None,
                        ) => {
                            // AArch64 stores scalar FP results in a widened
                            // integer TCG slot. Its low 32 payload bits are
                            // unchanged; widening is not numeric FP conversion.
                            Some(Val::FpTyped(LaneType::Float32))
                        }
                        (Opcode::ExtI32I64, Some(Val::Const(x)), None) => {
                            Some(Val::Const(x as u32 as i32 as i64 as u64))
                        }
                        _ => None,
                    };
                    if folded.is_none() {
                        for &a in inp {
                            facts.use_val(t[a as usize]);
                        }
                    }
                    for &o in out {
                        t[o as usize] = folded.unwrap_or(Val::Unknown);
                    }
                }
            }
        }
        // Fell off the end (should not happen in translated code): leave.
        if let Some((t, stack, written, env)) = cur {
            outs.push(Out::Leave(self.to_state(&t, stack, written, env)));
        }
        outs
    }

    fn to_state(
        &self,
        temps: &[Val],
        stack: BTreeMap<i64, Val>,
        written: Vec<bool>,
        env: BTreeMap<i64, Val>,
    ) -> State {
        State {
            regs: temps[..self.nb_globals].to_vec(),
            stack,
            written,
            env,
        }
    }

    fn env_offset(&self, block: &Block, value: Val, displacement: u64) -> Option<i64> {
        match value {
            Val::Entry(g, off) if Some(g) == self.env || block.temp(g).kind == TempKind::Fixed => {
                off.checked_add(displacement as i64)
            }
            _ => None,
        }
    }

    fn fp_use(&self, value: Val, ty: LaneType, part: u32, facts: &mut Facts) {
        match value {
            Val::FpEntry(lane, offset) => {
                facts.fp_hits.push((
                    lane,
                    if offset == part {
                        ty
                    } else {
                        LaneType::Vector128
                    },
                    false,
                ));
            }
            Val::FpRet(callee, lane, offset) => {
                facts.use_fp_ret(
                    callee,
                    lane,
                    if offset == part {
                        ty
                    } else {
                        LaneType::Vector128
                    },
                );
            }
            other => facts.use_val(other),
        }
    }

    /// Helpers establish representation; copies through CPU state and
    /// guest stack cells merely carry the value's provenance.
    fn fp_helper(
        &self,
        block: &Block,
        op: &Op,
        temps: &mut [Val],
        env: &mut BTreeMap<i64, Val>,
        facts: &mut Facts,
    ) {
        let inputs = block.inputs(op);
        let outputs = block.outputs(op);
        let name = block.helper(op).name.as_str();
        if name == "memset" {
            if let (Some(&p), Some(&n)) = (inputs.first(), inputs.get(2))
                && let (Some(off), Val::Const(size)) = (
                    self.env_offset(block, temps[p as usize], 0),
                    temps[n as usize],
                )
                && let Some(end) = off.checked_add_unsigned(size)
            {
                env.retain(|&at, _| at + 4 <= off || at >= end);
            }
            for &out in outputs {
                temps[out as usize] = Val::Unknown;
            }
            return;
        }
        let types = fp_helper_types(name);
        let vector = name.starts_with("gvec_");
        let arm = name.starts_with("vfp_") || name.starts_with("float");
        let compare = name.starts_with("ucomi") || name.starts_with("comi");
        if let Some((read, write)) = types {
            let first_source = if vector {
                1
            } else if arm {
                0
            } else if compare || write.is_none() {
                1
            } else {
                2
            };
            for &input in &inputs[first_source.min(inputs.len())..] {
                let value = temps[input as usize];
                if let Some(off) = self.env_offset(block, value, 0) {
                    if let Some(ty) = read {
                        for part in (0..lane_width(ty)).step_by(4) {
                            let v = env
                                .get(&(off + i64::from(part)))
                                .copied()
                                .unwrap_or(Val::Unknown);
                            self.fp_use(v, ty, part, facts);
                        }
                    }
                } else if let Some(ty) = read {
                    self.fp_use(value, ty, 0, facts);
                }
            }
            if let Some(ty) = write
                && !arm
            {
                let destination = if vector {
                    inputs.first()
                } else {
                    inputs.get(1)
                };
                if let Some(&p) = destination
                    && let Some(off) = self.env_offset(block, temps[p as usize], 0)
                {
                    write_env(env, off, lane_width(ty), Val::FpTyped(ty));
                }
            }
            for &out in outputs {
                temps[out as usize] = if arm {
                    write.map_or(Val::Unknown, Val::FpTyped)
                } else {
                    Val::Unknown
                };
            }
        } else {
            // Unknown pointer-writing SIMD helpers cannot leave a stale
            // typed result. Register bit-pattern traffic remains untyped.
            if !arm
                && let Some(&p) = inputs.get(1)
                && let Some(off) = self.env_offset(block, temps[p as usize], 0)
            {
                for part in (0..16).step_by(4) {
                    facts.use_val(env.get(&(off + part)).copied().unwrap_or(Val::Unknown));
                }
                write_env(env, off, 16, Val::Unknown);
            }
            for &out in outputs {
                temps[out as usize] = Val::Unknown;
            }
        }
    }

    fn lane_offset(&self, lane: u32, results: bool) -> Option<i64> {
        let banks = if results {
            self.fp_results
        } else {
            self.fp_lanes
        };
        for bank in banks {
            if lane >= bank.slot && lane - bank.slot < bank.count {
                return Some(bank.base + i64::from(lane - bank.slot) * bank.stride as i64);
            }
        }
        None
    }

    fn result_lanes(&self) -> impl Iterator<Item = (u32, i64)> + '_ {
        self.fp_results.iter().flat_map(|bank| {
            (0..bank.count)
                .map(move |i| (bank.slot + i, bank.base + i64::from(i) * bank.stride as i64))
        })
    }

    /// Follow one exit of a block of `f` in state `st`.
    #[allow(clippy::too_many_arguments)]
    fn exit(
        &self,
        f: &Function,
        bb: &BasicBlock,
        kind: Option<ExitKind>,
        st: State,
        abis: &BTreeMap<u64, FunctionAbi>,
        facts: &mut Facts,
        outs: &mut Vec<Out>,
    ) {
        let local = |t: u64| f.blocks.contains(&t);
        match kind {
            Some(ExitKind::Jump(t)) if local(t) => outs.push(Out::Block(t, st)),
            Some(ExitKind::Jump(t)) => {
                outs.push(Out::Leave(self.call(f.entry, Some(t), st, abis, facts)))
            }
            Some(ExitKind::Call { target, ret }) => {
                let after = self.call(f.entry, Some(target), st, abis, facts);
                if local(ret) {
                    outs.push(Out::Block(ret, after));
                }
            }
            Some(ExitKind::IndirectCall { ret, .. }) => {
                // The callee address itself is computed from our state.
                facts.use_val(st.regs[self.pc as usize]);
                if local(ret) {
                    if let Some(targets) = self.cfg.indirect_calls.get(&bb.pc()) {
                        for &target in &targets.targets {
                            if self.cfg.functions.get(&target).is_some_and(|f| !f.returns) {
                                continue;
                            }
                            let after = self.call(f.entry, Some(target), st.clone(), abis, facts);
                            outs.push(Out::Block(ret, after));
                        }
                    }
                    if self
                        .cfg
                        .indirect_calls
                        .get(&bb.pc())
                        .is_none_or(|ts| !ts.complete)
                    {
                        let after = self.call(f.entry, None, st, abis, facts);
                        outs.push(Out::Block(ret, after));
                    }
                }
            }
            Some(ExitKind::Syscall { next }) => {
                for &a in written_prefix(&self.syscall_args, &st) {
                    facts.use_val(st.regs[a as usize]);
                }
                let mut after = st;
                after.written.fill(false);
                for g in 0..self.nb_globals as TempId {
                    if self.syscall_clobbers.contains(&g) {
                        after.regs[g as usize] = Val::Unknown;
                    }
                }
                if local(next) {
                    outs.push(Out::Block(next, after));
                }
            }
            Some(ExitKind::IndirectJump { .. }) => match self.cfg.jump_tables.get(&bb.pc()) {
                Some(targets) => {
                    facts.use_val(st.regs[self.pc as usize]);
                    for &t in targets {
                        if local(t) {
                            outs.push(Out::Block(t, st.clone()));
                        } else {
                            outs.push(Out::Leave(self.call(
                                f.entry,
                                Some(t),
                                st.clone(),
                                abis,
                                facts,
                            )));
                        }
                    }
                    if self.cfg.incomplete_jump_tables.contains(&bb.pc()) {
                        outs.push(Out::Leave(self.call(f.entry, None, st, abis, facts)));
                    }
                }
                // Unknown destination: a tail call through a pointer.
                None => {
                    facts.use_val(st.regs[self.pc as usize]);
                    outs.push(Out::Leave(self.call(f.entry, None, st, abis, facts)))
                }
            },
            Some(ExitKind::Return) => outs.push(Out::Leave(st)),
            // An exit that classification did not reach: nothing known.
            None => {}
        }
    }

    /// State after calling `callee` (unknown code if `None` or not lifted)
    /// from state `st`, recording the uses of its arguments.
    fn call(
        &self,
        caller: u64,
        callee: Option<u64>,
        mut st: State,
        abis: &BTreeMap<u64, FunctionAbi>,
        facts: &mut Facts,
    ) -> State {
        // Import stubs (PLT entries) stand for unknown code.
        let known = callee
            .filter(|&c| self.cfg.functions.contains_key(&c) && self.cfg.stub_import(c).is_none());
        let abi = known.and_then(|c| abis.get(&c));
        let known_args: Vec<TempId>;
        let args: &[TempId] = match (known, abi) {
            (_, Some(a)) => {
                known_args = a.args.iter().copied().collect();
                &known_args
            }
            // Not analysed yet (first round): optimistically reads nothing
            // and keeps everything, so recursion converges from above.
            (Some(_), None) => &[],
            (None, None) => written_prefix(&self.unknown_args, &st),
        };
        let keeps = |g: TempId| match (known, abi) {
            // A callee whose stack could not be followed (realignment,
            // alloca) has no trustworthy preserved set: assume the convention.
            (_, Some(a)) if !a.frame.balanced => !self.unknown_clobbers.contains(&g),
            (_, Some(a)) => a.preserved.contains(&g),
            (Some(_), None) => true,
            (None, None) => !self.unknown_clobbers.contains(&g),
        };
        for &a in args {
            facts.use_val(st.regs[a as usize]);
        }
        if let Some(a) = abi {
            for &lane in &a.fp_args {
                if let Some(off) = self.lane_offset(lane, false) {
                    let value = st.env.get(&off).copied().unwrap_or(Val::Unknown);
                    if let Some(&ty) = a.fp_arg_types.get(&lane) {
                        self.fp_use(value, ty, 0, facts);
                    } else {
                        facts.use_val(value);
                    }
                }
            }
        }
        // Only live values at this call contribute caller evidence.
        let established: BTreeSet<(u32, LaneType)> = self
            .fp_lanes
            .iter()
            .flat_map(|bank| {
                (0..bank.count)
                    .map(move |i| (bank.slot + i, bank.base + i64::from(i) * bank.stride as i64))
            })
            .filter_map(|(lane, off)| {
                let ty = match st.env.get(&off).copied().unwrap_or(Val::Unknown) {
                    Val::FpTyped(ty) => Some(ty),
                    Val::FpEntry(origin, _) => abis
                        .get(&caller)
                        .and_then(|a| a.fp_arg_types.get(&origin))
                        .copied(),
                    Val::FpRet(callee, origin, _) => abis
                        .get(&callee)
                        .and_then(|a| a.fp_ret_types.get(&origin))
                        .copied(),
                    _ => None,
                };
                ty.map(|ty| (lane, ty))
            })
            .collect();
        match known {
            Some(c) => {
                facts.call_writes.push((
                    c,
                    self.unknown_args
                        .iter()
                        .copied()
                        .filter(|&r| st.written[r as usize])
                        .collect(),
                ));
                facts.fp_call_writes.push((c, established));
            }
            None => {
                facts.passthrough.extend(
                    self.unknown_args
                        .iter()
                        .copied()
                        .filter(|&r| st.regs[r as usize] == Val::Entry(r, 0)),
                );
                for bank in self.fp_lanes {
                    for i in 0..bank.count {
                        let lane = bank.slot + i;
                        let off = bank.base + i64::from(i) * bank.stride as i64;
                        if st.env.get(&off) == Some(&Val::FpEntry(lane, 0)) {
                            for ty in [LaneType::Float32, LaneType::Float64, LaneType::Vector128] {
                                facts.fp_passthrough.insert((lane, ty));
                            }
                        }
                    }
                }
            }
        }

        // A pointer into our frame handed over: the callee may write
        // anything there except register save slots.
        let escaped = args
            .iter()
            .any(|&a| self.is_stack_addr(st.regs[a as usize]))
            || st.stack.values().any(|&v| self.is_stack_addr(v));
        if escaped {
            st.stack
                .retain(|_, v| matches!(v, Val::Entry(g, 0) if *g != self.sp));
        }

        let sp = st.regs[self.sp as usize];
        let sp_after = match sp {
            Val::Entry(g, k) if self.pushes_return => Val::Entry(g, k + self.word as i64),
            other => other,
        };
        // The callee's frame is gone, and it may have written its home
        // space.
        if let Val::Entry(_, k) = sp_after {
            st.stack.retain(|&off, _| off >= k + self.home);
        }
        for g in 0..self.nb_globals as TempId {
            st.regs[g as usize] = if g == self.sp {
                sp_after
            } else if g == self.pc {
                Val::Unknown
            } else if keeps(g) {
                st.regs[g as usize]
            } else {
                match known {
                    Some(c) => Val::Ret(c, g),
                    None => Val::Unknown,
                }
            };
        }
        st.env.clear();
        if let Some(callee) = known {
            for (lane, off) in self.result_lanes() {
                write_env(&mut st.env, off, 16, Val::FpRet(callee, lane, 0));
            }
        }
        st.written.fill(false);
        st
    }

    fn is_stack_addr(&self, v: Val) -> bool {
        matches!(v, Val::Entry(g, _) if g == self.sp)
    }
}

type Local = (Vec<Val>, BTreeMap<i64, Val>, Vec<bool>, BTreeMap<i64, Val>);

fn join_local(a: &mut Local, b: &Local) {
    for (x, y) in a.0.iter_mut().zip(&b.0) {
        if x != y {
            *x = Val::Unknown;
        }
    }
    a.1.retain(|k, v| b.1.get(k) == Some(v));
    for (x, &y) in a.2.iter_mut().zip(&b.2) {
        *x |= y;
    }
    join_env(&mut a.3, &b.3);
}

fn merge(pending: &mut HashMap<u64, Local>, label: u64, st: Local) {
    match pending.get_mut(&label) {
        Some(p) => join_local(p, &st),
        None => {
            pending.insert(label, st);
        }
    }
}
fn is_fp(value: Val) -> bool {
    matches!(
        value,
        Val::FpEntry(..) | Val::FpRet(..) | Val::FpTyped(_) | Val::FpConflict
    )
}

fn lane_width(ty: LaneType) -> u32 {
    match ty {
        LaneType::Float32 => 4,
        LaneType::Float64 => 8,
        LaneType::Vector128 => 16,
    }
}

fn shifted(value: Val, bytes: u32) -> Val {
    match value {
        Val::FpEntry(lane, part) => Val::FpEntry(lane, part + bytes),
        Val::FpRet(callee, lane, part) => Val::FpRet(callee, lane, part + bytes),
        Val::FpTyped(_) | Val::FpConflict => value,
        Val::Const(v) => Val::Const(if bytes < 8 { v >> (8 * bytes) } else { 0 }),
        _ if bytes == 0 => value,
        _ => Val::Unknown,
    }
}

fn read_env(env: &BTreeMap<i64, Val>, off: i64, bytes: u32) -> Option<Val> {
    let value = *env.get(&off)?;
    ((0..bytes)
        .step_by(4)
        .all(|part| env.get(&(off + i64::from(part))).copied() == Some(shifted(value, part))))
    .then_some(value)
}

fn write_env(env: &mut BTreeMap<i64, Val>, off: i64, bytes: u32, value: Val) {
    let Some(end) = off.checked_add(i64::from(bytes)) else {
        env.clear();
        return;
    };
    env.retain(|&at, _| at + 4 <= off || at >= end);
    if off % 4 == 0 && bytes >= 4 {
        for part in (0..bytes).step_by(4) {
            let value = shifted(value, part);
            if value != Val::Unknown {
                env.insert(off + i64::from(part), value);
            }
        }
    }
}

fn join_env(a: &mut BTreeMap<i64, Val>, b: &BTreeMap<i64, Val>) -> bool {
    let mut changed = false;
    a.retain(|key, value| {
        let other = b.get(key).copied().unwrap_or(Val::Unknown);
        if *value == other {
            return true;
        }
        if matches!(
            (*value, other),
            (Val::FpTyped(_), Val::FpTyped(_))
                | (Val::FpConflict, Val::FpTyped(_))
                | (Val::FpTyped(_), Val::FpConflict)
        ) {
            changed |= *value != Val::FpConflict;
            *value = Val::FpConflict;
            true
        } else {
            changed = true;
            false
        }
    });
    changed
}

/// Source and destination representations are separate for conversions.
fn fp_helper_types(name: &str) -> Option<(Option<LaneType>, Option<LaneType>)> {
    use LaneType::*;
    if name.starts_with("gvec_f") {
        return Some((Some(Vector128), Some(Vector128)));
    }
    if let Some(base) = name.strip_prefix("vfp_") {
        let width = |c| match c {
            's' => Some(Float32),
            'd' => Some(Float64),
            _ => None,
        };
        if let Some(pair) = base.strip_prefix("fcvt") {
            let mut chars = pair.chars();
            let write = width(chars.next()?);
            let read = width(chars.next()?);
            return Some((read, write));
        }
        let ty = width(base.chars().last()?)?;
        if [
            "add", "sub", "mul", "div", "sqrt", "neg", "abs", "min", "max", "cmp", "rint", "round",
            "to",
        ]
        .iter()
        .any(|p| base.starts_with(p))
        {
            let write = if base.starts_with("cmp") || base.starts_with("to") {
                None
            } else {
                Some(ty)
            };
            return Some((Some(ty), write));
        }
        return None;
    }
    if name.ends_with("_ymm") || name.ends_with("_zmm") {
        return None;
    }
    let base = name.strip_suffix("_xmm").unwrap_or(name);
    let scalar = |s: &str| {
        if s.ends_with("ss") {
            Some(Float32)
        } else if s.ends_with("sd") {
            Some(Float64)
        } else {
            None
        }
    };
    if base.starts_with("cvt") {
        let (from, to) = base
            .trim_start_matches("cvtt")
            .trim_start_matches("cvt")
            .split_once('2')?;
        let read = match from {
            "ss" => Some(Float32),
            "sd" => Some(Float64),
            _ => None,
        };
        return Some((read, scalar(to)));
    }
    if [
        "add", "sub", "mul", "div", "min", "max", "sqrt", "rcp", "rsqrt", "cmp", "comi", "ucomi",
        "round",
    ]
    .iter()
    .any(|p| base.starts_with(p))
    {
        let ty = scalar(base)
            .or_else(|| (base.ends_with("ps") || base.ends_with("pd")).then_some(Vector128))?;
        return Some((
            Some(ty),
            if base.starts_with("comi") || base.starts_with("ucomi") {
                None
            } else {
                Some(ty)
            },
        ));
    }
    None
}

fn note_slot(facts: &mut Facts, off: i64, size: u32) {
    let e = facts.slots.entry(off).or_insert(0);
    *e = (*e).max(size);
}

fn mask(ty: Type) -> u64 {
    if ty.bits() >= 64 {
        u64::MAX
    } else {
        (1 << ty.bits()) - 1
    }
}

fn sext(v: u64, ty: Type) -> i64 {
    match ty {
        Type::I32 => v as u32 as i32 as i64,
        _ => v as i64,
    }
}

fn low_bits(len: u64) -> u64 {
    if len >= 64 { u64::MAX } else { (1 << len) - 1 }
}

/// The block ends in a call (and so pushes or links its end address).
fn calls_out(bb: &BasicBlock) -> bool {
    bb.exits.iter().any(|x| {
        matches!(
            x.kind,
            ExitKind::Call { .. } | ExitKind::IndirectCall { .. }
        )
    })
}

/// Positional arguments of unknown code: `regs` up to the last one written
/// since entry or the previous call. Registers never touched are taken to be
/// unused rather than forwarded.
fn written_prefix<'r>(regs: &'r [TempId], st: &State) -> &'r [TempId] {
    let n = regs
        .iter()
        .rposition(|&r| st.written[r as usize])
        .map_or(0, |i| i + 1);
    &regs[..n]
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;

    fn with_cfg(bytes: &[u8], f: impl FnOnce(&Cfg, &ContextInfo)) {
        let lib = biara_tcg::Libtcg::load(
            &biara_tcg::Libtcg::find("x86_64").expect("libtcg-x86_64"),
            None,
        )
        .expect("loading libtcg");
        let mut lib = lib.lock();
        let cfg = biara_cfg::recover(
            &mut *lib,
            |pc| (pc >= BASE && pc - BASE < bytes.len() as u64).then_some((bytes, BASE)),
            [BASE],
            &biara_cfg::Options::default(),
        )
        .unwrap();
        f(&cfg, lib.info());
    }

    #[test]
    fn scalar_return_has_a_balanced_known_frame() {
        with_cfg(&[0x31, 0xc0, 0xc3], |cfg, info| {
            // xor eax,eax; ret
            let abis = analyze(cfg, info).unwrap();
            let abi = &abis[&BASE];
            assert!(abi.analysis.converged);
            assert!(abi.frame.balanced);
            assert_eq!(abi.frame.sp_at[&BASE], Some(0));
        });
    }

    #[test]
    fn root_result_tracks_input_even_when_rounds_are_exhausted() {
        // mov rax,rdi; ret: the return is the only use of the input.
        with_cfg(&[0x48, 0x89, 0xf8, 0xc3], |cfg, info| {
            let abis = analyze_with_limit(cfg, info, 1).unwrap();
            let abi = &abis[&BASE];
            let reg = |name: &str| {
                info.globals
                    .iter()
                    .position(|g| g.name.as_deref() == Some(name))
                    .unwrap() as TempId
            };
            assert!(abi.returns.contains(&reg("rax")));
            assert!(abi.args.contains(&reg("rdi")));
            assert!(!abi.analysis.converged);
        });
    }

    #[test]
    fn round_exhaustion_does_not_claim_convergence() {
        with_cfg(&[0x31, 0xc0, 0xc3], |cfg, info| {
            let abis = analyze_with_limit(cfg, info, 1).unwrap();
            assert_eq!(
                abis[&BASE].analysis,
                AbiStatus {
                    converged: false,
                    rounds: 1
                }
            );
        });
    }

    #[test]
    fn whole_program_limit_is_reported_for_slow_argument_propagation() {
        // Each caller passes edi untouched to the next; its argument use
        // propagates one call edge per whole-program round from the last leaf.
        let count = MAX_ROUNDS + 4;
        let mut bytes = vec![0xcc; count * 16];
        for i in 0..count - 1 {
            let start = i * 16;
            bytes[start..start + 6].copy_from_slice(&[0xe8, 11, 0, 0, 0, 0xc3]);
        }
        let leaf = (count - 1) * 16;
        bytes[leaf..leaf + 3].copy_from_slice(&[0x89, 0xf8, 0xc3]); // mov eax,edi; ret
        with_cfg(&bytes, |cfg, info| {
            assert_eq!(cfg.functions.len(), count);
            let abis = analyze(cfg, info).unwrap();
            assert!(abis.values().all(|a| a.analysis
                == AbiStatus {
                    converged: false,
                    rounds: MAX_ROUNDS
                }));
        });
    }

    #[test]
    fn realigned_stack_pointer_is_exposed_as_unknown() {
        // and rsp,-16; jmp next; ret. Alignment destroys the entry-relative
        // offset; do not present the next block's SP as a known frame size.
        with_cfg(&[0x48, 0x83, 0xe4, 0xf0, 0xeb, 0, 0xc3], |cfg, info| {
            let abis = analyze(cfg, info).unwrap();
            let abi = &abis[&BASE];
            assert!(abi.analysis.converged);
            assert_eq!(abi.frame.sp_at[&(BASE + 6)], None);
            assert!(!abi.frame.balanced);
        });
    }

    #[test]
    fn noncommutative_double_multiply_names_typed_lanes() {
        // mulsd xmm1,xmm0; movq rax,xmm0; ret. The noncommutative helper
        // names `double` lanes in operand order; the low-quadword move is
        // bit-pattern traffic and must not widen or erase the lane type.
        with_cfg(
            &[0xf2, 0x0f, 0x59, 0xc1, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3],
            |cfg, info| {
                let abis = analyze(cfg, info).unwrap();
                let abi = &abis[&BASE];
                assert!(abi.analysis.converged);
                // Lanes 0 and 1 carry `double` evidence from `mulsd`.
                assert!(abi.fp_args.contains(&0));
                assert_eq!(abi.fp_arg_types.get(&0), Some(&LaneType::Float64));
                assert!(abi.fp_conflicts.is_empty());
                // Old integer facts are untouched: no GPR claims appear.
                assert!(!abi.args.contains(&7));
            },
        );
    }

    #[test]
    fn float_vs_double_width_conflict_stays_raw() {
        // addss xmm0,xmm1 then addsd xmm0,xmm1: lane 0 sees 4-byte and
        // 8-byte evidence on different paths. The lane must conflict and
        // lose its type rather than pick a side.
        with_cfg(
            &[0xf3, 0x0f, 0x58, 0xc1, 0xf2, 0x0f, 0x58, 0xc1, 0xc3],
            |cfg, info| {
                let abis = analyze(cfg, info).unwrap();
                let abi = &abis[&BASE];
                assert!(abi.analysis.converged);
                assert!(abi.fp_conflicts.contains(&0));
                assert!(!abi.fp_arg_types.contains_key(&0));
            },
        );
    }

    #[test]
    fn incompatible_return_consumers_keep_raw_transport() {
        // Two callers interpret the same raw return bits differently.
        // The callee is visited after both consumers in entry order.
        let mut bytes = vec![0xcc; 52];
        bytes[..11].copy_from_slice(&[0xe8, 11, 0, 0, 0, 0xe8, 22, 0, 0, 0, 0xc3]);
        bytes[16..26].copy_from_slice(&[0xe8, 27, 0, 0, 0, 0xf3, 0x0f, 0x58, 0xc1, 0xc3]);
        bytes[32..42].copy_from_slice(&[0xe8, 11, 0, 0, 0, 0xf2, 0x0f, 0x58, 0xc1, 0xc3]);
        bytes[48..].copy_from_slice(&[0x0f, 0x28, 0xc1, 0xc3]); // movaps xmm0,xmm1; ret
        with_cfg(&bytes, |cfg, info| {
            let abis = analyze(cfg, info).unwrap();
            let result = &abis[&(BASE + 48)];
            assert!(result.analysis.converged);
            assert!(result.fp_returns.contains(&0));
            assert!(result.fp_conflicts.contains(&0));
            assert!(!result.fp_ret_types.contains_key(&0));
        });
    }

    #[test]
    fn small_pair_return_needs_two_result_registers() {
        // mov rax,7; mov rdx,9; ret. Two live result registers with no
        // paired-consumption evidence are per-register facts, never an
        // aggregate claim: `ret_class` stays `None`.
        with_cfg(
            &[
                0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x09, 0x00, 0x00, 0x00,
                0xc3,
            ],
            |cfg, info| {
                let abis = analyze(cfg, info).unwrap();
                let abi = &abis[&BASE];
                assert!(abi.analysis.converged);
                assert_eq!(abi.ret_class, None);
            },
        );
    }

    #[test]
    fn memset_shaped_store_and_return_is_not_sret() {
        // mov [rdi],0; mov rax,rdi; ret. A store through the first argument
        // plus returning that same pointer is the memset/setter shape, not
        // proof of a hidden result: `ret_class` stays `None`, and the
        // store widths stay explicit evidence rather than a Memory claim.
        with_cfg(
            &[
                0x48, 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xf8, 0xc3,
            ],
            |cfg, info| {
                let abis = analyze(cfg, info).unwrap();
                let abi = &abis[&BASE];
                assert!(abi.analysis.converged);
                assert_eq!(abi.ret_class, None);
            },
        );
    }

    #[test]
    fn fp_to_int_conversion_returns_integer_not_float() {
        // cvttsd2si rax,xmm0; ret. The FP helper reads lane 0 (argument
        // evidence), but the conversion's integer destination is an explicit
        // consumer-visible GPR computation on every path: the root default
        // must pick the integer return, not an FP lane, even though `addsd`
        // traffic would leave a stale typed lane behind.
        // cvttsd2si rax,xmm0 is f2 0f 2c c0; addsd xmm0,xmm1 is f2 0f 58 c1.
        with_cfg(
            &[0xf2, 0x0f, 0x58, 0xc1, 0xf2, 0x0f, 0x2c, 0xc0, 0xc3],
            |cfg, info| {
                let abis = analyze(cfg, info).unwrap();
                let abi = &abis[&BASE];
                assert!(abi.analysis.converged);
                let reg = |name: &str| {
                    info.globals
                        .iter()
                        .position(|g| g.name.as_deref() == Some(name))
                        .unwrap() as TempId
                };
                assert!(abi.returns.contains(&reg("rax")));
                assert!(
                    abi.fp_returns.is_empty(),
                    "stale FP lane must not outrank explicit GPR: {abi:?}"
                );
                assert!(abi.fp_ret_types.is_empty());
            },
        );
    }

    #[test]
    fn genuine_fp_root_keeps_default_fp_result() {
        // addsd xmm0,xmm1; ret. No GPR computation touches the result
        // register: the uncalled root's established FP lane is the return.
        with_cfg(&[0xf2, 0x0f, 0x58, 0xc1, 0xc3], |cfg, info| {
            let abis = analyze(cfg, info).unwrap();
            let abi = &abis[&BASE];
            assert!(abi.analysis.converged);
            let reg = |name: &str| {
                info.globals
                    .iter()
                    .position(|g| g.name.as_deref() == Some(name))
                    .unwrap() as TempId
            };
            assert!(!abi.returns.contains(&reg("rax")));
            assert!(abi.fp_returns.contains(&0));
            assert_eq!(abi.fp_ret_types.get(&0), Some(&LaneType::Float64));
        });
    }

    #[test]
    fn mixed_root_paths_keep_explicit_integer_and_fp_results() {
        // addsd xmm0,xmm1; test rdi,rdi; je fp_only; mov rax,rdi; ret;
        // fp_only: ret. No caller chooses a return channel for this root.
        // The explicit integer result on one feasible path cannot be erased
        // by the FP-only path; represent both observed register channels.
        with_cfg(
            &[
                0xf2, 0x0f, 0x58, 0xc1, 0x48, 0x85, 0xff, 0x74, 4, 0x48, 0x89, 0xf8, 0xc3, 0xc3,
            ],
            |cfg, info| {
                let abis = analyze(cfg, info).unwrap();
                let abi = &abis[&BASE];
                let reg = |name: &str| {
                    info.globals
                        .iter()
                        .position(|g| g.name.as_deref() == Some(name))
                        .unwrap() as TempId
                };
                assert!(abi.analysis.converged);
                assert!(abi.returns.contains(&reg("rax")));
                assert!(abi.fp_returns.contains(&0));
                assert_eq!(abi.fp_ret_types.get(&0), Some(&LaneType::Float64));
            },
        );
    }
}
