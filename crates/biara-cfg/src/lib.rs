//! Control-flow recovery: basic blocks, their exits, and functions.
//!
//! Blocks are libtcg translation blocks cut so that no block runs over the
//! start of another (re-translating with a smaller instruction budget when a
//! branch lands inside an existing block). Functions are the blocks reachable
//! from an entry through intra-procedural exits. A call's return site belongs
//! to the caller when a possible callee may return; exhaustive nonreturning
//! indirect target sets cut that continuation, but partial sets cannot. That
//! and the set of functions are computed to a fixpoint. `Cfg::issues` reports
//! unknown non-import edges, translation failures, and recovery budget limits.
//! With `Options::discovery`, code pointers (from data and constants recovered
//! code materialises) that can be function entries become functions too,
//! until none are left.
//! `Options::function_starts` are metadata instruction boundaries: a decode
//! running across one (junk behind an opaque branch, as obfuscators emit)
//! becomes a translation failure instead of absorbing the next function.
//!
//! A `RecoveryBackend` can prefetch independent translations and checkpoint
//! the graph without sharing QEMU state. Entry blocks get budget priority;
//! waves advance one block per function across at most 64 independent frontiers.
//! Predictable re-cuts and direct-transfer stub/callee probes join these batches;
//! eager classification probes must not turn the frontier into serial translation.
//! Code-pointer candidates use bounded speculative batches too. Sorted
//! coordinator acceptance rechecks coverage, so a prefetched interior label
//! cannot become a function just because its translation succeeded.
//! Canonical splitting and ownership stay on the coordinator. Structural changes
//! invalidate all functions; with stable layout, only changed functions and their
//! call/tail-call dependents are revisited until returnability converges.
//!
//! Blocks are immutable Arc versions, shared by resolution views and checkpoint
//! caches without copying IR. Self-contained codecs serve worker IPC; manifest
//! codecs store metadata and exact block artifact identities separately.

mod arch;
mod exits;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Range,
    sync::Arc,
};

use biara_tcg::{Block, Helper, Libtcg, TranslationRequest, Translator};

pub use arch::{
    ArchSpec, CallConv, FpLane, FpState, HelperRegs, RegSet, ReturnClass, ReturnConvention,
    SyscallHelper, spec,
};
mod snapshot;
pub use snapshot::BlockId;

pub trait RecoveryBackend: Translator {
    fn checkpoint_cfg(&mut self, _cfg: &Cfg) -> Result<(), Error> {
        Ok(())
    }
}

impl RecoveryBackend for Libtcg {}
pub use exits::{Exit, ExitKind, insn_pcs};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no control-flow spec for {arch} on {os}")]
    Arch { arch: String, os: &'static str },
    #[error("{arch}: context lacks global {name}")]
    Global { arch: String, name: &'static str },
    #[error("analysis backend: {0}")]
    Backend(String),
}

#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub block: Block,
    /// Guest pcs of its instructions.
    pub insns: Vec<u64>,
    pub exits: Vec<Exit>,
    /// Constants the block leaves in registers at its exits or stores to
    /// memory (link values excepted): candidate code pointers.
    pub constants: Vec<u64>,
}

impl BasicBlock {
    pub fn pc(&self) -> u64 {
        self.block.pc
    }

    pub fn end(&self) -> u64 {
        self.block.end()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Function {
    pub entry: u64,
    /// Block start addresses, entry included.
    pub blocks: BTreeSet<u64>,
    /// Direct and statically recovered indirect call targets.
    pub calls: BTreeSet<u64>,
    /// Functions entered by a jump (tail calls, shared epilogues).
    pub tail_calls: BTreeSet<u64>,
    /// May return to its caller (has a return, an unresolved indirect jump,
    /// or tail-calls a function that may return).
    pub returns: bool,
}

/// Statically recovered targets of an indirect call. Candidate targets are
/// useful even when other destinations remain possible.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IndirectTargets {
    pub targets: BTreeSet<u64>,
    pub complete: bool,
}

/// Recovery budgets and whether they prevented complete analysis. Resolver
/// stages fill their own fields; block recovery records its translation budget.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryStatus {
    pub block_limit_reached: bool,
    pub block_limit: usize,
    pub resolution_limit_reached: bool,
    pub resolution_rounds: usize,
    pub table_limit_sites: BTreeSet<u64>,
    pub table_entry_limit: u64,
    pub callback_limit_reached: bool,
    pub callback_depth_limit: usize,
    pub callback_state_limit: usize,
}

/// A fact preventing recovery from being considered complete. Addresses of
/// indirect transfers are block starts, matching the resolver maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CfgIssue<'a> {
    TranslationFailure {
        address: u64,
        reason: &'a str,
    },
    UnknownIndirectCall {
        address: u64,
    },
    UnknownIndirectJump {
        address: u64,
    },
    BlockLimit {
        limit: usize,
    },
    ResolutionLimit {
        rounds: usize,
    },
    TableLimit {
        address: u64,
        entry_limit: u64,
    },
    CallbackLimit {
        depth_limit: usize,
        state_limit: usize,
    },
}

#[derive(Debug, Default)]
pub struct Cfg {
    /// The operating system the code was built for (`Options::os`).
    pub os: &'static str,
    /// Immutable versions: re-cuts replace the Arc; mutation uses Arc::make_mut.
    pub blocks: BTreeMap<u64, Arc<BasicBlock>>,
    pub functions: BTreeMap<u64, Function>,
    /// Targets that could not be translated, with the reason.
    pub unresolved: BTreeMap<u64, String>,
    /// Known targets of indirect jumps, by the address of the jumping block
    /// (from `Options::jump_tables`).
    pub jump_tables: BTreeMap<u64, BTreeSet<u64>>,
    /// Jump enumerations that may omit destinations, even when some are known.
    pub incomplete_jump_tables: BTreeSet<u64>,
    /// Indirect call targets, keyed by the address of the calling block.
    pub indirect_calls: BTreeMap<u64, IndirectTargets>,
    /// Imports by pointer slot (from `Options::imports`).
    pub imports: BTreeMap<u64, String>,
    /// Function entries found as code pointers (`Options::discovery`).
    pub discovered: BTreeSet<u64>,
    pub recovery: RecoveryStatus,
}

impl Cfg {
    /// Translation failures, unresolved non-import transfers, and exhausted
    /// recovery budgets. A partial target set does not resolve an unknown edge.
    pub fn issues(&self) -> impl Iterator<Item = CfgIssue<'_>> {
        let failures = self
            .unresolved
            .iter()
            .map(|(&address, reason)| CfgIssue::TranslationFailure { address, reason });
        let unknowns = self.blocks.iter().flat_map(|(&address, block)| {
            let call = block.exits.iter().any(|exit| match exit.kind {
                ExitKind::IndirectCall { slot, .. } => {
                    !slot.is_some_and(|s| self.imports.contains_key(&s))
                        && !self
                            .indirect_calls
                            .get(&address)
                            .is_some_and(|t| t.complete)
                }
                _ => false,
            });
            let jump = block.exits.iter().any(|exit| match exit.kind {
                ExitKind::IndirectJump { slot } => {
                    !slot.is_some_and(|s| self.imports.contains_key(&s))
                        && (self.incomplete_jump_tables.contains(&address)
                            || !self.jump_tables.contains_key(&address))
                }
                _ => false,
            });
            [
                call.then_some(CfgIssue::UnknownIndirectCall { address }),
                jump.then_some(CfgIssue::UnknownIndirectJump { address }),
            ]
            .into_iter()
            .flatten()
        });
        let r = &self.recovery;
        let limits = [
            r.block_limit_reached.then_some(CfgIssue::BlockLimit {
                limit: r.block_limit,
            }),
            r.resolution_limit_reached
                .then_some(CfgIssue::ResolutionLimit {
                    rounds: r.resolution_rounds,
                }),
            r.callback_limit_reached.then_some(CfgIssue::CallbackLimit {
                depth_limit: r.callback_depth_limit,
                state_limit: r.callback_state_limit,
            }),
        ]
        .into_iter()
        .flatten();
        failures
            .chain(unknowns)
            .chain(limits)
            .chain(
                r.table_limit_sites
                    .iter()
                    .map(|&address| CfgIssue::TableLimit {
                        address,
                        entry_limit: r.table_entry_limit,
                    }),
            )
    }

    /// The spec for `arch` (the context's QEMU target) on `self.os`.
    pub fn spec(&self, arch: &str) -> Result<&'static ArchSpec, Error> {
        spec(arch, self.os).ok_or_else(|| Error::Arch {
            arch: arch.to_owned(),
            os: self.os,
        })
    }

    /// Every helper called by some block, deduplicated by name.
    pub fn helpers(&self) -> impl Iterator<Item = &Helper> {
        let mut seen = BTreeSet::new();
        self.blocks
            .values()
            .flat_map(|b| &b.block.helpers)
            .filter(move |h| seen.insert(h.name.as_str()))
    }

    /// The import a function forwards to, if it is a one-block stub that
    /// jumps through an import's slot (a PLT entry).
    pub fn stub_import(&self, entry: u64) -> Option<&str> {
        let f = self.functions.get(&entry)?;
        if f.blocks.len() != 1 {
            return None;
        }
        match self.blocks.get(&entry)?.exits.as_slice() {
            [
                Exit {
                    kind: ExitKind::IndirectJump { slot: Some(s) },
                    ..
                },
            ] => self.imports.get(s).map(String::as_str),
            _ => None,
        }
    }
}

/// Imports that never return to their caller.
pub const NORETURN_IMPORTS: &[&str] = &[
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "__assert_fail",
    "__assert_perror_fail",
    "__stack_chk_fail",
    "__chk_fail",
    "__fortify_fail",
    "err",
    "errx",
    "verr",
    "verrx",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "__libc_start_main",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "_Unwind_Resume",
    "_ZSt9terminatev",
    "_ZSt17__throw_bad_allocv",
    "_ZSt20__throw_length_errorPKc",
    "_ZSt24__throw_out_of_range_fmtPKcz",
];

pub struct Options {
    /// The operating system the code was built for (`arch::spec`):
    /// `biara_loader::Image::os`.
    pub os: &'static str,
    /// Stop translating after this many blocks.
    pub max_blocks: usize,
    /// Resolved indirect jumps: block address -> possible targets. These
    /// become intra-procedural edges (or tail calls, for function entries).
    pub jump_tables: BTreeMap<u64, BTreeSet<u64>>,
    /// Sites whose known jump targets are not exhaustive.
    pub incomplete_jump_tables: BTreeSet<u64>,
    /// Resolved or candidate indirect callees, keyed by calling block.
    pub indirect_calls: BTreeMap<u64, IndirectTargets>,
    /// Imported symbols by pointer slot (`biara_loader::Image::imports`).
    /// Calls and jumps through slots of `NORETURN_IMPORTS` do not return.
    pub imports: BTreeMap<u64, String>,
    /// Also recover functions only reached through code pointers.
    pub discovery: Option<Discovery>,
    /// Function starts from image metadata (symbols, unwind/function lists,
    /// exports, loader callbacks). Each is an instruction boundary: a block
    /// whose instructions run across one is a conflicting decode (junk
    /// reached through an opaque branch) and is not recovered.
    pub function_starts: BTreeSet<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            os: "linux",
            max_blocks: 100_000,
            jump_tables: BTreeMap::new(),
            incomplete_jump_tables: BTreeSet::new(),
            indirect_calls: BTreeMap::new(),
            imports: BTreeMap::new(),
            discovery: None,
            function_starts: BTreeSet::new(),
        }
    }
}

/// Where code pointers come from and what they may point at. A candidate
/// (a data pointer, or a `BasicBlock::constants` value of a recovered
/// function) becomes a function entry if it is aligned code, not strictly
/// inside a known function body, not part of a recovered block, not a
/// jump-table target, and translates. Labels whose addresses are data (jump
/// tables, computed gotos) pass until the table that lists them is
/// resolved; `recover_from` then turns them back into blocks.
#[derive(Clone, Debug, Default)]
pub struct Discovery {
    /// Address ranges holding code, sorted by start.
    pub code: Vec<Range<u64>>,
    /// Known function bodies (unwind information, sized symbols), sorted by
    /// start; they may overlap.
    pub extents: Vec<Range<u64>>,
    /// Code addresses stored in data.
    pub data_pointers: BTreeSet<u64>,
}

impl Discovery {
    fn in_code(&self, a: u64) -> bool {
        let i = self.code.partition_point(|r| r.start <= a);
        i > 0 && self.code[i - 1].contains(&a)
    }
}

struct Recovery<'a, 'c, F> {
    lib: &'a mut dyn RecoveryBackend,
    code_at: F,
    spec: &'static ArchSpec,
    regs: arch::Regs,
    opts: &'a Options,
    cfg: Cfg,
    /// Bumped whenever a block is added or re-cut.
    generation: u64,
    /// Per `Discovery::extents` entry, the largest end of it and those
    /// before it.
    extents_end: Vec<u64>,
    /// Code pointers that did not translate.
    rejected: BTreeSet<u64>,
    fatal: Option<biara_tcg::Error>,
    _code: std::marker::PhantomData<&'c [u8]>,
}

struct Exploration {
    function: Function,
    work: Vec<u64>,
    has_return: bool,
}

impl Exploration {
    fn new(entry: u64) -> Self {
        Self {
            function: Function {
                entry,
                ..Default::default()
            },
            work: vec![entry],
            has_return: false,
        }
    }
}

/// Recover functions reachable from `entries`. `code_at(addr)` returns the
/// executable bytes containing `addr` and the address of their first byte.
pub fn recover<'c>(
    lib: &mut dyn RecoveryBackend,
    code_at: impl Fn(u64) -> Option<(&'c [u8], u64)>,
    entries: impl IntoIterator<Item = u64>,
    opts: &Options,
) -> Result<Cfg, Error> {
    recover_from(lib, code_at, entries, opts, Cfg::default())
}

/// `recover`, continuing from an earlier result for the same code (e.g.
/// before more jump tables were known): its blocks are reused instead of
/// re-translated, and its functions seed the fixpoint.
pub fn recover_from<'c>(
    lib: &mut dyn RecoveryBackend,
    code_at: impl Fn(u64) -> Option<(&'c [u8], u64)>,
    entries: impl IntoIterator<Item = u64>,
    opts: &Options,
    previous: Cfg,
) -> Result<Cfg, Error> {
    let info = lib.info();
    let spec = spec(&info.arch, opts.os).ok_or_else(|| Error::Arch {
        arch: info.arch.clone(),
        os: opts.os,
    })?;
    let regs = arch::Regs::resolve(spec, info).ok_or_else(|| Error::Global {
        arch: info.arch.clone(),
        name: spec.sp,
    })?;
    let mut r = Recovery {
        lib,
        code_at,
        spec,
        regs,
        opts,
        cfg: Cfg {
            os: opts.os,
            jump_tables: opts.jump_tables.clone(),
            incomplete_jump_tables: opts.incomplete_jump_tables.clone(),
            indirect_calls: opts.indirect_calls.clone(),
            imports: opts.imports.clone(),
            ..previous
        },
        generation: 0,
        extents_end: opts
            .discovery
            .iter()
            .flat_map(|d| &d.extents)
            .scan(0, |end, r| {
                *end = r.end.max(*end);
                Some(*end)
            })
            .collect(),
        rejected: BTreeSet::new(),
        fatal: None,
        _code: std::marker::PhantomData,
    };
    r.cfg.recovery.block_limit = opts.max_blocks;
    // Recompute returnability from the optimistic bottom, not a cached result:
    // making an indirect target set exhaustive can remove a return path.
    for (&entry, f) in &mut r.cfg.functions {
        *f = Function {
            entry,
            ..Default::default()
        };
    }
    // Code pointers that turned out to be jump-table targets are labels.
    let labels: Vec<u64> = r
        .cfg
        .discovered
        .iter()
        .copied()
        .filter(|e| opts.jump_tables.values().any(|ts| ts.contains(e)))
        .collect();
    for e in labels {
        r.cfg.discovered.remove(&e);
        r.cfg.functions.remove(&e);
    }
    for e in entries {
        r.cfg.functions.entry(e).or_insert_with(|| Function {
            entry: e,
            ..Default::default()
        });
    }
    r.fixpoint()?;
    Ok(r.cfg)
}

impl<'c, F: Fn(u64) -> Option<(&'c [u8], u64)>> Recovery<'_, 'c, F> {
    fn fixpoint(&mut self) -> Result<(), Error> {
        loop {
            let mut dirty: BTreeSet<_> = self.cfg.functions.keys().copied().collect();
            while !dirty.is_empty() {
                let before = (
                    self.generation,
                    self.cfg.functions.len(),
                    self.cfg.unresolved.len(),
                );
                let mut states: BTreeMap<_, _> = dirty
                    .iter()
                    .copied()
                    .map(|entry| (entry, Exploration::new(entry)))
                    .collect();
                let mut ready: VecDeque<_> = states.keys().copied().collect();
                let roots: Vec<_> = ready.iter().copied().collect();
                self.prefetch(&roots)?;
                // Reserve entries before any one body consumes the budget.
                for &entry in &roots {
                    self.ensure(entry);
                }
                if let Some(error) = self.fatal.take() {
                    return Err(Error::Backend(error.to_string()));
                }
                let mut changed = BTreeSet::new();
                let mut wave = Vec::with_capacity(64);
                let mut frontier = Vec::with_capacity(64);
                while !ready.is_empty() {
                    wave.clear();
                    frontier.clear();
                    for _ in 0..64 {
                        let Some(entry) = ready.pop_front() else {
                            break;
                        };
                        let state = &states[&entry];
                        if let Some(&pc) = state.work.last()
                            && !state.function.blocks.contains(&pc)
                        {
                            frontier.push(pc);
                        }
                        wave.push(entry);
                    }
                    // Independent functions expose their next blocks together.
                    // Applying results remains in deterministic coordinator order.
                    self.prefetch(&frontier)?;
                    for &pc in &frontier {
                        self.ensure(pc);
                    }
                    if let Some(error) = self.fatal.take() {
                        return Err(Error::Backend(error.to_string()));
                    }
                    // Direct transfers probe import stubs or discover callees.
                    // Batch those translations too, rather than serializing
                    // every next block during classification/completion.
                    frontier.clear();
                    for &entry in &wave {
                        let state = &states[&entry];
                        if let Some(pc) = state.work.last()
                            && !state.function.blocks.contains(pc)
                            && let Some(block) = self.cfg.blocks.get(pc)
                        {
                            frontier.extend(block.exits.iter().filter_map(|exit| {
                                if let ExitKind::Jump(target) | ExitKind::Call { target, .. } =
                                    exit.kind
                                    && target != entry
                                    && !self.cfg.functions.contains_key(&target)
                                {
                                    Some(target)
                                } else {
                                    None
                                }
                            }));
                        }
                    }
                    self.prefetch(&frontier)?;
                    for entry in wave.drain(..) {
                        let mut state = states.remove(&entry).expect("scheduled exploration");
                        if self.explore(entry, &mut state) {
                            let calls: Vec<_> = state.function.calls.iter().copied().collect();
                            self.prefetch(&calls)?;
                            for target in calls {
                                if self.ensure(target) {
                                    self.cfg
                                        .functions
                                        .entry(target)
                                        .or_insert_with(|| Function {
                                            entry: target,
                                            ..Default::default()
                                        });
                                }
                            }
                            if self.cfg.functions.get(&entry) != Some(&state.function) {
                                changed.insert(entry);
                            }
                            self.cfg.functions.insert(entry, state.function);
                        } else {
                            states.insert(entry, state);
                            ready.push_back(entry);
                        }
                        if let Some(error) = self.fatal.take() {
                            return Err(Error::Backend(error.to_string()));
                        }
                    }
                    self.lib.checkpoint_cfg(&self.cfg)?;
                }
                dirty = if before
                    != (
                        self.generation,
                        self.cfg.functions.len(),
                        self.cfg.unresolved.len(),
                    ) {
                    // Splits, new entry boundaries and unknown callees can
                    // change ownership or returnability outside direct callers.
                    self.cfg.functions.keys().copied().collect()
                } else {
                    self.cfg
                        .functions
                        .iter()
                        .filter_map(|(&entry, function)| {
                            (changed.contains(&entry)
                                || !function.calls.is_disjoint(&changed)
                                || !function.tail_calls.is_disjoint(&changed))
                            .then_some(entry)
                        })
                        .collect()
                };
            }
            let added = self.discover()?;
            if !added {
                break;
            }
        }
        // Functions whose entry never translated carry no information, and
        // blocks no function reaches any more (cut-off junk) are dropped.
        let blocks = &self.cfg.blocks;
        self.cfg.functions.retain(|e, _| blocks.contains_key(e));
        let reached: BTreeSet<u64> = self
            .cfg
            .functions
            .values()
            .flat_map(|f| f.blocks.iter().copied())
            .collect();
        self.cfg.blocks.retain(|a, _| reached.contains(a));
        // Tables of blocks since cut short now belong to the block that
        // ends in the jump.
        let blocks = &self.cfg.blocks;
        self.cfg.jump_tables.retain(|a, _| {
            blocks.get(a).is_some_and(|b| {
                b.exits
                    .iter()
                    .any(|x| matches!(x.kind, ExitKind::IndirectJump { .. }))
            })
        });
        self.lib.checkpoint_cfg(&self.cfg)?;
        Ok(())
    }

    /// Blocks of the function at `entry`, under the current knowledge of
    /// which functions return.
    fn explore(&mut self, entry: u64, state: &mut Exploration) -> bool {
        let f = &mut state.function;
        let work = &mut state.work;
        let has_return = &mut state.has_return;
        // Advance one block so the next wave can batch all function frontiers.
        if let Some(a) = work.pop()
            && !f.blocks.contains(&a)
            && self.ensure(a)
        {
            f.blocks.insert(a);
            let exits: Vec<ExitKind> = self.cfg.blocks[&a].exits.iter().map(|x| x.kind).collect();
            for kind in exits {
                // A jump to a PLT stub is a tail call to the import, even if
                // nothing calls the stub.
                if let ExitKind::Jump(t) = kind
                    && t != entry
                    && !self.cfg.functions.contains_key(&t)
                    && self.is_import_stub(t)
                {
                    self.cfg.functions.insert(
                        t,
                        Function {
                            entry: t,
                            ..Default::default()
                        },
                    );
                }
                let fns = &self.cfg.functions;
                match kind {
                    ExitKind::Jump(t) => jump(fns, entry, t, &mut f.tail_calls, work),
                    ExitKind::IndirectJump { slot } => {
                        if let Some(ts) = self.opts.jump_tables.get(&a) {
                            for &t in ts {
                                jump(fns, entry, t, &mut f.tail_calls, work);
                            }
                        }
                        // Partial tables still have an unknown destination.
                        if !self.noreturn_slot(slot)
                            && (self.opts.incomplete_jump_tables.contains(&a)
                                || !self.opts.jump_tables.contains_key(&a))
                        {
                            *has_return = true;
                        }
                    }
                    ExitKind::Return => *has_return = true,
                    ExitKind::Call { target, ret } => {
                        f.calls.insert(target);
                        if self.callee_returns(target) {
                            work.push(ret);
                        }
                    }
                    ExitKind::IndirectCall { ret, slot } => {
                        let targets = self.opts.indirect_calls.get(&a);
                        if let Some(ts) = targets {
                            f.calls.extend(&ts.targets);
                        }
                        let may_return = targets.is_none_or(|ts| {
                            !ts.complete || ts.targets.iter().any(|&t| self.callee_returns(t))
                        });
                        if !self.noreturn_slot(slot) && may_return {
                            work.push(ret);
                        }
                    }
                    other => work.extend(other.local_successors()),
                }
            }
        }
        f.returns = *has_return || f.tail_calls.iter().any(|&t| self.callee_returns(t));
        work.is_empty()
    }

    /// Add the code-pointer candidates that pass `Discovery`'s checks as
    /// functions. False if there were none.
    fn discover(&mut self) -> Result<bool, Error> {
        let opts = self.opts;
        let Some(d) = &opts.discovery else {
            return Ok(false);
        };
        let constants = self
            .cfg
            .functions
            .values()
            .flat_map(|f| &f.blocks)
            .flat_map(|b| &self.cfg.blocks[b].constants);
        let mut candidates = d
            .data_pointers
            .iter()
            .chain(constants)
            .copied()
            .collect::<BTreeSet<u64>>()
            .into_iter();
        let labels: BTreeSet<u64> = opts.jump_tables.values().flatten().copied().collect();
        let mut wave = Vec::with_capacity(64);
        let mut added = false;
        // Batch independent candidate translations through the backend in
        // bounded waves, like the 64-frontier recovery. Prefetching never
        // commits: an earlier accepted block may cover a later candidate, so
        // each commit rechecks `could_be_entry` in sorted order first.
        loop {
            wave.clear();
            wave.extend(candidates.by_ref().take(64));
            if wave.is_empty() {
                break;
            }
            wave.retain(|c| {
                !self.cfg.functions.contains_key(c)
                    && !self.rejected.contains(c)
                    && !labels.contains(c)
                    && self.could_be_entry(d, *c)
            });
            self.prefetch(&wave)?;
            for c in wave.drain(..) {
                if !self.could_be_entry(d, c) {
                    continue;
                }
                let translated = self.ensure(c);
                if let Some(error) = self.fatal.take() {
                    return Err(Error::Backend(error.to_string()));
                }
                if translated {
                    self.cfg.functions.insert(
                        c,
                        Function {
                            entry: c,
                            ..Default::default()
                        },
                    );
                    self.cfg.discovered.insert(c);
                    added = true;
                } else {
                    self.cfg.unresolved.remove(&c);
                    self.rejected.insert(c);
                }
            }
        }
        Ok(added)
    }

    fn could_be_entry(&self, d: &Discovery, c: u64) -> bool {
        if !c.is_multiple_of(self.spec.insn_align) || !d.in_code(c) {
            return false;
        }
        // Strictly inside a known body: a label (jump target, landing pad).
        let i = d.extents.partition_point(|r| r.start < c);
        if i > 0 && self.extents_end[i - 1] > c {
            return false;
        }
        // Part of a recovered block, or a block of some function: code that
        // is reached without being a function entry.
        match self.cfg.blocks.range(..=c).next_back() {
            Some((_, b)) => c >= b.end(),
            None => true,
        }
    }

    /// Whether `pc` starts a block that only jumps through an import's slot.
    fn is_import_stub(&mut self, pc: u64) -> bool {
        self.ensure(pc)
            && matches!(
                self.cfg.blocks[&pc].exits.as_slice(),
                [Exit {
                    kind: ExitKind::IndirectJump { slot: Some(s) },
                    ..
                }] if self.opts.imports.contains_key(s)
            )
    }

    fn noreturn_slot(&self, slot: Option<u64>) -> bool {
        slot.and_then(|s| self.opts.imports.get(&s))
            .is_some_and(|name| NORETURN_IMPORTS.contains(&name.as_str()))
    }

    /// Optimistic: a callee returns only once shown to, so return sites of
    /// `exit`-like calls never pull in the bytes that follow them. Callees
    /// that cannot be translated (imports, data) are assumed to return.
    fn callee_returns(&self, target: u64) -> bool {
        self.cfg.unresolved.contains_key(&target)
            || self.cfg.functions.get(&target).is_some_and(|f| f.returns)
    }

    fn prefetch(&mut self, addresses: &[u64]) -> Result<(), Error> {
        let requests: Vec<_> = addresses
            .iter()
            .copied()
            .filter(|pc| !self.cfg.blocks.contains_key(pc) && !self.cfg.unresolved.contains_key(pc))
            .filter_map(|pc| {
                let (code, code_base) = (self.code_at)(pc)?;
                // Splitting an existing translation is independent of the new
                // entry translation. Batch both; ensure still applies the cut.
                let cut = self
                    .cfg
                    .blocks
                    .range(..pc)
                    .next_back()
                    .filter(|(_, block)| pc < block.end())
                    .and_then(|(&start, block)| {
                        let count = block.insns.iter().position(|&insn| insn == pc)?;
                        let (code, code_base) = (self.code_at)(start)?;
                        Some(TranslationRequest {
                            code,
                            code_base,
                            pc: start,
                            max_insns: count as u32,
                        })
                    });
                Some([
                    cut,
                    Some(TranslationRequest {
                        code,
                        code_base,
                        pc,
                        max_insns: 0,
                    }),
                ])
            })
            .take(self.opts.max_blocks.saturating_sub(self.cfg.blocks.len()))
            .flat_map(|pair| pair.into_iter().flatten())
            .collect();
        self.lib
            .prefetch(&requests)
            .map_err(|error| Error::Backend(error.to_string()))
    }

    /// Make sure a block starts at `pc`. Returns false if it cannot be
    /// translated.
    fn ensure(&mut self, pc: u64) -> bool {
        if self.cfg.blocks.contains_key(&pc) {
            return true;
        }
        if self.cfg.unresolved.contains_key(&pc) {
            return false;
        }
        // A branch into the middle of a block at an instruction boundary:
        // cut that block short so blocks never overlap.
        if let Some((&start, b)) = self.cfg.blocks.range(..pc).next_back()
            && pc < b.end()
            && let Some(n) = b.insns.iter().position(|&i| i == pc)
        {
            self.translate(start, n as u32);
        }
        self.translate(pc, 0)
    }

    /// Translate the block at `pc`, stopping before the first known block or
    /// metadata function start it reaches.
    fn translate(&mut self, pc: u64, max_insns: u32) -> bool {
        if self.cfg.blocks.len() >= self.opts.max_blocks && !self.cfg.blocks.contains_key(&pc) {
            self.cfg.recovery.block_limit_reached = true;
            self.cfg
                .unresolved
                .insert(pc, format!("block limit {} reached", self.opts.max_blocks));
            return false;
        }
        let Some((code, base)) = (self.code_at)(pc) else {
            self.cfg
                .unresolved
                .insert(pc, "not in executable memory".into());
            return false;
        };
        let mut block = match self.lib.translate(code, base, pc, max_insns) {
            Ok(b) => b,
            Err(e) => {
                if matches!(e, biara_tcg::Error::Backend(_) | biara_tcg::Error::Codec(_)) {
                    self.fatal = Some(e);
                    return false;
                }
                self.cfg.unresolved.insert(pc, e.to_string());
                return false;
            }
        };
        let mut insns = insn_pcs(&block);
        // Stop before the first instruction that starts a known block or a
        // metadata function, so blocks never run over either. Function starts
        // are known up front: the cut does not depend on translation order.
        if let Some(cut) = insns
            .iter()
            .skip(1)
            .position(|i| self.cfg.blocks.contains_key(i) || self.opts.function_starts.contains(i))
        {
            let cut = cut + 1;
            match self.lib.translate(code, base, pc, cut as u32) {
                Ok(b) => {
                    block = b;
                    insns = insn_pcs(&block);
                }
                Err(e) => {
                    if matches!(e, biara_tcg::Error::Backend(_) | biara_tcg::Error::Codec(_)) {
                        self.fatal = Some(e);
                        return false;
                    }
                    self.cfg.unresolved.insert(pc, e.to_string());
                    return false;
                }
            }
        }
        // Metadata function starts are instruction boundaries; a decode that
        // runs across one cannot be the code that executes there.
        if let Some(start) = self
            .opts
            .function_starts
            .range(pc + 1..block.end())
            .find(|&&s| s.is_multiple_of(self.spec.insn_align) && !insns.contains(&s))
        {
            self.cfg.unresolved.insert(
                pc,
                format!("instructions overlap function start {start:#x}"),
            );
            return false;
        }
        let (exits, constants) = exits::classify(&block, &self.regs, self.spec);
        self.cfg.blocks.insert(
            pc,
            Arc::new(BasicBlock {
                block,
                insns,
                exits,
                constants,
            }),
        );
        self.generation += 1;
        true
    }
}

/// A jump to `t` from the function at `entry`: a tail call if `t` is
/// another function's entry, otherwise more of this function.
fn jump(
    functions: &BTreeMap<u64, Function>,
    entry: u64,
    t: u64,
    tail_calls: &mut BTreeSet<u64>,
    work: &mut Vec<u64>,
) {
    if t != entry && functions.contains_key(&t) {
        tail_calls.insert(t);
    } else {
        work.push(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;

    fn with_lib(f: impl FnOnce(&mut Libtcg)) {
        let lib = Libtcg::load(&Libtcg::find("x86_64").expect("libtcg-x86_64"), None)
            .expect("loading libtcg");
        f(&mut lib.lock());
    }

    fn code_at(bytes: &[u8], pc: u64) -> Option<(&[u8], u64)> {
        (pc >= BASE && pc - BASE < bytes.len() as u64).then_some((bytes, BASE))
    }

    fn call_fixture() -> Vec<u8> {
        let mut bytes = vec![0xc3; 0x202];
        bytes[..3].copy_from_slice(&[0xff, 0xd0, 0xc3]); // call rax; ret
        bytes[0x100..0x102].copy_from_slice(&[0xeb, 0xfe]); // nonreturning loop
        bytes[0x200..0x202].copy_from_slice(&[0xeb, 0xfe]);
        bytes
    }

    #[test]
    fn block_limit_and_translation_failure_are_reported() {
        with_lib(|lib| {
            let opts = Options {
                max_blocks: 0,
                ..Default::default()
            };
            let cfg = recover(lib, |pc| code_at(&[0xc3], pc), [BASE], &opts).unwrap();
            assert!(cfg.recovery.block_limit_reached);
            assert_eq!(cfg.recovery.block_limit, 0);
            assert!(
                cfg.issues()
                    .any(|i| matches!(i, CfgIssue::BlockLimit { limit: 0 }))
            );
            let cfg = recover(lib, |_| None, [BASE], &Options::default()).unwrap();
            assert!(!cfg.recovery.block_limit_reached);
            assert!(
                cfg.issues()
                    .any(|i| matches!(i, CfgIssue::TranslationFailure { address: BASE, .. }))
            );
        });
    }

    #[test]
    fn large_function_does_not_starve_other_known_entries_under_a_block_budget() {
        with_lib(|lib| {
            let mut bytes = vec![0xc3; 0x301];
            for pair in bytes[..0x100].chunks_exact_mut(2) {
                pair.copy_from_slice(&[0xeb, 0]); // jump to the next block
            }
            let tiny = BASE + 0x300;
            let cfg = recover(
                lib,
                |pc| code_at(&bytes, pc),
                [BASE, tiny],
                &Options {
                    max_blocks: 4,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(cfg.functions[&tiny].returns);
            assert_eq!(cfg.functions[&tiny].blocks, BTreeSet::from([tiny]));
            assert!(cfg.recovery.block_limit_reached);
        });
    }

    /// An opaque branch into junk whose decode runs across a metadata
    /// function start must not absorb that function's code into the caller.
    /// Function starts that are instruction boundaries end blocks whatever
    /// the roots, so block shapes do not depend on what was translated first.
    #[test]
    fn decodes_across_metadata_function_starts_are_not_recovered() {
        with_lib(|lib| {
            let mut bytes = vec![0xc3; 0x30];
            bytes[..2].copy_from_slice(&[0x74, 0x0e]); // je BASE+0x10; ret
            // movabs rax, imm64 covers BASE+0x12..0x1a, including B's entry.
            bytes[0x10..0x12].copy_from_slice(&[0x48, 0xb8]);
            bytes[0x14..0x17].copy_from_slice(&[0x31, 0xc0, 0xc3]); // B: xor eax,eax; ret
            bytes[0x20..0x22].copy_from_slice(&[0x90, 0x90]); // C: nop; D: nop; ret
            let (a, junk, b, c, d) = (BASE, BASE + 0x10, BASE + 0x14, BASE + 0x20, BASE + 0x21);
            let starts = BTreeSet::from([a, b, c, d]);
            let opts = Options {
                function_starts: starts.clone(),
                ..Default::default()
            };
            let cfg = recover(lib, |pc| code_at(&bytes, pc), starts.clone(), &opts).unwrap();
            assert_eq!(cfg.functions[&a].blocks, BTreeSet::from([a, a + 2]));
            assert!(cfg.functions[&a].returns);
            assert_eq!(cfg.functions[&b].blocks, BTreeSet::from([b]));
            assert!(cfg.unresolved[&junk].contains("overlap function start"));
            assert_eq!(
                cfg.functions.keys().copied().collect::<BTreeSet<_>>(),
                starts
            );
            assert!(cfg.unresolved.keys().all(|&pc| pc == junk));
            assert_eq!(cfg.functions[&c].tail_calls, BTreeSet::from([d]));

            // Rooted at C alone, D still ends C's first block.
            let cfg = recover(lib, |pc| code_at(&bytes, pc), [c], &opts).unwrap();
            assert_eq!(cfg.blocks[&c].end(), d);
            assert_eq!(cfg.functions[&c].blocks, BTreeSet::from([c, d]));

            // Without metadata the junk decode is indistinguishable from code.
            let starts = [a, b];
            let cfg = recover(lib, |pc| code_at(&bytes, pc), starts, &Options::default()).unwrap();
            assert!(cfg.functions[&a].blocks.contains(&junk));
        });
    }

    #[test]
    fn bounded_wavefronts_recover_edges_in_both_large_functions() {
        with_lib(|lib| {
            let mut bytes = vec![0xc3; 0x111];
            for start in [0, 0x100] {
                for pair in bytes[start..start + 0x10].chunks_exact_mut(2) {
                    pair.copy_from_slice(&[0xeb, 0]);
                }
            }
            let cfg = recover(
                lib,
                |pc| code_at(&bytes, pc),
                [BASE, BASE + 0x100],
                &Options {
                    max_blocks: 6,
                    ..Default::default()
                },
            )
            .unwrap();
            for entry in [BASE, BASE + 0x100] {
                assert_eq!(
                    cfg.functions[&entry].blocks,
                    BTreeSet::from([entry, entry + 2, entry + 4]),
                );
            }
            assert!(cfg.recovery.block_limit_reached);
        });
    }

    #[test]
    fn returnability_propagates_through_recursive_call_and_tail_dependencies() {
        with_lib(|lib| {
            let mut bytes = vec![0xc3; 0x105];
            // A: test edi,edi; je return; call B; ret; return: ret.
            bytes[..11].copy_from_slice(&[0x85, 0xff, 0x74, 6, 0xe8, 0xf7, 0, 0, 0, 0xc3, 0xc3]);
            // B tail-calls A. A's independent return makes both functions returning.
            bytes[0x100] = 0xe9;
            bytes[0x101..0x105].copy_from_slice(&(-0x105i32).to_le_bytes());
            let b = BASE + 0x100;
            let cfg = recover(
                lib,
                |pc| code_at(&bytes, pc),
                [BASE, b],
                &Options::default(),
            )
            .unwrap();
            assert!(cfg.functions[&BASE].returns);
            assert!(cfg.functions[&b].returns);
            assert_eq!(cfg.functions[&BASE].calls, BTreeSet::from([b]));
            assert_eq!(cfg.functions[&b].tail_calls, BTreeSet::from([BASE]));
            assert!(cfg.functions[&BASE].blocks.contains(&(BASE + 9)));
            assert!(cfg.functions[&BASE].blocks.contains(&(BASE + 10)));
            assert!(cfg.issues().next().is_none());
        });
    }

    #[test]
    fn resolver_limits_have_typed_serializable_evidence() {
        let cfg = Cfg {
            recovery: RecoveryStatus {
                resolution_limit_reached: true,
                resolution_rounds: 7,
                table_limit_sites: BTreeSet::from([BASE, BASE + 1]),
                table_entry_limit: 31,
                callback_limit_reached: true,
                callback_depth_limit: 3,
                callback_state_limit: 17,
                ..Default::default()
            },
            ..Default::default()
        };
        let issues: Vec<_> = cfg.issues().collect();
        assert_eq!(issues.len(), 4);
        assert!(issues.contains(&CfgIssue::ResolutionLimit { rounds: 7 }));
        for address in [BASE, BASE + 1] {
            assert!(issues.contains(&CfgIssue::TableLimit {
                address,
                entry_limit: 31
            }));
        }
        assert!(issues.contains(&CfgIssue::CallbackLimit {
            depth_limit: 3,
            state_limit: 17
        }));
        let serialized = serde_json::to_value(&issues).unwrap();
        assert_eq!(serialized[0]["kind"], "resolution_limit");
        assert_eq!(serialized[0]["rounds"], 7);
        assert_eq!(
            serde_json::to_value(&cfg.recovery).unwrap()["table_entry_limit"],
            31
        );
    }

    #[test]
    fn unknown_calls_jumps_and_partial_tables_remain_issues() {
        with_lib(|lib| {
            let bytes = call_fixture();
            let cfg = recover(lib, |pc| code_at(&bytes, pc), [BASE], &Options::default()).unwrap();
            assert!(
                cfg.issues()
                    .any(|i| i == CfgIssue::UnknownIndirectCall { address: BASE })
            );
            let mut jumps = bytes;
            jumps[..2].copy_from_slice(&[0xff, 0xe0]); // jmp rax
            let mut opts = Options::default();
            let cfg = recover(lib, |pc| code_at(&jumps, pc), [BASE], &opts).unwrap();
            assert!(
                cfg.issues()
                    .any(|i| i == CfgIssue::UnknownIndirectJump { address: BASE })
            );
            opts.jump_tables
                .insert(BASE, BTreeSet::from([BASE + 0x100]));
            opts.incomplete_jump_tables.insert(BASE);
            let cfg = recover_from(lib, |pc| code_at(&jumps, pc), [BASE], &opts, cfg).unwrap();
            assert!(cfg.incomplete_jump_tables.contains(&BASE));
            assert!(cfg.functions[&BASE].blocks.contains(&(BASE + 0x100)));
            assert!(cfg.functions[&BASE].returns);
            assert!(
                cfg.issues()
                    .any(|i| i == CfgIssue::UnknownIndirectJump { address: BASE })
            );
            opts.incomplete_jump_tables.clear();
            let cfg = recover_from(lib, |pc| code_at(&jumps, pc), [BASE], &opts, cfg).unwrap();
            assert!(!cfg.functions[&BASE].returns);
            assert!(cfg.issues().next().is_none());
        });
    }

    #[test]
    fn imports_are_not_unknown_and_noreturn_imports_cut_continuations() {
        with_lib(|lib| {
            for opcode in [0x15, 0x25] {
                // call/jmp [rip + 0xffa], pointer slot 0x2000.
                let bytes = [0xff, opcode, 0xfa, 0x0f, 0, 0, 0xc3];
                for name in ["puts", "abort"] {
                    let opts = Options {
                        imports: BTreeMap::from([(0x2000, name.to_owned())]),
                        ..Default::default()
                    };
                    let cfg = recover(lib, |pc| code_at(&bytes, pc), [BASE], &opts).unwrap();
                    assert!(cfg.issues().next().is_none(), "{name} {opcode:#x}");
                    assert_eq!(cfg.functions[&BASE].returns, name == "puts");
                    if opcode == 0x15 {
                        assert_eq!(
                            cfg.functions[&BASE].blocks.contains(&(BASE + 6)),
                            name == "puts"
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn indirect_noreturn_targets_require_exhaustiveness_and_recompute_cached_functions() {
        with_lib(|lib| {
            let bytes = call_fixture();
            let targets = BTreeSet::from([BASE + 0x100, BASE + 0x200]);
            let mut opts = Options::default();
            opts.indirect_calls.insert(
                BASE,
                IndirectTargets {
                    targets: targets.clone(),
                    complete: false,
                },
            );
            let cfg = recover(lib, |pc| code_at(&bytes, pc), [BASE], &opts).unwrap();
            assert_eq!(cfg.functions[&BASE].calls, targets);
            assert!(targets.iter().all(|t| cfg.functions.contains_key(t)));
            assert!(cfg.functions[&BASE].blocks.contains(&(BASE + 2)));
            assert!(cfg.functions[&BASE].returns);
            assert!(
                cfg.issues()
                    .any(|i| i == CfgIssue::UnknownIndirectCall { address: BASE })
            );
            opts.indirect_calls.get_mut(&BASE).unwrap().complete = true;
            let cfg = recover_from(lib, |pc| code_at(&bytes, pc), [BASE], &opts, cfg).unwrap();
            assert_eq!(cfg.functions[&BASE].calls, targets);
            assert!(!cfg.functions[&BASE].blocks.contains(&(BASE + 2)));
            assert!(!cfg.functions[&BASE].returns);
            assert!(cfg.issues().next().is_none());
            opts.indirect_calls.get_mut(&BASE).unwrap().complete = false;
            let cfg = recover_from(lib, |pc| code_at(&bytes, pc), [BASE], &opts, cfg).unwrap();
            assert!(cfg.functions[&BASE].returns);
            assert!(cfg.functions[&BASE].blocks.contains(&(BASE + 2)));
        });
    }

    #[test]
    fn complete_multi_target_call_returns_if_any_target_returns() {
        with_lib(|lib| {
            let mut bytes = call_fixture();
            bytes[0x200] = 0xc3;
            let opts = Options {
                indirect_calls: BTreeMap::from([(
                    BASE,
                    IndirectTargets {
                        targets: BTreeSet::from([BASE + 0x100, BASE + 0x200]),
                        complete: true,
                    },
                )]),
                ..Default::default()
            };
            let cfg = recover(lib, |pc| code_at(&bytes, pc), [BASE], &opts).unwrap();
            assert!(!cfg.functions[&(BASE + 0x100)].returns);
            assert!(cfg.functions[&(BASE + 0x200)].returns);
            assert!(cfg.functions[&BASE].returns);
            assert!(cfg.functions[&BASE].blocks.contains(&(BASE + 2)));
            assert!(cfg.issues().next().is_none());
        });
    }
}
