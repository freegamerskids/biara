//! Indirect-target resolution: announce calls and jumps to
//! `biara.target(pc, site)`, simplify so registers flow as SSA, and bound
//! and enumerate destinations through readonly guest memory. Bounded caller
//! substitution also evaluates integer expressions and established shared-frame
//! loads. Candidate callees and jump targets feed CFG recovery; caller-derived
//! candidates do not establish exhaustiveness, and residual unknowns remain
//! explicit. Expression, context, memory-walk and enumeration limits stop work
//! conservatively and are reported through recovery limitations.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    ffi::{CString, c_char, c_void},
};

use biara_cfg::{Cfg, ExitKind, Options};
use biara_tcg::Libtcg;
use inkwell::{
    context::{AsContextRef, Context},
    module::Module,
    targets::TargetMachine,
    values::AsValueRef,
};

use crate::{
    Error,
    calls::{Arg, CallSites, Callee},
};

/// Announces an indirect target: `void biara.target(i64 pc, i64 block)`.
pub(crate) const MARKER: &str = "biara.target";

type ReadFn = unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> i32;
type EmitFn = unsafe extern "C" fn(*mut c_void, u64, u64);
type FinishFn = unsafe extern "C" fn(*mut c_void, u64, i32);

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SiteResolution {
    pub targets: BTreeSet<u64>,
    pub complete: bool,
    pub limited: bool,
}

impl Default for SiteResolution {
    fn default() -> Self {
        Self {
            targets: BTreeSet::new(),
            complete: true,
            limited: false,
        }
    }
}

unsafe extern "C" {
    fn LLVMContextSetDiscardValueNames(context: *mut c_void, discard: i32);
    fn biara_indirect_targets(
        func: *mut c_void,
        marker: *const c_char,
        read: ReadFn,
        read_ctx: *mut c_void,
        max_entries: u64,
        emit: EmitFn,
        emit_ctx: *mut c_void,
        finish: FinishFn,
    ) -> usize;
}

type Reader<'r> = &'r dyn Fn(u64, &mut [u8]) -> bool;

unsafe extern "C" fn read_cb(ctx: *mut c_void, addr: u64, buf: *mut u8, len: usize) -> i32 {
    let read = unsafe { &*(ctx as *const Reader) };
    read(addr, unsafe { std::slice::from_raw_parts_mut(buf, len) }) as i32
}

unsafe extern "C" fn emit_cb(ctx: *mut c_void, site: u64, target: u64) {
    let out = unsafe { &mut *(ctx as *mut BTreeMap<u64, SiteResolution>) };
    out.entry(site).or_default().targets.insert(target);
}

unsafe extern "C" fn finish_cb(ctx: *mut c_void, site: u64, status: i32) {
    let out = unsafe { &mut *(ctx as *mut BTreeMap<u64, SiteResolution>) };
    let resolution = out.entry(site).or_default();
    resolution.complete &= status == 0;
    resolution.limited |= status == 2;
}

/// Resolve marked targets through readonly guest memory. Each site's result
/// combines all lifted contexts; failed reads leave a residual unknown.
pub(crate) fn find(
    module: &Module<'_>,
    machine: &TargetMachine,
    read: Reader,
    max_entries: u64,
) -> Result<BTreeMap<u64, SiteResolution>, Error> {
    crate::memory::simplify(module, machine)?;
    let marker = CString::new(MARKER).unwrap();
    let mut out = BTreeMap::new();
    for f in module.get_functions() {
        unsafe {
            biara_indirect_targets(
                f.as_value_ref().cast(),
                marker.as_ptr(),
                read_cb,
                &read as *const Reader as *mut c_void,
                max_entries,
                emit_cb,
                &mut out as *mut _ as *mut c_void,
                finish_cb,
            );
        }
    }
    Ok(out)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ResolutionArtifact {
    pub targets: BTreeMap<u64, SiteResolution>,
    pub calls: crate::calls::CallFacts,
}

pub fn analyze_resolution(
    cfg: &Cfg,
    info: &biara_tcg::ContextInfo,
    machine: &TargetMachine,
    read: &dyn Fn(u64, &mut [u8]) -> bool,
    pending: &BTreeSet<u64>,
    max_entries: u64,
) -> Result<ResolutionArtifact, Error> {
    let cx = Context::create();
    // Resolution consumes global function/helper names and pc metadata, not
    // local SSA names. Avoid their strings and LLVM's value-symbol-table work
    // for large private analysis graphs; printable/executable lifts keep names.
    unsafe { LLVMContextSetDiscardValueNames((&cx).as_ctx_ref().cast(), 1) };
    let module = crate::lift_with(
        &cx,
        machine,
        info,
        cfg,
        None,
        &|_| None,
        "targets",
        Some(crate::Analysis {
            only: pending,
            target_markers: true,
        }),
    )?;
    let targets = find(&module, machine, read, max_entries)?;
    let mut calls = CallSites::for_resolution(machine, info, cfg)?;
    calls.collect(&module);
    Ok(ResolutionArtifact {
        targets,
        calls: calls.into_facts(),
    })
}

/// Only selected bodies and directly referenced callee/stub facts enter a job.
pub fn resolution_view(cfg: &Cfg, pending: &BTreeSet<u64>) -> Cfg {
    let mut view = Cfg {
        os: cfg.os,
        imports: cfg.imports.clone(),
        ..Default::default()
    };
    let mut needed = pending.clone();
    for entry in pending {
        let function = &cfg.functions[entry];
        needed.extend(&function.calls);
        needed.extend(&function.tail_calls);
        for pc in &function.blocks {
            let block = &cfg.blocks[pc];
            for exit in &block.exits {
                if let ExitKind::Jump(target) | ExitKind::Call { target, .. } = exit.kind
                    && cfg.functions.contains_key(&target)
                {
                    needed.insert(target);
                }
            }
        }
    }
    for entry in needed {
        let Some(function) = cfg.functions.get(&entry) else {
            continue;
        };
        let body = pending.contains(&entry) || cfg.stub_import(entry).is_some();
        let function = if body {
            function.clone()
        } else {
            biara_cfg::Function {
                entry,
                returns: function.returns,
                ..Default::default()
            }
        };
        for pc in &function.blocks {
            view.blocks
                .entry(*pc)
                .or_insert_with(|| cfg.blocks[pc].clone());
            if let Some(reason) = cfg.unresolved.get(pc) {
                view.unresolved.insert(*pc, reason.clone());
            }
            if let Some(targets) = cfg.jump_tables.get(pc) {
                view.jump_tables.insert(*pc, targets.clone());
            }
            if cfg.incomplete_jump_tables.contains(pc) {
                view.incomplete_jump_tables.insert(*pc);
            }
            if let Some(targets) = cfg.indirect_calls.get(pc) {
                view.indirect_calls.insert(*pc, targets.clone());
            }
            for exit in &cfg.blocks[pc].exits {
                for target in exit.kind.local_successors() {
                    if let Some(reason) = cfg.unresolved.get(&target) {
                        view.unresolved.insert(target, reason.clone());
                    }
                }
            }
        }
        view.functions.insert(entry, function);
    }
    view
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct RecoveryState {
    pub round: usize,
    pub attempted_jumps: BTreeSet<u64>,
    pub graph_cache: BTreeMap<u64, Vec<u64>>,
    pub callback_entries: BTreeSet<u64>,
}

pub struct RecoverySnapshot {
    pub cfg: Cfg,
    pub state: RecoveryState,
    /// The exact recovery request finished; the CFG can still contain limitations.
    pub finished: bool,
}

pub trait RecoveryBackend: biara_cfg::RecoveryBackend {
    fn restore(&mut self) -> Result<Option<RecoverySnapshot>, Error> {
        Ok(None)
    }
    fn checkpoint(&mut self, _cfg: &Cfg, _state: &RecoveryState) -> Result<(), Error> {
        Ok(())
    }
    fn resolve(
        &mut self,
        cfg: &Cfg,
        pending: &BTreeSet<u64>,
        machine: &TargetMachine,
        read: &dyn Fn(u64, &mut [u8]) -> bool,
        max_entries: u64,
    ) -> Result<ResolutionArtifact, Error> {
        analyze_resolution(cfg, self.info(), machine, read, pending, max_entries)
    }
}

impl RecoveryBackend for Libtcg {}

/// Limits for `recover_resolving`.
pub struct ResolveOptions {
    pub cfg: Options,
    /// Largest jump table enumerated.
    pub max_table_entries: u64,
    /// Upper bound on recover/resolve rounds.
    pub max_rounds: usize,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            cfg: Options::default(),
            max_table_entries: 4096,
            max_rounds: 16,
        }
    }
}

/// Resolve readonly indirect targets and propagate callback arguments through
/// known callers. Callback candidates do not prove the caller set exhaustive.
pub fn recover_resolving<'c>(
    lib: &mut dyn RecoveryBackend,
    machine: &TargetMachine,
    code_at: &dyn Fn(u64) -> Option<(&'c [u8], u64)>,
    read: Reader,
    entries: &[u64],
    mut opts: ResolveOptions,
) -> Result<Cfg, Error> {
    let snapshot = match lib.restore()? {
        Some(snapshot) if snapshot.finished => return Ok(snapshot.cfg),
        snapshot => snapshot,
    };
    let (mut previous, mut state) = snapshot.map_or_else(
        || (Cfg::default(), RecoveryState::default()),
        |snapshot| (snapshot.cfg, snapshot.state),
    );
    opts.cfg.jump_tables.extend(previous.jump_tables.clone());
    opts.cfg
        .incomplete_jump_tables
        .extend(&previous.incomplete_jump_tables);
    opts.cfg
        .indirect_calls
        .extend(previous.indirect_calls.clone());
    let RecoveryState {
        mut round,
        mut attempted_jumps,
        mut graph_cache,
        mut callback_entries,
    } = state;
    loop {
        let mut cfg = biara_cfg::recover_from(
            lib,
            code_at,
            entries.iter().chain(&callback_entries).copied(),
            &opts.cfg,
            previous,
        )?;
        cfg.recovery.resolution_rounds = round;
        cfg.recovery.table_entry_limit = opts.max_table_entries;
        cfg.recovery.callback_depth_limit = 16;
        cfg.recovery.callback_state_limit = 4096;
        let indirect_sites: BTreeSet<_> = cfg
            .blocks
            .iter()
            .filter_map(|(&pc, b)| {
                b.exits
                    .iter()
                    .any(|x| match x.kind {
                        ExitKind::IndirectCall { slot, .. } | ExitKind::IndirectJump { slot } => {
                            slot.is_none_or(|s| !cfg.imports.contains_key(&s))
                        }
                        _ => false,
                    })
                    .then_some(pc)
            })
            .collect();
        let unresolved_sites: BTreeSet<_> = indirect_sites
            .iter()
            .copied()
            .filter(|pc| {
                cfg.blocks[pc].exits.iter().any(|x| match x.kind {
                    ExitKind::IndirectCall { .. } => {
                        !cfg.indirect_calls.get(pc).is_some_and(|t| t.complete)
                    }
                    ExitKind::IndirectJump { .. } => !attempted_jumps.contains(pc),
                    _ => false,
                })
            })
            .collect();
        let mut pending = BTreeSet::new();
        let mut owners: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for f in cfg.functions.values() {
            let relevant = !f.blocks.is_disjoint(&indirect_sites);
            if !relevant {
                continue;
            }
            for &b in f.blocks.intersection(&indirect_sites) {
                owners.entry(b).or_default().push(f.entry);
            }
            if !f.blocks.is_disjoint(&unresolved_sites)
                || graph_cache
                    .get(&f.entry)
                    .is_none_or(|old| graph_inputs(&cfg, f).ne(old.iter().copied()))
            {
                pending.insert(f.entry);
            }
        }
        // A physical site can belong to multiple recovered functions. Combine
        // all of its contexts, not merely the context whose graph changed.
        let mut queue: VecDeque<_> = pending.iter().copied().collect();
        while let Some(entry) = queue.pop_front() {
            for b in cfg.functions[&entry].blocks.intersection(&indirect_sites) {
                for &owner in &owners[b] {
                    if pending.insert(owner) {
                        queue.push_back(owner);
                    }
                }
            }
        }
        state = RecoveryState {
            round,
            attempted_jumps,
            graph_cache,
            callback_entries,
        };
        lib.checkpoint(&cfg, &state)?;
        (round, attempted_jumps, graph_cache, callback_entries) = (
            state.round,
            state.attempted_jumps,
            state.graph_cache,
            state.callback_entries,
        );
        if pending.is_empty() {
            return Ok(cfg);
        }
        if round >= opts.max_rounds {
            for &entry in &pending {
                for b in &cfg.functions[&entry].blocks {
                    if let Some(targets) = cfg.indirect_calls.get_mut(b) {
                        targets.complete = false;
                    }
                }
            }
            cfg.recovery.resolution_limit_reached = true;
            return Ok(cfg);
        }
        round += 1;
        cfg.recovery.resolution_rounds = round;
        let artifact = lib.resolve(&cfg, &pending, machine, read, opts.max_table_entries)?;
        let found = artifact.targets;
        let mut sites = CallSites::for_resolution(machine, lib.info(), &cfg)?;
        sites.import_facts(artifact.calls);
        let pc_blocks: BTreeMap<_, _> = cfg
            .blocks
            .iter()
            .filter_map(|(&b, body)| body.insns.last().map(|&pc| (pc, b)))
            .collect();
        let roots: Vec<_> = sites
            .sites()
            .iter()
            .filter_map(|call| {
                if let Callee::Indirect { target } = &call.callee {
                    let site = *pc_blocks.get(&call.pc)?;
                    Some((site, call.caller, target.clone(), 0usize))
                } else {
                    None
                }
            })
            .collect();
        let callbacks = callback_targets(&mut sites, roots, read)?;
        drop(sites);
        cfg.recovery.callback_limit_reached |= callbacks.limited;
        for &entry in &pending {
            graph_cache.insert(entry, graph_inputs(&cfg, &cfg.functions[&entry]).collect());
        }
        let open_flow: BTreeMap<_, BTreeSet<_>> =
            cfg.functions
                .values()
                .map(|f| {
                    let open =
                        f.blocks
                            .iter()
                            .copied()
                            .filter(|b| {
                                cfg.blocks[b].exits.iter().any(|e| {
                let unknown_jump = matches!(e.kind, ExitKind::IndirectJump { slot }
                    if slot.is_none_or(|s| !cfg.imports.contains_key(&s)))
                    && (cfg.jump_tables.get(b).is_none_or(BTreeSet::is_empty)
                        || cfg.incomplete_jump_tables.contains(b));
                unknown_jump || e.kind.local_successors().any(|t| cfg.unresolved.contains_key(&t))
            })
                            })
                            .collect();
                    (f.entry, open)
                })
                .collect();
        let mut changed = false;
        for (site, mut resolution) in found {
            if resolution.limited {
                cfg.recovery.table_limit_sites.insert(site);
            }
            let is_call = cfg.blocks[&site]
                .exits
                .iter()
                .any(|e| matches!(e.kind, ExitKind::IndirectCall { .. }));
            resolution.complete &= !resolution.targets.is_empty()
                && owners.get(&site).is_none_or(|fs| {
                    fs.iter()
                        .all(|f| open_flow[f].iter().all(|&open| !is_call && open == site))
                });
            resolution.targets.retain(|&t| {
                let mapped = code_at(t).is_some();
                if !mapped {
                    resolution.complete = false;
                }
                mapped
            });
            // Context evidence cannot create an exhaustive proof. Keep an
            // independent local proof only if it covers every added candidate.
            resolution.complete &= callbacks
                .functions
                .get(&site)
                .is_none_or(|targets| targets.is_subset(&resolution.targets))
                && callbacks
                    .local
                    .get(&site)
                    .is_none_or(|targets| targets.is_subset(&resolution.targets))
                && opts
                    .cfg
                    .indirect_calls
                    .get(&site)
                    .is_none_or(|known| known.targets.is_subset(&resolution.targets));
            if is_call {
                let known = opts.cfg.indirect_calls.entry(site).or_default();
                for t in resolution.targets {
                    changed |= known.targets.insert(t);
                }
                known.complete = resolution.complete;
            } else {
                attempted_jumps.insert(site);
                if !resolution.complete {
                    opts.cfg.incomplete_jump_tables.insert(site);
                } else {
                    opts.cfg.incomplete_jump_tables.remove(&site);
                }
                let known = opts.cfg.jump_tables.entry(site).or_default();
                for t in resolution.targets {
                    changed |= known.insert(t);
                }
            }
        }
        // Interprocedural function-pointer evidence is not a local jump-table
        // label. Keep these roots even when they are also jump destinations.
        for targets in callbacks.functions.values() {
            for &target in targets.iter().filter(|&&t| code_at(t).is_some()) {
                changed |= callback_entries.insert(target);
            }
        }
        for (site, targets) in callbacks.local.into_iter().chain(callbacks.functions) {
            let is_call = cfg.blocks[&site]
                .exits
                .iter()
                .any(|e| matches!(e.kind, ExitKind::IndirectCall { .. }));
            for t in targets.into_iter().filter(|&t| code_at(t).is_some()) {
                if is_call {
                    let known = opts.cfg.indirect_calls.entry(site).or_default();
                    changed |= known.targets.insert(t);
                } else {
                    opts.cfg.incomplete_jump_tables.insert(site);
                    changed |= opts.cfg.jump_tables.entry(site).or_default().insert(t);
                }
            }
        }
        // Compare final completeness, not temporary results before context evidence.
        changed |= opts.cfg.indirect_calls.iter().any(|(site, targets)| {
            targets.complete != cfg.indirect_calls.get(site).is_some_and(|old| old.complete)
        });
        changed |= opts.cfg.incomplete_jump_tables != cfg.incomplete_jump_tables;
        opts.cfg.jump_tables.retain(|_, ts| !ts.is_empty());
        cfg.jump_tables = opts.cfg.jump_tables.clone();
        cfg.indirect_calls = opts.cfg.indirect_calls.clone();
        cfg.incomplete_jump_tables = opts.cfg.incomplete_jump_tables.clone();
        state = RecoveryState {
            round,
            attempted_jumps,
            graph_cache,
            callback_entries,
        };
        lib.checkpoint(&cfg, &state)?;
        (round, attempted_jumps, graph_cache, callback_entries) = (
            state.round,
            state.attempted_jumps,
            state.graph_cache,
            state.callback_entries,
        );
        if !changed {
            return Ok(cfg);
        }
        previous = cfg;
    }
}

/// Exact, allocation-free comparison input for a function's recovered graph.
/// Cache owns one flat sequence; no hash equality can hide a new predecessor.
fn graph_inputs<'a>(
    cfg: &'a Cfg,
    function: &'a biara_cfg::Function,
) -> impl Iterator<Item = u64> + 'a {
    std::iter::once(function.blocks.len() as u64).chain(function.blocks.iter().flat_map(|&pc| {
        let jumps = cfg.jump_tables.get(&pc);
        let calls = cfg.indirect_calls.get(&pc);
        [
            pc,
            cfg.blocks[&pc].end(),
            jumps.map_or(0, BTreeSet::len) as u64,
        ]
        .into_iter()
        .chain(jumps.into_iter().flat_map(|ts| ts.iter().copied()))
        .chain(std::iter::once(calls.map_or(0, |t| t.targets.len()) as u64))
        .chain(calls.into_iter().flat_map(|t| t.targets.iter().copied()))
    }))
}

#[derive(Default)]
struct CallbackTargets {
    local: BTreeMap<u64, BTreeSet<u64>>,
    functions: BTreeMap<u64, BTreeSet<u64>>,
    limited: bool,
}

fn callback_targets(
    sites: &mut CallSites<'_>,
    roots: Vec<(u64, u64, Arg, usize)>,
    read: Reader<'_>,
) -> Result<CallbackTargets, Error> {
    let mut out = CallbackTargets::default();
    let mut work: VecDeque<_> = roots.into();
    let mut seen = HashSet::new();
    while let Some((site, at, arg, depth)) = work.pop_front() {
        if !seen.insert((site, at, arg.clone())) {
            continue;
        }
        if depth >= 16 || seen.len() > 4096 {
            out.limited = true;
            continue;
        }
        let function_pointer = depth > 0 || internal_result(&arg);
        let mut summary_rounds = 0;
        loop {
            let needed = sites.missing_summaries(&arg);
            if needed.is_empty() {
                break;
            }
            if summary_rounds == 16 {
                out.limited = true;
                break;
            }
            let before = sites.lifted().len();
            sites.add(&needed)?;
            summary_rounds += 1;
            if sites.lifted().len() == before {
                break;
            }
        }
        let arg = sites.resolve_arg(&arg, at);
        let targets = if function_pointer {
            &mut out.functions
        } else {
            &mut out.local
        };
        let mut budget = 4096;
        if !constants(&arg, read, targets.entry(site).or_default(), &mut budget) {
            out.limited = true;
        }
        if !needs_entry(&arg) {
            continue;
        }
        let callers: BTreeSet<_> = sites
            .cfg()
            .functions
            .values()
            .filter(|f| f.calls.contains(&at) || f.tail_calls.contains(&at))
            .map(|f| f.entry)
            .collect();
        sites.add(&callers)?;
        // Substitution resolves call results eagerly. Load their summaries
        // before binding entry arguments, or a factory result becomes Unknown
        // and its dependency can no longer be discovered.
        let mut summary_rounds = 0;
        loop {
            let needed: BTreeSet<_> = sites
                .sites()
                .iter()
                .filter(|c| matches!(c.callee, Callee::Function(f) if f == at))
                .flat_map(|call| call.args.iter().chain(call.registers.values()))
                .flat_map(|arg| sites.missing_summaries(arg))
                .collect();
            if needed.is_empty() {
                break;
            }
            if summary_rounds == 16 {
                out.limited = true;
                break;
            }
            let before = sites.lifted().len();
            sites.add(&needed)?;
            summary_rounds += 1;
            if sites.lifted().len() == before {
                break;
            }
        }
        for call in sites
            .sites()
            .iter()
            .filter(|c| matches!(c.callee, Callee::Function(f) if f == at))
        {
            work.push_back((
                site,
                call.caller,
                sites.substitute_arg(&arg, at, call),
                depth + 1,
            ));
        }
    }
    out.limited |= sites.memory_limited();
    Ok(out)
}

fn internal_result(arg: &Arg) -> bool {
    match arg {
        Arg::FunctionResult { .. } | Arg::RegisterResult { .. } => true,
        Arg::Offset { base, .. } | Arg::Load { base, .. } => internal_result(base),
        Arg::OneOf(values) | Arg::Expr { args: values, .. } => values.iter().any(internal_result),
        _ => false,
    }
}

fn needs_entry(arg: &Arg) -> bool {
    match arg {
        Arg::Incoming(_) | Arg::Deref { .. } | Arg::Stack(_) => true,
        Arg::Offset { base, .. } | Arg::Load { base, .. } => needs_entry(base),
        Arg::OneOf(vs) | Arg::Expr { args: vs, .. } => vs.iter().any(needs_entry),
        _ => false,
    }
}

/// Enumerate only established values, with a bounded expression walk.
/// Two varying operands may be correlated; do not invent their Cartesian product.
fn constants(arg: &Arg, read: Reader<'_>, out: &mut BTreeSet<u64>, budget: &mut usize) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    match arg {
        Arg::Const(v) => {
            out.insert(*v);
        }
        Arg::OneOf(vs) => {
            for v in vs {
                if !constants(v, read, out, budget) {
                    return false;
                }
            }
        }
        Arg::Offset { base, off } => {
            let mut values = BTreeSet::new();
            if !constants(base, read, &mut values, budget) {
                return false;
            }
            out.extend(values.into_iter().map(|v| v.wrapping_add(*off as u64)));
        }
        Arg::Load { base, off, bits } if (8..=64).contains(bits) && bits % 8 == 0 => {
            let mut addresses = BTreeSet::new();
            if !constants(base, read, &mut addresses, budget) {
                return false;
            }
            for address in addresses {
                let mut bytes = [0; 8];
                if read(
                    address.wrapping_add(*off as u64),
                    &mut bytes[..(*bits / 8) as usize],
                ) {
                    out.insert(u64::from_le_bytes(bytes));
                }
            }
        }
        Arg::Expr { op, bits, args } => {
            if args.len() != op.arity() {
                return true;
            }
            let mut values: [BTreeSet<u64>; 3] = std::array::from_fn(|_| BTreeSet::new());
            for (arg, values) in args.iter().zip(&mut values) {
                if !constants(arg, read, values, budget) {
                    return false;
                }
                if values.is_empty() {
                    return true;
                }
            }
            let varying = values[..args.len()].iter().filter(|v| v.len() > 1).count();
            if varying > 1 {
                return true;
            }
            let mut operands = [0; 3];
            for (i, values) in values[..args.len()].iter().enumerate() {
                operands[i] = *values.first().unwrap();
            }
            if let Some(i) = values[..args.len()].iter().position(|v| v.len() > 1) {
                for value in &values[i] {
                    if *budget == 0 {
                        return false;
                    }
                    *budget -= 1;
                    operands[i] = *value;
                    if let Some(value) = op.apply(*bits, &operands[..args.len()]) {
                        out.insert(value);
                    }
                }
            } else if let Some(value) = op.apply(*bits, &operands[..args.len()]) {
                out.insert(value);
            }
        }
        _ => {}
    }
    true
}
