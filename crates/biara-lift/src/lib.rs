//! Lifting: recovered functions to an LLVM module.
//!
//! Every guest function becomes `void <name>(ptr %env)` whose basic blocks
//! are the guest's; direct calls are LLVM calls, returns are `ret`. Two
//! drivers take over where static knowledge ends:
//! - `biara.dispatch(env)` calls the lifted function whose entry is env's
//!   pc (indirect calls and jumps go through it);
//! - `biara.run(env)` keeps dispatching until the pc leaves the lifted set.
//!
//! System calls are `biara.syscall(env)` (left external). Helper calls are
//! external `helper_*` declarations; `link_helpers` pulls in their bitcode
//! (built by scripts/build-libtcg.sh).
//!
//! Analyses on the lifted IR: jump tables (`recover_resolving`), calls and
//! what their arguments hold (`CallSites`, `import_calls`) and checks on
//! calls to well-known imports (`audit`).
//!
//! `prepare_c` extracts an owned LLVM module and compact ABI summaries.
//! Its transform/render stages recover types and stream C; callers can release
//! the recovered TCG before transformation and the image before rendering.
//! `PreparedC::transform` takes `DecompileOptions`: its function-local LLVM
//! passes use isolated workers, bounded by available logical CPUs minus one
//! (minimum one). Cross-function stages and streaming output remain serial.
//! Extraction and ordered merging overlap worker computation; batches are capped
//! by function count and instruction volume (one indivisible function may exceed
//! the volume cap). Failures join workers and restore all unmerged function bodies.
//!
//! Large CFGs (more than 512 functions) are canonicalized one completed
//! function at a time during lifting. Raw spill IR and LLVM analysis caches
//! are bounded to one function; already-processed functions are not revisited.
//! This also applies at `-O0`, so its IR is not a uniformly raw debug dump.
//! Early canonicalization preserves behavior but can change optimized fold
//! shapes relative to running the passes only after the module is complete.

pub mod audit;
mod call_memory;
mod calls;
mod concurrency;
mod decompile;
mod integer;
pub mod layouts;
mod lower;
mod memory;
pub mod output;
mod packages;
pub mod signatures;
mod tables;
pub(crate) mod tokens;

pub use biara_proto::{
    FunctionPackage, PackageDependency, PackageFunctionSymbol, PackageGlobalSymbol, PackageName,
    PackageStatement, PackageSymbols, PackageTypeSymbol, ReadabilityMetrics,
};
pub use calls::{Arg, CallSite, CallSites, Callee, SizeRange, import_calls};
pub use concurrency::DecompileOptions;
pub use decompile::{CStats, PreparedC, TransformedC, TypeFacts, prepare_c, prepare_c_selected};
pub use integer::IntOp;
pub use layouts::{
    ArgLayout, FactStatus, FrameLayout, LayoutConflict, LayoutFacts, LayoutField, LayoutLimits,
    ReturnLayout, SharedLayout,
};
pub use packages::{DebugName, DebugObject};
pub use signatures::{AbiResult, AbiTy, FuncSig, RetClass, summarize};
pub use tables::{
    RecoveryBackend, RecoverySnapshot, RecoveryState, ResolutionArtifact, ResolveOptions,
    SiteResolution, analyze_resolution, recover_resolving, resolution_view,
};
pub mod annotations;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use biara_abi::FunctionAbi;
use biara_cfg::Cfg;
use biara_tcg::ContextInfo;
use inkwell::{
    AddressSpace, OptimizationLevel,
    attributes::{Attribute, AttributeLoc},
    builder::{Builder, BuilderError},
    context::Context,
    module::{Linkage, Module},
    passes::PassBuilderOptions,
    targets::{CodeModel, InitializationConfig, RelocMode, Target, TargetMachine},
    values::{FunctionValue, IntValue, PointerValue},
};

/// Run until the pc leaves the lifted functions.
pub const RUN: &str = "biara.run";
/// Call the lifted function at the current pc, if any.
pub const DISPATCH: &str = "biara.dispatch";
/// System call with arguments in the guest state.
pub const SYSCALL: &str = "biara.syscall";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{pc:#x}: unsupported {what}")]
    Unsupported { pc: u64, what: String },
    #[error("llvm builder: {0}")]
    Builder(#[from] BuilderError),
    #[error("llvm: {0}")]
    Llvm(String),
    #[error(transparent)]
    Cfg(#[from] biara_cfg::Error),
    #[error(transparent)]
    Abi(#[from] biara_abi::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tcg(#[from] biara_tcg::Error),
}

// The analysis target is part of the portable service protocol and cache key.
use biara_proto::ANALYSIS_TRIPLE;
/// Little-endian 64-bit data layout implied by [`ANALYSIS_TRIPLE`].
/// Asserted on every machine construction so a backend change is loud.
const ANALYSIS_DATA_LAYOUT_PREFIX: &str = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128";
pub fn analysis_machine() -> Result<TargetMachine, Error> {
    Target::initialize_x86(&InitializationConfig::default());
    let triple = inkwell::targets::TargetTriple::create(ANALYSIS_TRIPLE);
    let target = Target::from_triple(&triple).map_err(|e| Error::Llvm(e.to_string()))?;
    let machine = target
        .create_target_machine(
            &triple,
            "generic",
            "",
            OptimizationLevel::Default,
            RelocMode::Default,
            CodeModel::Default,
        )
        .ok_or_else(|| Error::Llvm(format!("no target machine for {ANALYSIS_TRIPLE}")))?;
    let data = machine.get_target_data();
    let layout = data.get_data_layout();
    if !layout
        .as_str()
        .to_bytes()
        .starts_with(ANALYSIS_DATA_LAYOUT_PREFIX.as_bytes())
    {
        return Err(Error::Llvm(format!(
            "unexpected data layout for {ANALYSIS_TRIPLE}: {}",
            layout.as_str().to_string_lossy()
        )));
    }
    Ok(machine)
}
/// Native execution machine for genuine JIT consumers (tests that execute
/// lifted code in-process). Never used for analysis output or cache keys.
pub fn native_machine() -> Result<TargetMachine, Error> {
    Target::initialize_native(&InitializationConfig::default()).map_err(Error::Llvm)?;
    let triple = TargetMachine::get_default_triple();
    let target = Target::from_triple(&triple).map_err(|e| Error::Llvm(e.to_string()))?;
    target
        .create_target_machine(
            &triple,
            "generic",
            "",
            OptimizationLevel::None,
            RelocMode::Default,
            CodeModel::Default,
        )
        .ok_or_else(|| Error::Llvm(format!("no target machine for {triple}")))
}

/// Lower every function of `cfg` into a new module. `name_of(entry)` names
/// functions (symbols); others are `sub_<entry>`. With `abis`
/// (`biara_abi::analyze`), calls are lowered as that analysis models them:
/// the registers a callee preserves (for unknown callees: those the
/// convention leaves alone) and the stack pointer stay in SSA form across
/// the call; the lifted code is then only as right as the analysis.
pub fn lift<'ctx>(
    cx: &'ctx Context,
    machine: &TargetMachine,
    info: &ContextInfo,
    cfg: &Cfg,
    abis: Option<&BTreeMap<u64, FunctionAbi>>,
    name_of: &dyn Fn(u64) -> Option<String>,
    module_name: &str,
) -> Result<Module<'ctx>, Error> {
    lift_with(cx, machine, info, cfg, abis, name_of, module_name, None)
}

/// A module for an analysis rather than for running.
pub(crate) struct Analysis<'a> {
    /// The functions that get bodies; known callees get declarations,
    /// while unknown targets go through `biara.dispatch`.
    pub(crate) only: &'a BTreeSet<u64>,
    /// Announce indirect call and jump targets to the resolver.
    pub(crate) target_markers: bool,
}

/// `lift`, or (`analysis`) a module of some of the functions.
#[allow(clippy::too_many_arguments)]
fn lift_with<'ctx>(
    cx: &'ctx Context,
    machine: &TargetMachine,
    info: &ContextInfo,
    cfg: &Cfg,
    abis: Option<&BTreeMap<u64, FunctionAbi>>,
    name_of: &dyn Fn(u64) -> Option<String>,
    module_name: &str,
    analysis: Option<Analysis>,
) -> Result<Module<'ctx>, Error> {
    let module = cx.create_module(module_name);
    module.set_triple(&machine.get_triple());
    module.set_data_layout(&machine.get_target_data().get_data_layout());

    let ptr = cx.ptr_type(AddressSpace::default());
    let fn_ty = cx.void_type().fn_type(&[ptr.into()], false);
    let noalias = cx.create_enum_attribute(Attribute::get_named_enum_kind_id("noalias"), 0);
    // env never escapes lifted code: guest pointers (inttoptr) cannot reach
    // it, so stores to guest memory do not clobber registers in env.
    let no_capture = cx.create_enum_attribute(Attribute::get_named_enum_kind_id("captures"), 0);
    let declare = |name: &str| {
        let f = module.add_function(name, fn_ty, None);
        f.get_nth_param(0).unwrap().set_name("env");
        f.add_attribute(AttributeLoc::Param(0), no_capture);
        f
    };

    let lifted = |e: &u64| analysis.as_ref().is_none_or(|a| a.only.contains(e));
    // Selected modules retain declarations for both direct and recovered
    // indirect callees so native ABI rewriting preserves call relationships.
    let dependencies: BTreeSet<u64> = analysis.as_ref().map_or_else(BTreeSet::new, |a| {
        a.only
            .iter()
            .filter_map(|e| cfg.functions.get(e))
            .flat_map(|f| {
                f.calls.iter().chain(&f.tail_calls).copied().chain(
                    f.blocks
                        .iter()
                        .filter_map(|b| cfg.indirect_calls.get(b))
                        .flat_map(|targets| targets.targets.iter().copied()),
                )
            })
            .collect()
    });
    let functions: HashMap<u64, FunctionValue> = cfg
        .functions
        .keys()
        .filter(|e| lifted(e) || dependencies.contains(e))
        .map(|&e| {
            let f = declare(&name_of(e).unwrap_or_else(|| format!("sub_{e:x}")));
            f.add_attribute(AttributeLoc::Param(0), noalias);
            (e, f)
        })
        .collect();
    let dispatch = declare(DISPATCH);
    let run = declare(RUN);
    let syscall = declare(SYSCALL);
    let target_marker = analysis
        .as_ref()
        .is_some_and(|a| a.target_markers)
        .then(|| {
            let i64 = cx.i64_type();
            let f = module.add_function(
                tables::MARKER,
                cx.void_type().fn_type(&[i64.into(), i64.into()], false),
                None,
            );
            // memory(inaccessiblemem: readwrite): kept, but clobbers no guest state.
            let memory = Attribute::get_named_enum_kind_id("memory");
            f.add_attribute(
                AttributeLoc::Function,
                cx.create_enum_attribute(memory, 0b11 << 2),
            );
            f
        });
    // Preserve guest return boundaries through LLVM's merging of normal
    // returns with escaped-call propagation. Analysis only; never executable IR.
    let return_marker = analysis.as_ref().map(|_| {
        let f = declare(calls::RETURN_MARKER);
        let memory = Attribute::get_named_enum_kind_id("memory");
        f.add_attribute(
            AttributeLoc::Function,
            cx.create_enum_attribute(memory, 0b01 | (0b11 << 2)),
        );
        f
    });

    let spec = cfg.spec(&info.arch)?;
    let global = |name: &str| {
        info.globals
            .iter()
            .position(|g| g.name.as_deref() == Some(name))
            .map(|i| i as biara_tcg::TempId)
            .ok_or_else(|| Error::Llvm(format!("no global {name}")))
    };
    let sp = global(spec.sp)?;
    let pop = match spec.ret {
        biara_cfg::ReturnConvention::Stack { word } => word as i64,
        biara_cfg::ReturnConvention::LinkRegister(_) => 0,
    };
    let clobbered = spec
        .unknown_call
        .clobbers
        .iter()
        .map(|r| global(r))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let convention_kept: BTreeSet<biara_tcg::TempId> = (0..info.globals.len() as biara_tcg::TempId)
        .filter(|g| *g != sp && *g != info.pc_global && !clobbered.contains(g))
        .collect();
    // Collapse each completed function before constructing the next one.
    // Reuse the pass manager, but release its analyses after every function.
    // This bounds raw spill IR to one function instead of a 1024-function
    // batch and never reprocesses an already-trimmed prefix. Small modules
    // retain their raw -O0 form; early passes can change optimized fold shapes.
    let mut trimmer = (cfg.functions.len() > 512).then(|| memory::Trimmer::new(machine));
    for (entry, func) in cfg.functions.iter().filter(|(e, _)| lifted(e)) {
        let f = functions[entry];
        let allocas = cx.append_basic_block(f, "entry");
        let blocks: HashMap<u64, _> = func
            .blocks
            .iter()
            .map(|&a| (a, cx.append_basic_block(f, &format!("b_{a:x}"))))
            .collect();
        // Globals this function's code names; the rest stay in env.
        let used: BTreeSet<biara_tcg::TempId> = func
            .blocks
            .iter()
            .flat_map(|a| {
                let b = &cfg.blocks[a].block;
                b.ops
                    .iter()
                    .flat_map(move |op| b.inputs(op).iter().chain(b.outputs(op)).copied())
            })
            .filter(|&t| (t as usize) < info.globals.len())
            .collect();
        // Every join admits writes from any predecessor. Keep a conservative
        // function-wide union, then narrow it along straight-line paths after
        // synchronization. Helper-written homes are reloaded, hence clean.
        let mut modified: BTreeSet<biara_tcg::TempId> = func
            .blocks
            .iter()
            .flat_map(|a| {
                let block = &cfg.blocks[a].block;
                block
                    .ops
                    .iter()
                    .flat_map(move |op| block.outputs(op).iter().copied())
            })
            .filter(|id| used.contains(id))
            .collect();
        if abis.is_some()
            && func.blocks.iter().any(|a| {
                cfg.blocks[a].exits.iter().any(|exit| {
                    matches!(
                        exit.kind,
                        biara_cfg::ExitKind::Call { .. } | biara_cfg::ExitKind::IndirectCall { .. }
                    )
                })
            })
        {
            modified.insert(sp);
        }
        let globals = promote(cx, info, f, allocas, &used)?;
        let targets = lower::Targets {
            blocks,
            functions: &functions,
            dispatch,
            syscall,
            tables: &cfg.jump_tables,
            indirect_calls: &cfg.indirect_calls,
            imports: &cfg.imports,
            target_marker,
            return_marker,
            globals,
            modified: &modified,
            spec,
            abis,
            convention_kept: &convention_kept,
            sp: (sp, pop),
        };
        for a in &func.blocks {
            let bb = &cfg.blocks[a];
            lower::Lowering::emit(
                cx,
                &module,
                info,
                f,
                allocas,
                targets.blocks[a],
                &bb.block,
                &bb.exits,
                &targets,
            )?;
        }
        let b = cx.create_builder();
        b.position_at_end(allocas);
        b.build_unconditional_branch(targets.blocks[entry])?;
        if let Some(trimmer) = &mut trimmer {
            trimmer.run(f);
        }
    }
    let entries: BTreeSet<u64> = functions.keys().copied().collect();
    driver(cx, info, dispatch, &entries, &functions, false)?;
    driver(cx, info, run, &entries, &functions, true)?;
    module.verify().map_err(|e| Error::Llvm(e.to_string()))?;
    Ok(module)
}

/// `switch (pc) { case entry: call f(env) }`, once or (`looping`) until the
/// pc matches no entry.
fn driver<'ctx>(
    cx: &'ctx Context,
    info: &ContextInfo,
    f: FunctionValue<'ctx>,
    entries: &BTreeSet<u64>,
    functions: &HashMap<u64, FunctionValue<'ctx>>,
    looping: bool,
) -> Result<(), Error> {
    let env = f.get_nth_param(0).unwrap().into_pointer_value();
    let b = cx.create_builder();
    let entry = cx.append_basic_block(f, "entry");
    let head = cx.append_basic_block(f, "dispatch");
    let exit = cx.append_basic_block(f, "exit");
    b.position_at_end(entry);
    b.build_unconditional_branch(head)?;

    b.position_at_end(head);
    let pc = load_pc(cx, &b, info, env)?;
    let mut cases = Vec::with_capacity(entries.len());
    for &addr in entries {
        let bb = cx.append_basic_block(f, &format!("pc_{addr:x}"));
        cases.push((pc.get_type().const_int(addr, false), bb));
        b.position_at_end(bb);
        b.build_call(functions[&addr], &[env.into()], "")?;
        b.build_unconditional_branch(if looping { head } else { exit })?;
    }
    b.position_at_end(head);
    b.build_switch(pc, exit, &cases)?;
    b.position_at_end(exit);
    b.build_return(None)?;
    Ok(())
}

/// Give every env-backed integer TCG global `f` uses a slot in its entry
/// block, loaded from env on entry. mem2reg turns the slots into SSA
/// registers; the lowering writes them back around calls and returns.
fn promote<'ctx>(
    cx: &'ctx Context,
    info: &ContextInfo,
    f: FunctionValue<'ctx>,
    entry: inkwell::basic_block::BasicBlock<'ctx>,
    used: &BTreeSet<biara_tcg::TempId>,
) -> Result<BTreeMap<biara_tcg::TempId, lower::Promoted<'ctx>>, Error> {
    let env = f.get_nth_param(0).unwrap().into_pointer_value();
    let b = cx.create_builder();
    b.position_at_end(entry);
    let mut out = BTreeMap::new();
    for (i, g) in info.globals.iter().enumerate() {
        let promotable = used.contains(&(i as biara_tcg::TempId))
            && g.kind == biara_tcg::TempKind::Global
            && g.mem_base == Some(info.env_global)
            && matches!(g.ty, biara_tcg::Type::I32 | biara_tcg::Type::I64);
        if !promotable {
            continue;
        }
        let name = g.name.as_deref().unwrap_or("g");
        let ty = lower::int_bits(cx, g.ty.bits())?;
        let off = cx.i64_type().const_int(g.mem_offset as u64, true);
        let home = unsafe { b.build_gep(cx.i8_type(), env, &[off], &format!("{name}.home"))? };
        let slot = b.build_alloca(ty, name)?;
        let v = b.build_load(ty, home, &format!("{name}.in"))?;
        b.build_store(slot, v)?;
        out.insert(i as biara_tcg::TempId, lower::Promoted { slot, home, ty });
    }
    Ok(out)
}

fn load_pc<'ctx>(
    cx: &'ctx Context,
    b: &Builder<'ctx>,
    info: &ContextInfo,
    env: PointerValue<'ctx>,
) -> Result<IntValue<'ctx>, Error> {
    let off = cx.i64_type().const_int(info.pc().mem_offset as u64, true);
    let ptr = unsafe { b.build_gep(cx.i8_type(), env, &[off], "pc.ptr")? };
    let ty = lower::int_bits(cx, info.pc().ty.bits())?;
    Ok(b.build_load(ty, ptr, "pc")?.into_int_value())
}

/// Link the helper bitcode at `path` into `module`. Helpers become internal
/// so that optimisation inlines the used ones and drops the rest.
pub fn link_helpers(module: &Module<'_>, path: &Path) -> Result<(), Error> {
    let helpers = Module::parse_bitcode_from_path(path, module.get_context())
        .map_err(|e| Error::Llvm(format!("{}: {e}", path.display())))?;
    // The helpers were compiled for the same host; adopt the lifted module's
    // target so the linker does not warn.
    helpers.set_triple(&module.get_triple());
    helpers.set_data_layout(&module.get_data_layout());
    // QEMU's module constructors (QOM type registration) are not helpers
    // and would keep half of QEMU alive.
    if let Some(ctors) = helpers.get_global("llvm.global_ctors") {
        unsafe { ctors.delete() };
    }
    // Everything defined before linking is lifted code and stays visible.
    let lifted: BTreeSet<Vec<u8>> = module
        .get_functions()
        .filter(|f| f.count_basic_blocks() > 0)
        .map(|f| f.get_name().to_bytes().to_vec())
        .collect();
    module
        .link_in_module(helpers)
        .map_err(|e| Error::Llvm(e.to_string()))?;

    let ours = |name: &[u8]| name.starts_with(b"llvm.") || lifted.contains(name);
    for f in module.get_functions() {
        if f.count_basic_blocks() > 0 && !ours(f.get_name().to_bytes()) {
            f.set_linkage(Linkage::Internal);
        }
    }
    for g in module.get_globals() {
        if g.get_initializer().is_some() && !ours(g.get_name().to_bytes()) {
            g.set_linkage(Linkage::Internal);
        }
    }
    module.verify().map_err(|e| Error::Llvm(e.to_string()))
}

/// Canonicalize (see `memory`), run LLVM's `default<O{level}>` pipeline, then
/// one more round of dead store elimination: register write-backs before
/// calls only become `store (load p), p` once the pipeline has merged them,
/// after its own DSE.
pub fn optimize(module: &Module<'_>, machine: &TargetMachine, level: u8) -> Result<(), Error> {
    memory::canonicalize(module, machine)?;
    module
        .run_passes(
            &format!("default<O{level}>,function(dse,instcombine<no-verify-fixpoint>,simplifycfg)"),
            machine,
            PassBuilderOptions::create(),
        )
        .map_err(|e| Error::Llvm(e.to_string()))
}
