use std::{
    fs,
    io::{self, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, anyhow, bail};
use biara_loader::Image;
use biara_tcg::Libtcg;
use clap::{Parser, Subcommand, ValueEnum};
use inkwell::context::Context;
use parking_lot::Mutex;

mod decomp;
mod json;
mod parallelism;
mod quality;
mod service;

static PROCESS_STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    /// One independently consumable record per line; decompilation only.
    Jsonl,
}

#[derive(Parser)]
#[command(
    name = "biara",
    about = "Binary analysis: QEMU TCG lifting to LLVM IR (ELF, PE and Mach-O; x86-64 and AArch64)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Lift code reachable from the given addresses.
    Lift(LiftArgs),
    /// Match the functions of two binaries by their code.
    Diff(DiffArgs),
    /// Measure function/edge recall for identical mapped code against a symbol oracle.
    Quality(quality::QualityArgs),
    #[command(name = "__worker", hide = true)]
    EngineWorker { config: String },
    /// Run a provider-independent JSON job from a file or stdin.
    Worker(service::WorkerArgs),
    #[command(name = "__service", hide = true)]
    Service { directory: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
enum Emit {
    /// QEMU TCG ops per translation block.
    Tcg,
    /// LLVM IR (textual).
    Llvm,
    /// C: functions with the recovered calling conventions, stack frames
    /// and pointer arguments as structs.
    C,
    /// Function-focused analysis: readable bodies, dependencies and evidence.
    Decomp,
    /// Recovered functions, blocks and their exits.
    Cfg,
    /// Per function: stack frame, register arguments, return values,
    /// registers clobbered.
    Abi,
    /// Calls to imports with what their arguments hold.
    Calls,
    /// Non-constant format strings and writes beyond declared objects or
    /// frame boundaries, at well-known imports. Object sizes come from
    /// allocator arguments, data symbols or supported DWARF locations;
    /// missing sizes remain unknown. Values follow their known callers.
    Audit,
    /// Reusable inferred layouts and typed function signatures; observed
    /// accesses do not establish declared object extents.
    Types,
}

#[derive(clap::Args)]
struct LiftArgs {
    /// Native executable or DLL to analyse.
    binary: PathBuf,
    /// Lift only what is reachable from these addresses (hex 0x...,
    /// decimal, or symbol name). Default: the whole program, from the entry
    /// point, function symbols, PE code exports, TLS callbacks and Guard CF
    /// function tables, unwind/function lists (ELF `.eh_frame`, PE `.pdata`,
    /// Mach-O `LC_FUNCTION_STARTS`) and code pointers.
    at: Vec<String>,
    /// Stop after this many translation blocks.
    #[arg(long, default_value_t = 1_000_000)]
    max_blocks: usize,
    #[arg(long, value_enum, default_value_t = Emit::Llvm)]
    emit: Emit,
    /// LLVM optimisation level (default<O{N}> pipeline); 0 skips it.
    #[arg(short = 'O', default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
    opt: u8,
    /// Link the QEMU helper bitcode so optimisation can inline helpers.
    #[arg(long)]
    link_helpers: bool,
    /// Reload every register after every call in the LLVM output, rather
    /// than keep those the ABI analysis finds preserved in SSA form.
    #[arg(long)]
    no_abi: bool,
    /// libtcg shared object; default $BIARA_LIBTCG_DIR/libtcg-<arch>.so.
    #[arg(long)]
    libtcg: Option<PathBuf>,
    /// Helper bitcode; default $BIARA_LIBTCG_DIR/helpers-<arch>.bc.
    #[arg(long)]
    helpers: Option<PathBuf>,
    /// QEMU CPU model.
    #[arg(long)]
    cpu: Option<String>,
    /// Output file; default stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Schema version 1: numeric addresses, evidence and uncertainty.
    /// JSON supports cfg/abi/calls/audit/decomp/types. JSONL supports decomp only,
    /// with index, function, chunk and readability records. Raw code stays text.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Shared analysis worker budget for recovery, ABI and function passes.
    /// Defaults to max(1, available logical CPUs - 1); larger requests clamp.
    /// Linux processes and native threads inherit the budgeted CPU affinity.
    #[arg(long)]
    jobs: Option<NonZeroUsize>,
    /// Persistent analysis database; default content-addressed user cache.
    /// Rerun the same command to resume committed recovery work after interruption.
    /// Larger recovery budgets reuse translations but recompute the bounded graph.
    /// Schema 1 migrates automatically: job artifacts remain, old graph snapshots retire.
    #[arg(long)]
    database: Option<PathBuf>,
    /// Analysis memory budget in MiB, including recovery workers.
    #[arg(long, default_value_t = 4096)]
    memory_mib: u64,
    /// User names, signatures and struct layouts (JSON or TOML).
    #[arg(long)]
    annotations: Option<PathBuf>,
    #[command(flatten)]
    decomp: decomp::Options,
}

fn main() -> Result<()> {
    let _ = PROCESS_STARTED.set(std::time::Instant::now());
    match Cli::parse().cmd {
        Cmd::Lift(a) => lift(a),
        Cmd::Diff(a) => diff(a),
        Cmd::Quality(a) => quality::run(a),
        Cmd::EngineWorker { config } => biara_engine::worker(&config).map_err(Into::into),
        Cmd::Worker(a) => service::worker(a),
        Cmd::Service { directory } => service::execute(&directory),
    }
}

fn resolve(image: &Image, s: &str) -> Result<u64> {
    let num = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    };
    num.or_else(|| image.symbol(s).map(|sym| sym.addr))
        .ok_or_else(|| anyhow!("{s}: not an address or known symbol"))
}

/// Small sets print every fact. Larger ones keep global limits verbatim and
/// group per-site facts by kind with their first addresses: thousands of
/// lines bury the summary. JSON outputs keep every fact.
fn report_issues(cfg: &biara_cfg::Cfg) {
    use biara_cfg::CfgIssue;
    const ITEMIZED: usize = 20;
    const SHOWN: usize = 3;
    if cfg.issues().nth(ITEMIZED).is_none() {
        for issue in cfg.issues() {
            eprintln!("incomplete analysis: {issue:?}");
        }
        return;
    }
    let mut sites: std::collections::BTreeMap<&str, (usize, Vec<u64>)> = Default::default();
    for issue in cfg.issues() {
        let (kind, address) = match issue {
            CfgIssue::TranslationFailure { address, .. } => ("translation failures", address),
            CfgIssue::UnknownIndirectCall { address } => ("unknown indirect calls", address),
            CfgIssue::UnknownIndirectJump { address } => ("unknown indirect jumps", address),
            CfgIssue::TableLimit { address, .. } => ("target enumeration limits", address),
            global => {
                eprintln!("incomplete analysis: {global:?}");
                continue;
            }
        };
        let (count, first) = sites.entry(kind).or_default();
        *count += 1;
        if first.len() < SHOWN {
            first.push(address);
        }
    }
    for (kind, (count, first)) in sites {
        let first: Vec<_> = first.iter().map(|a| format!("{a:#x}")).collect();
        eprintln!(
            "incomplete analysis: {count} {kind} (first: {})",
            first.join(", ")
        );
    }
    eprintln!("incomplete analysis: --emit cfg --format json lists every fact");
}

fn lift(a: LiftArgs) -> Result<()> {
    if matches!(a.format, Format::Jsonl) && !matches!(a.emit, Emit::Decomp) {
        bail!("--format jsonl requires --emit decomp");
    }
    if matches!(a.format, Format::Json) && matches!(a.emit, Emit::Tcg | Emit::Llvm | Emit::C) {
        bail!(
            "--format json requires --emit cfg, abi, calls, audit, decomp or types; executable code remains text"
        );
    }
    a.decomp.validate(matches!(a.emit, Emit::Decomp))?;
    // Capture one shared budget before restricting affinity. Recovery workers
    // and downstream analyses reuse it rather than subtracting a CPU again.
    let memory_bytes = a
        .memory_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("memory budget overflow"))?;
    let decomp_options = parallelism::resolve(a.jobs, memory_bytes)?;
    let annotations = service::load_annotations(a.annotations.as_deref())?;
    let (image, cfg, lib) = recover(
        &a.binary,
        &a.at,
        a.libtcg.as_deref(),
        a.cpu.as_deref(),
        a.database.as_deref(),
        RecoveryBudget {
            max_blocks: a.max_blocks,
            workers: decomp_options.workers(),
            memory_bytes,
        },
    )?;
    let machine = biara_lift::analysis_machine()?;
    report_issues(&cfg);
    eprintln!(
        "{} functions, {} blocks, {} incomplete-analysis facts",
        cfg.functions.len(),
        cfg.blocks.len(),
        cfg.issues().count()
    );
    let name_of = |addr: u64| {
        annotations
            .functions
            .get(&addr)
            .and_then(|f| f.name.clone())
            .or_else(|| image.function_at(addr).map(|f| f.name.clone()))
            .or_else(|| cfg.stub_import(addr).map(|i| format!("{i}@plt")))
    };
    let label = |addr: u64| name_of(addr).map(|n| format!(" <{n}>")).unwrap_or_default();

    if matches!(a.emit, Emit::Llvm) {
        if cfg.functions.is_empty() {
            bail!("nothing to lift");
        }
        let cx = Context::create();
        let name = a
            .binary
            .file_name()
            .map_or("lifted".into(), |n| n.to_string_lossy());
        let arch = image.arch;
        let mut abis = if a.no_abi {
            None
        } else {
            Some(biara_abi::analyze_with_workers(
                &cfg,
                lib.lock().info(),
                decomp_options.workers(),
            )?)
        };
        if let Some(abis) = &mut abis {
            biara_lift::annotations::apply_abi_annotations(
                &cfg,
                lib.lock().info(),
                abis,
                &annotations,
            )?;
        } else if annotations
            .functions
            .values()
            .any(|f| f.signature.is_some())
        {
            bail!("explicit signatures require ABI analysis; remove --no-abi");
        }
        let module = {
            let guard = lib.lock();
            biara_lift::lift(
                &cx,
                &machine,
                guard.info(),
                &cfg,
                abis.as_ref(),
                &name_of,
                &name,
            )?
        };
        // Recovery state is no longer needed. Release it before helper
        // linking, optimization, and printing can raise the memory peak.
        drop(abis);
        drop(cfg);
        drop(image);
        drop(lib);
        drop(name);
        if a.link_helpers {
            let path = match &a.helpers {
                Some(p) => p.clone(),
                None => {
                    let dir = std::env::var_os("BIARA_LIBTCG_DIR")
                        .ok_or_else(|| anyhow!("--helpers or BIARA_LIBTCG_DIR required"))?;
                    PathBuf::from(dir).join(format!("helpers-{arch}.bc"))
                }
            };
            biara_lift::link_helpers(&module, &path)?;
        }
        if a.opt > 0 {
            biara_lift::optimize(&module, &machine, a.opt)?;
        }
        match &a.output {
            Some(p) => {
                module
                    .print_to_file(p)
                    .map_err(|e| anyhow!("{e}"))
                    .with_context(|| p.display().to_string())?;
            }
            None => {
                biara_lift::output::print_module(&module, &mut io::stdout().lock())?;
            }
        }
        return Ok(());
    }
    if matches!(a.emit, Emit::Decomp) {
        return decomp::run(&a, image, cfg, lib, &machine, decomp_options);
    }
    if matches!(a.emit, Emit::C | Emit::Types) {
        if cfg.functions.is_empty() {
            bail!("nothing to decompile");
        }
        let cx = Context::create();
        let mut abis =
            biara_abi::analyze_with_workers(&cfg, lib.lock().info(), decomp_options.workers())?;
        biara_lift::annotations::apply_abi_annotations(
            &cfg,
            lib.lock().info(),
            &mut abis,
            &annotations,
        )?;
        let banner = format!(
            "Decompiled by biara from {} ({}).",
            a.binary.display(),
            image.arch
        );
        let mut prepared = {
            let guard = lib.lock();
            biara_lift::prepare_c(
                &cx,
                &machine,
                guard.info(),
                &cfg,
                &abis,
                &name_of,
                &banner,
                &image.data,
            )?
        };
        prepared.apply_annotations(&annotations)?;
        drop(abis);
        let report_cfg = matches!(a.emit, Emit::Types).then_some(cfg);
        drop(lib);
        let mut transformed = prepared.transform(
            &machine,
            &|addr, buf| image.read_const(addr, buf),
            decomp_options,
        )?;
        transformed.apply_image_debug(&image);
        transformed.apply_annotations(&annotations)?;
        if matches!(a.emit, Emit::Types) {
            let facts = transformed.type_facts()?;
            return json::types(&a, &image, report_cfg.as_ref().unwrap(), &facts);
        }
        drop(image);
        let stats = match &a.output {
            Some(path) => {
                let file = fs::File::create(path).with_context(|| path.display().to_string())?;
                transformed
                    .render(&mut io::BufWriter::new(file))
                    .with_context(|| path.display().to_string())?
            }
            None => transformed.render(&mut io::stdout().lock())?,
        };
        if stats.unsupported > 0 {
            eprintln!("{} constructs printed as placeholders", stats.unsupported);
        }
        return Ok(());
    }
    let lib = lib.lock();
    if matches!(a.format, Format::Json) {
        return json::lift(
            &a,
            &image,
            &cfg,
            lib.info(),
            &machine,
            decomp_options.workers(),
            &annotations,
        );
    }

    let mut abis = if matches!(a.emit, Emit::Abi | Emit::Calls | Emit::Audit) {
        Some(biara_abi::analyze_with_workers(
            &cfg,
            lib.info(),
            decomp_options.workers(),
        )?)
    } else {
        None
    };
    if let Some(abis) = &mut abis {
        biara_lift::annotations::apply_abi_annotations(&cfg, lib.info(), abis, &annotations)?;
    }
    let text = match a.emit {
        Emit::Tcg => {
            let mut s = String::new();
            for bb in cfg.blocks.values() {
                let b = &bb.block;
                s += &format!(
                    "==== {:#x}{} size {} insns {}\n{b}\n",
                    b.pc,
                    label(b.pc),
                    b.size,
                    b.icount
                );
            }
            s
        }
        Emit::Cfg => {
            let mut s = String::new();
            for f in cfg.functions.values() {
                s += &format!(
                    "function {:#x}{}{}\n",
                    f.entry,
                    label(f.entry),
                    if f.returns { "" } else { " noreturn" }
                );
                for b in &f.blocks {
                    let bb = &cfg.blocks[b];
                    s += &format!("  block {:#x}..{:#x}\n", bb.pc(), bb.end());
                    for x in &bb.exits {
                        s += &format!("    {}\n", x.kind);
                    }
                    if let Some(ts) = cfg.jump_tables.get(b) {
                        let ts: Vec<String> = ts.iter().map(|t| format!("{t:#x}")).collect();
                        s += &format!("    table [{}]\n", ts.join(", "));
                    }
                }
            }
            s
        }
        Emit::Abi => {
            let info = lib.info();
            let abis = abis.as_ref().unwrap();
            let spec = cfg.spec(&info.arch)?;
            // Report in terms of the convention's registers, in its order.
            let regs: Vec<(u32, &str)> = spec
                .registers
                .iter()
                .filter(|&&r| r != spec.sp)
                .filter_map(|&r| {
                    let g = info
                        .globals
                        .iter()
                        .position(|g| g.name.as_deref() == Some(r))?;
                    Some((g as u32, r))
                })
                .collect();
            let list = |keep: &dyn Fn(u32) -> bool| -> String {
                let v: Vec<&str> = regs
                    .iter()
                    .filter(|(g, _)| keep(*g))
                    .map(|(_, n)| *n)
                    .collect();
                if v.is_empty() {
                    "-".into()
                } else {
                    v.join(" ")
                }
            };
            let mut s = String::new();
            for (entry, abi) in abis {
                let stack_args: Vec<String> =
                    abi.stack_args.iter().map(|o| format!("+{o}")).collect();
                s += &format!(
                    "function {entry:#x}{}\n  args: {}{}\n  returns: {}\n  clobbers: {}\n  frame: {} bytes{}\n",
                    label(*entry),
                    list(&|g| abi.args.contains(&g)),
                    if stack_args.is_empty() {
                        String::new()
                    } else {
                        format!("  stack: {}", stack_args.join(" "))
                    },
                    list(&|g| abi.returns.contains(&g)),
                    if cfg.functions.get(entry).is_some_and(|f| f.returns) {
                        list(&|g| !abi.preserved.contains(&g))
                    } else {
                        "(does not return)".into()
                    },
                    abi.frame.size,
                    if abi.frame.balanced {
                        ""
                    } else {
                        ", unbalanced"
                    },
                );
                if !abi.fp_args.is_empty()
                    || !abi.fp_returns.is_empty()
                    || !abi.fp_conflicts.is_empty()
                {
                    s += &format!(
                        "  fp/vector args: {:?}\n  fp/vector returns: {:?}\n  fp/vector conflicts: {:?}\n",
                        abi.fp_arg_types, abi.fp_ret_types, abi.fp_conflicts,
                    );
                }
                if let Some(class) = abi.ret_class {
                    s += &format!("  return class: {class:?}\n");
                }
                s += &format!(
                    "  analysis: {} after {} rounds; {} unknown stack positions\n",
                    if abi.analysis.converged {
                        "converged"
                    } else {
                        "incomplete"
                    },
                    abi.analysis.rounds,
                    abi.frame.sp_at.values().filter(|s| s.is_none()).count()
                );
            }
            s
        }
        Emit::Calls => {
            let mut sites =
                biara_lift::CallSites::with_abis(&machine, lib.info(), &cfg, abis.take())?;
            sites.add(&sites.import_callers())?;
            let mut s = String::new();
            for c in sites.sites().iter().filter(|c| c.import().is_some()) {
                let import = c.import().unwrap_or_default();
                // The arguments the import is known to take, else those up
                // to the last one the caller set.
                let n = biara_lift::audit::known_arity(import).unwrap_or_else(|| {
                    c.args
                        .iter()
                        .rposition(|v| {
                            !matches!(v, biara_lift::Arg::Unknown | biara_lift::Arg::Incoming(_))
                        })
                        .map_or(0, |i| i + 1)
                });
                let args: Vec<String> = c.args.iter().take(n).map(|v| v.to_string()).collect();
                s += &format!(
                    "{:#x} in {:#x}{}: {import}({})\n",
                    c.pc,
                    c.caller,
                    label(c.caller),
                    args.join(", ")
                );
            }
            s
        }
        Emit::Audit => {
            let mut sites =
                biara_lift::CallSites::with_abis(&machine, lib.info(), &cfg, abis.take())?;
            let findings = biara_lift::audit::audit(
                &mut sites,
                &image.indirect_entries(),
                image.main,
                &|addr, buf| image.read_const(addr, buf),
                &|query| json::object_bound(&image, query),
            )?;
            let name = |f: u64| format!("{f:#x}{}", label(f));
            let mut s = String::new();
            for f in &findings {
                s += &format!(
                    "{:#x} in {}: {}\n",
                    f.site.pc,
                    name(f.site.caller),
                    f.describe(&name)
                );
            }
            s
        }
        Emit::C | Emit::Llvm | Emit::Decomp | Emit::Types => {
            unreachable!("handled by the early returns above")
        }
    };

    match a.output {
        Some(p) => fs::write(&p, text).with_context(|| p.display().to_string())?,
        None => io::stdout().lock().write_all(text.as_bytes())?,
    }
    Ok(())
}

#[derive(clap::Args)]
struct DiffArgs {
    /// The older binary.
    old: PathBuf,
    /// The newer binary.
    new: PathBuf,
    /// Only show matches of these kinds (comma-separated): same, changed,
    /// uncertain, added, removed. Default: all but same.
    #[arg(long, value_delimiter = ',')]
    show: Vec<String>,
    /// Stop after this many translation blocks per binary.
    #[arg(long, default_value_t = 1_000_000)]
    max_blocks: usize,
    /// QEMU CPU model.
    #[arg(long)]
    cpu: Option<String>,
    /// Shared analysis workers; capped to available logical CPUs minus one.
    #[arg(long)]
    jobs: Option<NonZeroUsize>,
    /// Total analysis memory budget in MiB.
    #[arg(long, default_value_t = 4096)]
    memory_mib: u64,
    /// Persistent analysis database; default content-addressed user cache.
    #[arg(long)]
    database: Option<PathBuf>,
    /// Output file; default stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

/// Load `path`, recover the whole program (entry point, symbols, unwind
/// and function lists, code pointers), and return the image, its CFG, and
/// the locked libtcg for its architecture.
#[derive(Clone, Copy)]
struct RecoveryBudget {
    max_blocks: usize,
    workers: usize,
    memory_bytes: u64,
}
fn recover(
    path: &Path,
    at: &[String],
    libtcg: Option<&Path>,
    cpu: Option<&str>,
    database: Option<&Path>,
    budget: RecoveryBudget,
) -> Result<(Image, biara_cfg::Cfg, Arc<Mutex<Libtcg>>)> {
    service::limit_address_space(budget.memory_bytes / 2)?;
    let image = Image::load(path).with_context(|| path.display().to_string())?;
    let (entries, discovery): (Vec<u64>, _) = if at.is_empty() {
        let discovery = biara_cfg::Discovery {
            code: image.code.clone(),
            extents: image.function_extents(),
            data_pointers: image.code_pointers.clone(),
        };
        (
            image.function_starts().into_iter().collect(),
            Some(discovery),
        )
    } else {
        let at = at.iter().map(|s| resolve(&image, s));
        (at.collect::<Result<_>>()?, None)
    };
    let lib_path = match libtcg {
        Some(p) => p.to_owned(),
        None => Libtcg::find(image.arch)?,
    };
    let opts = biara_lift::ResolveOptions {
        cfg: biara_cfg::Options {
            os: image.os,
            max_blocks: budget.max_blocks,
            imports: image.imports.clone(),
            discovery,
            function_starts: image.function_starts(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut session = biara_engine::Session::open(
        biara_engine::Options {
            binary: path.to_owned(),
            libtcg: lib_path,
            cpu: cpu.map(str::to_owned),
            database: database.map(Path::to_owned),
            workers: budget.workers,
            memory_budget: budget.memory_bytes,
            executable: std::env::current_exe()?,
        },
        &entries,
        &opts,
    )?;
    let lib = session.lib();
    let cfg = biara_lift::recover_resolving(
        &mut session,
        &biara_lift::analysis_machine()?,
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &entries,
        opts,
    )?;
    session.finish(&cfg)?;
    Ok((image, cfg, lib))
}

fn diff(a: DiffArgs) -> Result<()> {
    if matches!(a.format, Format::Jsonl) {
        bail!("--format jsonl requires lift --emit decomp");
    }
    for kind in &a.show {
        if !["same", "changed", "uncertain", "added", "removed"].contains(&kind.as_str()) {
            bail!("{kind}: --show takes same, changed, uncertain, added, removed");
        }
    }
    let show =
        |kind: &str| (a.show.is_empty() && kind != "same") || a.show.iter().any(|k| k == kind);
    let memory_bytes = a
        .memory_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("memory budget overflow"))?;
    let workers = parallelism::resolve(a.jobs, memory_bytes)?.workers();
    let (old_image, old_cfg, _) = recover(
        &a.old,
        &[],
        None,
        a.cpu.as_deref(),
        a.database.as_deref(),
        RecoveryBudget {
            max_blocks: a.max_blocks,
            workers,
            memory_bytes,
        },
    )?;
    let (new_image, new_cfg, _) = recover(
        &a.new,
        &[],
        None,
        a.cpu.as_deref(),
        a.database.as_deref(),
        RecoveryBudget {
            max_blocks: a.max_blocks,
            workers,
            memory_bytes,
        },
    )?;
    let old = biara_diff::Program::new(&old_cfg, &old_image);
    let new = biara_diff::Program::new(&new_cfg, &new_image);
    for (side, program) in [("old", &old), ("new", &new)] {
        for issue in program.comparison_issues() {
            eprintln!("{side} comparison uncertainty: {issue:?}");
        }
    }
    if matches!(a.format, Format::Json) {
        use biara_proto::diff::FunctionKind;
        let mut report = biara_diff::compare(&old, &new);
        report.functions.retain(|m| {
            show(match m.kind {
                FunctionKind::Same => "same",
                FunctionKind::Changed => "changed",
                FunctionKind::Uncertain => "uncertain",
                FunctionKind::Added => "added",
                FunctionKind::Removed => "removed",
            })
        });
        return json::diff(
            &a,
            json::DiffInput {
                image: &old_image,
                cfg: &old_cfg,
                program: &old,
            },
            json::DiffInput {
                image: &new_image,
                cfg: &new_cfg,
                program: &new,
            },
            &report,
        );
    }
    let matches = biara_diff::diff(&old, &new);
    let mut s = String::new();
    for m in &matches {
        let kind = match m {
            biara_diff::Match::Same { .. } => "same",
            biara_diff::Match::Changed { .. } => "changed",
            biara_diff::Match::Uncertain { .. } => "uncertain",
            biara_diff::Match::Added { .. } => "added",
            biara_diff::Match::Removed { .. } => "removed",
        };
        if show(kind) {
            s += &format!("{}\n", biara_diff::describe(m, &old, &new));
        }
    }
    match a.output {
        Some(p) => fs::write(&p, s).with_context(|| p.display().to_string())?,
        None => io::stdout().lock().write_all(s.as_bytes())?,
    }
    Ok(())
}
