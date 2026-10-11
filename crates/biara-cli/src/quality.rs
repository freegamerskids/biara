//! Same-address recovery measurements against a symbol-bearing reference.
//!
//! Function symbols are a bounded oracle, not a list of every real function.
//! Edges are observations from reference recovery, not an independent proof
//! of completeness or vulnerability recall. Candidate-only observations are
//! reported outside that oracle, never labelled false positives.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Write},
    num::NonZeroUsize,
    path::PathBuf,
};

use anyhow::{Context as _, Result, bail};
use biara_cfg::{Cfg, CfgIssue, ExitKind};
use biara_loader::Image;
use clap::ValueEnum;
use serde::Serialize;

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    Text,
    Json,
}

#[derive(clap::Args)]
pub(crate) struct QualityArgs {
    /// Symbol-bearing executable: the function-symbol oracle.
    reference: PathBuf,
    /// Stripped copy of the same executable, at the same mapped addresses.
    candidate: PathBuf,
    /// Stop after this many translation blocks per executable.
    #[arg(long, default_value_t = 1_000_000)]
    max_blocks: usize,
    /// QEMU CPU model.
    #[arg(long)]
    cpu: Option<String>,
    /// Shared analysis workers, capped to available logical CPUs minus one.
    #[arg(long)]
    jobs: Option<NonZeroUsize>,
    /// Persistent analysis database; default content-addressed user cache.
    #[arg(long)]
    database: Option<PathBuf>,
    #[arg(long, default_value_t = 1.0, value_parser = recall_threshold)]
    min_function_recall: f64,
    #[arg(long, default_value_t = 1.0, value_parser = recall_threshold)]
    min_edge_recall: f64,
    #[arg(long, default_value_t = 0)]
    max_translation_failures: usize,
    #[arg(long)]
    max_unknown_edges: Option<usize>,
    #[arg(long, value_parser = resource_threshold)]
    max_seconds: Option<f64>,
    #[arg(long, value_parser = resource_threshold)]
    max_rss_mib: Option<f64>,
    /// Output file; default stdout. Reports are flushed before gate failure.
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

fn resource_threshold(value: &str) -> std::result::Result<f64, String> {
    let value: f64 = value
        .parse()
        .map_err(|_| "expected a finite nonnegative number")?;
    if value.is_finite() && value >= 0.0 {
        Ok(value)
    } else {
        Err("expected a finite nonnegative number".into())
    }
}

fn recall_threshold(value: &str) -> std::result::Result<f64, String> {
    let value = resource_threshold(value)?;
    if value <= 1.0 {
        Ok(value)
    } else {
        Err("recall must be between 0 and 1".into())
    }
}

#[derive(Serialize)]
struct OracleScope {
    functions: &'static str,
    edges: &'static str,
    reference_is_completeness_certificate: bool,
    outside_oracle_is_false_positive: bool,
    vulnerability_recall: Option<f64>,
}

#[derive(Serialize)]
struct Comparison<T> {
    oracle_count: usize,
    candidate_count: usize,
    matched: Vec<T>,
    matched_count: usize,
    recall: Option<f64>,
    missing: Vec<T>,
    outside_oracle: Vec<T>,
}

fn compare<T: Ord + Clone>(oracle: &BTreeSet<T>, candidate: &BTreeSet<T>) -> Comparison<T> {
    let matched: Vec<_> = oracle.intersection(candidate).cloned().collect();
    let matched_count = matched.len();
    Comparison {
        oracle_count: oracle.len(),
        candidate_count: candidate.len(),
        matched_count,
        matched,
        recall: (!oracle.is_empty()).then(|| matched_count as f64 / oracle.len() as f64),
        missing: oracle.difference(candidate).cloned().collect(),
        outside_oracle: candidate.difference(oracle).cloned().collect(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum EdgeKind {
    Jump,
    DirectCall,
    CallReturn,
    SyscallReturn,
    IndirectCall,
    IndirectJump,
}

/// Instruction addresses, rather than translation-block starts, keep edge
/// identity stable when symbol seeds change the partition into blocks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Edge {
    source: u64,
    target: u64,
    kind: EdgeKind,
}

fn edge_source(block: &biara_cfg::BasicBlock, exit: &biara_cfg::Exit) -> u64 {
    block.block.ops[..=exit.op]
        .iter()
        .rev()
        .find(|op| op.opcode == biara_tcg::Opcode::InsnStart)
        .map(|op| block.block.consts(op)[0])
        .unwrap_or(block.pc())
}

fn edges(cfg: &Cfg) -> BTreeSet<Edge> {
    let mut result = BTreeSet::new();
    // Visit each function's blocks once instead of scanning every function
    // for every call. Shared blocks can legitimately have multiple owners.
    for function in cfg.functions.values() {
        for pc in &function.blocks {
            let Some(block) = cfg.blocks.get(pc) else {
                continue;
            };
            for exit in &block.exits {
                let (target, kind) = match exit.kind {
                    ExitKind::Call { ret, .. } | ExitKind::IndirectCall { ret, .. } => {
                        (ret, EdgeKind::CallReturn)
                    }
                    ExitKind::Syscall { next } => (next, EdgeKind::SyscallReturn),
                    _ => continue,
                };
                if function.blocks.contains(&target) {
                    result.insert(Edge {
                        source: edge_source(block, exit),
                        target,
                        kind,
                    });
                }
            }
        }
    }
    for (&pc, block) in &cfg.blocks {
        for exit in &block.exits {
            let source = edge_source(block, exit);
            let mut insert = |target, kind| {
                result.insert(Edge {
                    source,
                    target,
                    kind,
                });
            };
            match exit.kind {
                ExitKind::Jump(target) => insert(target, EdgeKind::Jump),
                ExitKind::Call { target, .. } => insert(target, EdgeKind::DirectCall),
                ExitKind::IndirectCall { .. } => {
                    if let Some(targets) = cfg.indirect_calls.get(&pc) {
                        for &target in &targets.targets {
                            insert(target, EdgeKind::IndirectCall);
                        }
                    }
                }
                ExitKind::IndirectJump { .. } => {
                    if let Some(targets) = cfg.jump_tables.get(&pc) {
                        for &target in targets {
                            insert(target, EdgeKind::IndirectJump);
                        }
                    }
                }
                ExitKind::Syscall { .. } | ExitKind::Return => {}
            }
        }
    }
    result
}

#[derive(Serialize)]
struct RecoveryMetrics<'a> {
    functions: usize,
    blocks: usize,
    translation_failures: usize,
    unknown_edges: usize,
    issues: Vec<CfgIssue<'a>>,
    /// No issues is only an absence of recorded limitations, not a proof.
    has_recorded_limitations: bool,
    recovery: &'a biara_cfg::RecoveryStatus,
}

fn recovery_metrics(cfg: &Cfg) -> RecoveryMetrics<'_> {
    let issues: Vec<_> = cfg.issues().collect();
    let translation_failures = issues
        .iter()
        .filter(|issue| matches!(issue, CfgIssue::TranslationFailure { .. }))
        .count();
    let unknown_edges = issues
        .iter()
        .filter(|issue| {
            matches!(
                issue,
                CfgIssue::UnknownIndirectCall { .. } | CfgIssue::UnknownIndirectJump { .. }
            )
        })
        .count();
    RecoveryMetrics {
        functions: cfg.functions.len(),
        blocks: cfg.blocks.len(),
        translation_failures,
        unknown_edges,
        has_recorded_limitations: !issues.is_empty(),
        issues,
        recovery: &cfg.recovery,
    }
}

#[derive(Serialize)]
struct Resources {
    scope: &'static str,
    wall_seconds: f64,
    peak_rss_mib: Option<f64>,
    peak_rss_unavailable_reason: Option<String>,
}

fn resources() -> Resources {
    let (peak_rss_mib, peak_rss_unavailable_reason) = peak_rss();
    Resources {
        scope: "whole process from main entry, sampled immediately before report emission; Linux RSS is the process high-water mark",
        wall_seconds: crate::PROCESS_STARTED
            .get()
            .expect("main records process start")
            .elapsed()
            .as_secs_f64(),
        peak_rss_mib,
        peak_rss_unavailable_reason,
    }
}

#[cfg(target_os = "linux")]
fn peak_rss() -> (Option<f64>, Option<String>) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage initializes the supplied rusage on success; Linux reports KiB.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return (None, Some(io::Error::last_os_error().to_string()));
    }
    let usage = unsafe { usage.assume_init() };
    (Some(usage.ru_maxrss as f64 / 1024.0), None)
}

#[cfg(not(target_os = "linux"))]
fn peak_rss() -> (Option<f64>, Option<String>) {
    (
        None,
        Some("Linux getrusage maxRSS measurement is unavailable on this platform".into()),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Minimum,
    Maximum,
}

#[derive(Serialize)]
struct Gate {
    metric: &'static str,
    direction: Direction,
    threshold: f64,
    measured: Option<f64>,
    passed: bool,
}

fn gate(metric: &'static str, direction: Direction, threshold: f64, measured: Option<f64>) -> Gate {
    let passed = measured.is_some_and(|value| match direction {
        Direction::Minimum => value >= threshold,
        Direction::Maximum => value <= threshold,
    });
    Gate {
        metric,
        direction,
        threshold,
        measured,
        passed,
    }
}

#[derive(Serialize)]
struct Report<'a> {
    version: u32,
    reference: &'a std::path::Path,
    candidate: &'a std::path::Path,
    architecture: &'static str,
    max_blocks_per_image: usize,
    cpu: Option<&'a str>,
    oracle_scope: OracleScope,
    function_names: BTreeMap<u64, Vec<&'a str>>,
    functions: Comparison<u64>,
    edges: Comparison<Edge>,
    reference_recovery: RecoveryMetrics<'a>,
    candidate_recovery: RecoveryMetrics<'a>,
    resources: Resources,
    gates: Vec<Gate>,
    passed: bool,
}

/// Compare the loader's code ranges at identical executable mappings.
/// Stripping may change ELF headers inside RX segments, but not these ranges.
fn same_code(reference: &Image, candidate: &Image) -> Result<()> {
    if reference.arch != candidate.arch
        || reference.os != candidate.os
        || reference.entry != candidate.entry
        || reference.code != candidate.code
    {
        bail!(
            "code mismatch: architecture, entry point or code addresses differ (rebased comparisons are unsupported)"
        );
    }
    let left_mappings = reference
        .segments
        .iter()
        .filter(|s| s.exec)
        .map(|s| (s.addr, s.size));
    let right_mappings = candidate
        .segments
        .iter()
        .filter(|s| s.exec)
        .map(|s| (s.addr, s.size));
    if !left_mappings.eq(right_mappings) {
        bail!("code mismatch: executable mappings differ (rebased comparisons are unsupported)");
    }
    for range in &reference.code {
        fn code<'a>(image: &'a Image, range: &std::ops::Range<u64>) -> Result<&'a [u8]> {
            let (bytes, base) = image.code_at(range.start).ok_or_else(|| {
                anyhow::anyhow!("code mismatch: unmapped code at {:#x}", range.start)
            })?;
            let start = usize::try_from(range.start - base)?;
            let size = usize::try_from(range.end - range.start)?;
            bytes
                .get(start..start.checked_add(size).context("code range overflow")?)
                .context("code range is not file-backed")
        }
        if code(reference, range)? != code(candidate, range)? {
            bail!(
                "code mismatch: executable bytes differ at {:#x}",
                range.start
            );
        }
    }
    Ok(())
}

pub(crate) fn run(args: QualityArgs) -> Result<()> {
    // Reject invalid pairs before invoking either recovery engine.
    let reference =
        Image::load(&args.reference).with_context(|| args.reference.display().to_string())?;
    let candidate =
        Image::load(&args.candidate).with_context(|| args.candidate.display().to_string())?;
    same_code(&reference, &candidate)?;
    if !reference
        .symbols
        .iter()
        .any(|s| s.is_function && reference.is_code(s.addr))
    {
        bail!("reference has no executable function symbols for the oracle");
    }
    // Preflight images are not analysis inputs; release them before the helper
    // loads its images so redundant copies do not inflate the process peak.
    drop(reference);
    drop(candidate);
    let workers = crate::parallelism::resolve(args.jobs)?.workers();
    let (reference, reference_cfg, reference_lib) = crate::recover(
        &args.reference,
        &[],
        args.max_blocks,
        None,
        args.cpu.as_deref(),
        args.database.as_deref(),
        workers,
    )?;
    drop(reference_lib);
    let mut function_names: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
    for symbol in reference
        .symbols
        .iter()
        .filter(|s| s.is_function && reference.is_code(s.addr))
    {
        function_names
            .entry(symbol.addr)
            .or_default()
            .push(&symbol.name);
    }
    let oracle_functions = function_names.keys().copied().collect();
    let (_, candidate_cfg, candidate_lib) = crate::recover(
        &args.candidate,
        &[],
        args.max_blocks,
        None,
        args.cpu.as_deref(),
        args.database.as_deref(),
        workers,
    )?;
    drop(candidate_lib);
    let functions = compare(
        &oracle_functions,
        &candidate_cfg.functions.keys().copied().collect(),
    );
    let edges = compare(&edges(&reference_cfg), &edges(&candidate_cfg));
    let reference_recovery = recovery_metrics(&reference_cfg);
    let candidate_recovery = recovery_metrics(&candidate_cfg);
    let resources = resources();
    let mut gates = vec![
        gate(
            "function_recall",
            Direction::Minimum,
            args.min_function_recall,
            functions.recall,
        ),
        gate(
            "edge_recall",
            Direction::Minimum,
            args.min_edge_recall,
            edges.recall,
        ),
        gate(
            "translation_failures",
            Direction::Maximum,
            args.max_translation_failures as f64,
            Some(candidate_recovery.translation_failures as f64),
        ),
    ];
    if let Some(threshold) = args.max_unknown_edges {
        gates.push(gate(
            "unknown_edges",
            Direction::Maximum,
            threshold as f64,
            Some(candidate_recovery.unknown_edges as f64),
        ));
    }
    if let Some(threshold) = args.max_seconds {
        gates.push(gate(
            "wall_seconds",
            Direction::Maximum,
            threshold,
            Some(resources.wall_seconds),
        ));
    }
    if let Some(threshold) = args.max_rss_mib {
        gates.push(gate(
            "peak_rss_mib",
            Direction::Maximum,
            threshold,
            resources.peak_rss_mib,
        ));
    }
    let passed = gates.iter().all(|g| g.passed);
    let report = Report {
        version: 1,
        reference: &args.reference,
        candidate: &args.candidate,
        architecture: reference.arch,
        max_blocks_per_image: args.max_blocks,
        cpu: args.cpu.as_deref(),
        oracle_scope: OracleScope {
            functions: "defined executable function-symbol addresses in the reference; aliases deduplicated by address",
            edges: "direct transfers, recovered local continuations, and resolved indirect targets observed by reference recovery, identified by source instruction, target and kind; returns and dynamic import destinations are excluded",
            reference_is_completeness_certificate: false,
            outside_oracle_is_false_positive: false,
            vulnerability_recall: None,
        },
        function_names,
        functions,
        edges,
        reference_recovery,
        candidate_recovery,
        resources,
        gates,
        passed,
    };
    match &args.output {
        Some(path) => {
            let mut output = File::create(path).with_context(|| path.display().to_string())?;
            emit_report(&mut output, &report, args.format)?;
        }
        None => emit_report(&mut io::stdout().lock(), &report, args.format)?,
    }
    if !passed {
        bail!("quality threshold gates failed; report emitted");
    }
    Ok(())
}

fn emit_report(mut output: &mut dyn Write, report: &Report<'_>, format: Format) -> Result<()> {
    match format {
        Format::Json => {
            serde_json::to_writer_pretty(&mut output, report)?;
            writeln!(output)?;
        }
        Format::Text => write_text(output, report)?,
    }
    output.flush()?;
    Ok(())
}

fn write_text(output: &mut dyn Write, report: &Report<'_>) -> Result<()> {
    writeln!(
        output,
        "biara quality v{} ({})",
        report.version, report.architecture
    )?;
    writeln!(output, "reference: {}", report.reference.display())?;
    writeln!(output, "candidate: {}", report.candidate.display())?;
    writeln!(
        output,
        "max_blocks_per_image={} cpu={}",
        report.max_blocks_per_image,
        report.cpu.unwrap_or("libtcg default")
    )?;
    writeln!(output, "Function oracle: {}", report.oracle_scope.functions)?;
    writeln!(output, "Edge oracle: {}", report.oracle_scope.edges)?;
    writeln!(
        output,
        "Reference recovery is NOT a completeness certificate. Outside-oracle observations are not false positives. Vulnerability recall is not measured."
    )?;
    for (name, oracle, candidate, matched, recall) in [
        (
            "functions",
            report.functions.oracle_count,
            report.functions.candidate_count,
            report.functions.matched_count,
            report.functions.recall,
        ),
        (
            "edges",
            report.edges.oracle_count,
            report.edges.candidate_count,
            report.edges.matched_count,
            report.edges.recall,
        ),
    ] {
        write!(
            output,
            "{name}: oracle={oracle} candidate={candidate} matched={matched} recall="
        )?;
        match recall {
            Some(value) => writeln!(output, "{value:.6}")?,
            None => writeln!(output, "unavailable (empty oracle)")?,
        }
    }
    writeln!(output, "missing functions: {:?}", report.functions.missing)?;
    writeln!(
        output,
        "outside-oracle functions: {:?}",
        report.functions.outside_oracle
    )?;
    writeln!(output, "missing edges: {:?}", report.edges.missing)?;
    writeln!(
        output,
        "outside-oracle edges: {:?}",
        report.edges.outside_oracle
    )?;
    for (name, metrics) in [
        ("reference", &report.reference_recovery),
        ("candidate", &report.candidate_recovery),
    ] {
        writeln!(
            output,
            "{name}: functions={} blocks={} translation_failures={} unknown_edges={}",
            metrics.functions, metrics.blocks, metrics.translation_failures, metrics.unknown_edges
        )?;
        for issue in &metrics.issues {
            write!(output, "{name} issue: ")?;
            serde_json::to_writer(&mut *output, issue)?;
            writeln!(output)?;
        }
    }
    writeln!(output, "resources: {}", report.resources.scope)?;
    writeln!(output, "wall_seconds={:.6}", report.resources.wall_seconds)?;
    match report.resources.peak_rss_mib {
        Some(rss) => writeln!(output, "peak_rss_mib={rss:.3}")?,
        None => writeln!(
            output,
            "peak_rss_mib=unavailable: {}",
            report
                .resources
                .peak_rss_unavailable_reason
                .as_deref()
                .unwrap_or("unavailable")
        )?,
    }
    for gate in &report.gates {
        let direction = match gate.direction {
            Direction::Minimum => ">=",
            Direction::Maximum => "<=",
        };
        writeln!(
            output,
            "{}: {} {:?} {} {}",
            if gate.passed { "PASS" } else { "FAIL" },
            gate.metric,
            gate.measured,
            direction,
            gate.threshold
        )?;
    }
    writeln!(
        output,
        "quality gates: {}",
        if report.passed { "PASS" } else { "FAIL" }
    )?;
    Ok(())
}
