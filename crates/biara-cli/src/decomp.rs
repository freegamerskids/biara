//! Function-focused presentation is analysis, not a standalone translation unit.
//! Records retain uncertainty; bounded context and chunking never imply complete
//! recovery. Readability gates are diagnostics, not semantic-correctness proofs.
//!
//! CLI examples:
//! `biara lift binary target --emit decomp`
//! `biara lift binary target --emit decomp --format jsonl --context-depth 1
//! --context-functions 16 --chunk-lines 80 --max-body-tokens 500`
//!
//! Schema version 1 has an index with recovery limits and selected/omitted
//! addresses, function records with ABI/call/debug facts and source links,
//! bounded code chunks, and a final readability report. Chunk text concatenates
//! to the complete function body; continuation fragments are not standalone C.
//! Statement IDs are function-address scoped and deterministic for identical
//! inputs, not persistent identities across binary revisions. Source addresses
//! are surviving contributors, not exhaustive instruction coverage.
//!
//! Context expands only recovered caller/callee edges. Unknown targets and
//! incomplete caller knowledge remain explicit, including when a cap is hit.
//! Failed readability gates emit the complete report before returning nonzero.
//! Use `--emit c` for executable support; analysis lists referenced dependencies
//! after the body and never hides dispatcher/helper requirements by fabricating
//! a standalone translation unit.
use crate::{Format, LiftArgs};
use anyhow::{Context, Result, bail};
use biara_cfg::{Cfg, ExitKind};
use biara_lift::{FunctionPackage, ReadabilityMetrics};
use biara_loader::Image;
use biara_tcg::Libtcg;
use inkwell::{context::Context as LlvmContext, targets::TargetMachine};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::File,
    io::{self, Write},
    sync::Arc,
};

#[derive(clap::Args)]
pub(crate) struct Options {
    /// Caller/callee context radius for --emit decomp; roots are emitted first.
    #[arg(long, default_value_t = 0)]
    context_depth: usize,
    /// Maximum exported functions, including roots; omissions are explicit.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    context_functions: u32,
    /// Maximum body lines per chunk; cuts prefer low-nesting statement boundaries.
    #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u32).range(1..))]
    chunk_lines: u32,
    /// Fail after emitting the report if any function exceeds this token estimate.
    #[arg(long)]
    max_body_tokens: Option<u64>,
    /// Maximum explicit casts per function (diagnostic, not a correctness score).
    #[arg(long)]
    max_casts: Option<u64>,
    #[arg(long)]
    max_gotos: Option<u64>,
    #[arg(long)]
    max_register_names: Option<u64>,
    #[arg(long)]
    max_nesting: Option<u64>,
    /// Minimum fraction of emitted statements with known source contributors.
    #[arg(long, value_parser = fraction)]
    min_provenance: Option<f64>,
}
fn fraction(value: &str) -> std::result::Result<f64, String> {
    let n: f64 = value
        .parse()
        .map_err(|_| "expected a fraction in [0,1]".to_string())?;
    if n.is_finite() && (0.0..=1.0).contains(&n) {
        Ok(n)
    } else {
        Err("expected a fraction in [0,1]".into())
    }
}
impl Options {
    pub(crate) fn validate(&self, decomp: bool) -> Result<()> {
        if !decomp
            && (self.context_depth != 0
                || self.context_functions != 64
                || self.chunk_lines != 200
                || self.max_body_tokens.is_some()
                || self.max_casts.is_some()
                || self.max_gotos.is_some()
                || self.max_register_names.is_some()
                || self.max_nesting.is_some()
                || self.min_provenance.is_some())
        {
            bail!("context, chunking and readability gates require --emit decomp");
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct Selection {
    roots: Vec<u64>,
    functions: Vec<u64>,
    omitted: Vec<u64>,
    depth: usize,
    limit: u32,
    callers_complete: bool,
}
fn runtime(name: &str) -> bool {
    matches!(
        name,
        "_start"
            | "_init"
            | "_fini"
            | "_dl_relocate_static_pie"
            | "deregister_tm_clones"
            | "register_tm_clones"
            | "__do_global_dtors_aux"
            | "frame_dummy"
    )
}
fn select(a: &LiftArgs, image: &Image, cfg: &Cfg) -> Result<Selection> {
    let roots = if a.at.is_empty() {
        let mut roots: Vec<_> = cfg
            .functions
            .keys()
            .copied()
            .filter(|&e| cfg.stub_import(e).is_none())
            .collect();
        roots.sort_by_key(|&e| (image.function_at(e).is_some_and(|f| runtime(&f.name)), e));
        roots
    } else {
        a.at.iter()
            .map(|s| crate::resolve(image, s))
            .collect::<Result<Vec<_>>>()?
    };
    let mut neighbors: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (&entry, f) in &cfg.functions {
        for &callee in f.calls.iter().chain(&f.tail_calls) {
            if cfg.functions.contains_key(&callee) && cfg.stub_import(callee).is_none() {
                neighbors.entry(entry).or_default().insert(callee);
                neighbors.entry(callee).or_default().insert(entry);
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    for &root in &roots {
        if seen.insert(root) {
            queue.push_back((root, 0));
        }
    }
    let mut functions = Vec::new();
    let mut omitted = Vec::new();
    while let Some((entry, depth)) = queue.pop_front() {
        if !cfg.functions.contains_key(&entry) || cfg.stub_import(entry).is_some() {
            continue;
        }
        if functions.len() < a.decomp.context_functions as usize {
            functions.push(entry);
        } else {
            omitted.push(entry);
        }
        if depth < a.decomp.context_depth {
            for &next in neighbors.get(&entry).into_iter().flatten() {
                if seen.insert(next) {
                    queue.push_back((next, depth + 1));
                }
            }
        }
    }
    if functions.is_empty() {
        bail!("no recovered function bodies selected");
    }
    Ok(Selection {
        roots,
        functions,
        omitted,
        depth: a.decomp.context_depth,
        limit: a.decomp.context_functions,
        callers_complete: false,
    })
}

fn function_facts(
    image: &Image,
    cfg: &Cfg,
    abis: &BTreeMap<u64, biara_abi::FunctionAbi>,
    entry: u64,
) -> Value {
    let f = &cfg.functions[&entry];
    let callees: Vec<_> = f.calls.iter().chain(&f.tail_calls).map(|&e| json!({"address":e,"name":image.function_at(e).map(|f|&f.name),"import":cfg.stub_import(e)})).collect();
    let callers: Vec<_> = cfg
        .functions
        .values()
        .filter(|f| f.calls.contains(&entry) || f.tail_calls.contains(&entry))
        .map(|f| f.entry)
        .collect();
    let mut indirect = Vec::new();
    for &pc in &f.blocks {
        for exit in &cfg.blocks[&pc].exits {
            match exit.kind {
                ExitKind::IndirectCall { slot, .. } | ExitKind::IndirectJump { slot } => {
                    let import = slot.and_then(|s| cfg.imports.get(&s));
                    let (targets, complete) = match exit.kind {
                        ExitKind::IndirectCall { .. } => (
                            cfg.indirect_calls.get(&pc).map(|t| &t.targets),
                            cfg.indirect_calls.get(&pc).is_some_and(|t| t.complete),
                        ),
                        _ => (
                            cfg.jump_tables.get(&pc),
                            cfg.jump_tables.contains_key(&pc)
                                && !cfg.incomplete_jump_tables.contains(&pc),
                        ),
                    };
                    indirect.push(json!({"block_address":pc,"import":import,"targets":targets,"exhaustive":import.is_some() || complete}));
                }
                _ => {}
            }
        }
    }
    let abi = abis.get(&entry).map(|abi| json!({"status":abi.analysis,"frame_bytes":abi.frame.size,"balanced":abi.frame.balanced,"unknown_sp_blocks":abi.frame.sp_at.iter().filter(|(_,v)|v.is_none()).map(|(&pc,_)|pc).collect::<Vec<_>>()}));
    let issues: Vec<_> = cfg.issues().filter(|issue| match issue {
        biara_cfg::CfgIssue::TranslationFailure { address, .. } => f.calls.contains(address) || f.tail_calls.contains(address) || f.blocks.iter().any(|b| cfg.blocks[b].exits.iter().any(|x| matches!(x.kind, ExitKind::Jump(t) | ExitKind::Call {target:t,..} if t == *address))),
        biara_cfg::CfgIssue::UnknownIndirectCall {address} | biara_cfg::CfgIssue::UnknownIndirectJump {address} | biara_cfg::CfgIssue::TableLimit {address,..} => f.blocks.contains(address),
        _ => true,
    }).collect();
    json!({"category":if image.function_at(entry).is_some_and(|f|runtime(&f.name)){"runtime"}else{"application_or_unknown"},"callees":callees,"callers":callers,"callers_exhaustive":false,"indirect_transfers":indirect,"abi":abi,"issues":issues,"stack_objects":image.stack_objects.iter().filter(|o|o.function==entry).collect::<Vec<_>>(),"debug_parameters":image.debug_names.iter().filter(|o|o.function==entry).collect::<Vec<_>>()})
}
fn debug_register(arch: &str, reg: u16) -> Option<String> {
    match arch {
        "x86_64" => [
            "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ]
        .get(reg as usize)
        .map(|s| s.to_string()),
        "aarch64" if reg < 31 => Some(format!("x{reg}")),
        _ => None,
    }
}
pub(crate) fn apply_debug(transformed: &mut biara_lift::TransformedC<'_>, image: &Image) {
    let names: Vec<_> = image
        .debug_names
        .iter()
        .filter_map(|n| {
            Some(biara_lift::DebugName {
                function: n.function,
                register: debug_register(image.arch, n.register)?,
                name: n.name.clone(),
            })
        })
        .collect();
    transformed.apply_debug_names(&names);
    let objects: Vec<_> = image
        .stack_objects
        .iter()
        .map(|o| biara_lift::DebugObject {
            function: o.function,
            start: o.range.start,
            end: o.range.end,
            offset: o.offset,
            size: o.size,
            name: o.name.clone(),
            type_name: o.type_name.clone(),
        })
        .collect();
    transformed.apply_debug_objects(&objects);
}

#[derive(Serialize)]
struct Chunk<'a> {
    id: String,
    first_line: usize,
    last_line: usize,
    statement_ids: Vec<&'a str>,
    text: &'a str,
    fragment: bool,
}
fn chunks(package: &FunctionPackage, limit: usize) -> Vec<Chunk<'_>> {
    let lines: Vec<_> = package.body.lines().collect();
    let mut offsets = vec![0];
    for line in package.body.split_inclusive('\n') {
        offsets.push(offsets.last().copied().unwrap_or(0) + line.len());
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < lines.len() {
        let hard_end = (start + limit).min(lines.len());
        let mut end = hard_end;
        if hard_end < lines.len() && limit > 1 {
            // Prefer the shallowest real statement boundary in the latter half.
            let low = start + limit / 2;
            if let Some(s) = package
                .statements
                .iter()
                .filter(|s| {
                    let line = s.line as usize;
                    line > low && line <= hard_end
                })
                .min_by_key(|s| {
                    (
                        lines[s.line as usize - 1]
                            .chars()
                            .take_while(|c| c.is_whitespace())
                            .count(),
                        std::cmp::Reverse(s.line),
                    )
                })
            {
                end = s.line as usize - 1;
            }
        }
        if end <= start {
            end = hard_end;
        }
        chunks.push(Chunk {
            id: format!("function_{:x}/chunk{}", package.address, chunks.len()),
            first_line: start + 1,
            last_line: end,
            statement_ids: package
                .statements
                .iter()
                .filter(|s| s.line as usize > start && s.line as usize <= end)
                .map(|s| s.id.as_str())
                .collect(),
            text: &package.body[offsets[start]..offsets[end]],
            fragment: start != 0 || end != lines.len(),
        });
        start = end;
    }
    chunks
}
struct StatementLinks<'a>(&'a [biara_lift::PackageStatement]);
impl Serialize for StatementLinks<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        #[derive(Serialize)]
        struct Link<'a> {
            id: &'a str,
            line: u64,
            addresses: &'a [u64],
            provenance: &'a str,
        }
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for s in self.0 {
            sequence.serialize_element(&Link {
                id: &s.id,
                line: s.line,
                addresses: &s.addresses,
                provenance: &s.provenance,
            })?;
        }
        sequence.end()
    }
}
struct Header<'a>(&'a FunctionPackage);
impl Serialize for Header<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let p = self.0;
        let mut map = serializer.serialize_map(Some(7))?;
        map.serialize_entry("address", &p.address)?;
        map.serialize_entry("name", &p.name)?;
        map.serialize_entry("signature", &p.signature)?;
        // Body text appears once in chunks; links reference its line numbers.
        map.serialize_entry("statements", &StatementLinks(&p.statements))?;
        map.serialize_entry("dependencies", &p.dependencies)?;
        map.serialize_entry("names", &p.names)?;
        map.serialize_entry("metrics", &p.metrics)?;
        map.end()
    }
}
#[derive(Serialize)]
struct Gate {
    function: u64,
    metric: &'static str,
    measured: f64,
    threshold: f64,
    passed: bool,
}
fn gates(address: u64, m: &ReadabilityMetrics, opts: &Options) -> Vec<Gate> {
    let mut gates = Vec::new();
    for (metric, measured, threshold) in [
        ("tokens", m.tokens, opts.max_body_tokens),
        ("casts", m.casts, opts.max_casts),
        ("gotos", m.gotos, opts.max_gotos),
        ("register_names", m.register_names, opts.max_register_names),
        ("max_nesting", m.max_nesting, opts.max_nesting),
    ] {
        if let Some(threshold) = threshold {
            gates.push(Gate {
                function: address,
                metric,
                measured: measured as f64,
                threshold: threshold as f64,
                passed: measured <= threshold,
            });
        }
    }
    if let Some(threshold) = opts.min_provenance {
        let measured = if m.statements == 0 {
            1.0
        } else {
            m.mapped_statements as f64 / m.statements as f64
        };
        gates.push(Gate {
            function: address,
            metric: "provenance_fraction",
            measured,
            threshold,
            passed: measured >= threshold,
        });
    }
    gates
}
fn write_json(out: &mut dyn Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(out, value).map_err(io::Error::other)
}

fn text_context(out: &mut dyn Write, facts: &Value) -> io::Result<()> {
    writeln!(out, "/* Analysis evidence:")?;
    writeln!(
        out,
        " * category: {}; known callers are not exhaustive",
        facts["category"].as_str().unwrap_or("unknown")
    )?;
    if let Some(abi) = facts["abi"].as_object() {
        writeln!(
            out,
            " * ABI: {}; frame {} bytes; balanced {}; unknown SP blocks {}",
            if abi["status"]["converged"] == true {
                "converged"
            } else {
                "provisional"
            },
            abi["frame_bytes"],
            abi["balanced"],
            abi["unknown_sp_blocks"]
        )?;
    }
    if let Some(callees) = facts["callees"].as_array() {
        for callee in callees {
            let name = callee["import"]
                .as_str()
                .or_else(|| callee["name"].as_str())
                .unwrap_or("unnamed")
                .replace("*/", "* /");
            writeln!(
                out,
                " * callee {:#x}: {}",
                callee["address"].as_u64().unwrap_or(0),
                name
            )?;
        }
    }
    if let Some(transfers) = facts["indirect_transfers"].as_array() {
        for transfer in transfers {
            writeln!(
                out,
                " * indirect at {:#x}: candidates {}; exhaustive {}",
                transfer["block_address"].as_u64().unwrap_or(0),
                transfer["targets"],
                transfer["exhaustive"]
            )?;
        }
    }
    if let Some(objects) = facts["stack_objects"].as_array() {
        for object in objects {
            let name = object["name"]
                .as_str()
                .unwrap_or("unnamed")
                .replace("*/", "* /");
            let ty = object["type_name"]
                .as_str()
                .unwrap_or("unknown type")
                .replace("*/", "* /");
            writeln!(
                out,
                " * debug object {}: {}; entry-SP {}; {} bytes; PCs {}..{}",
                name,
                ty,
                object["offset"],
                object["size"],
                object["range"]["start"],
                object["range"]["end"]
            )?;
        }
    }
    if let Some(issues) = facts["issues"].as_array() {
        for issue in issues {
            writeln!(
                out,
                " * incomplete: {}",
                issue.to_string().replace("*/", "* /")
            )?;
        }
    }
    writeln!(out, " */")
}
pub(crate) fn run(
    a: &LiftArgs,
    image: Image,
    cfg: Cfg,
    lib: Arc<Mutex<Libtcg>>,
    machine: &TargetMachine,
    options: biara_lift::DecompileOptions,
) -> Result<()> {
    let selection = select(a, &image, &cfg)?;
    let cx = LlvmContext::create();
    let abis = biara_abi::analyze_with_workers(&cfg, lib.lock().info(), options.workers())?;
    let facts: BTreeMap<_, _> = selection
        .functions
        .iter()
        .map(|&e| (e, function_facts(&image, &cfg, &abis, e)))
        .collect();
    let metadata = json!({"schema_version":1,"kind":"decomp","image":{"path":a.binary,"arch":image.arch,"os":image.os,"entry":image.entry},"selection":selection,"completeness":{"recovery":cfg.recovery,"issues":cfg.issues().collect::<Vec<_>>()},"debug":image.debug_status,"assumptions":["analysis presentation is not standalone executable C","unknown types and source mappings remain unknown","source contributors are surviving metadata, not exhaustive instruction coverage","known callers and indirect candidates need not be exhaustive","readability metrics do not establish semantic correctness","token counts are lexical estimates, not a model tokenizer"]});
    let prepared = {
        let guard = lib.lock();
        let name_of = |e| {
            image
                .function_at(e)
                .map(|f| f.name.clone())
                .or_else(|| cfg.stub_import(e).map(|s| format!("{s}@plt")))
        };
        biara_lift::prepare_c(
            &cx,
            machine,
            guard.info(),
            &cfg,
            &abis,
            &name_of,
            &format!(
                "Decompiled by biara from {} ({}).",
                a.binary.display(),
                image.arch
            ),
            &image.data,
        )?
    };
    drop(abis);
    drop(cfg);
    drop(lib);
    let mut transformed =
        prepared.transform(machine, &|addr, buf| image.read_const(addr, buf), options)?;
    apply_debug(&mut transformed, &image);
    transformed.select_functions(&selection.functions);
    drop(image);
    let mut all_gates = Vec::new();
    let write = |out: &mut dyn Write, all_gates: &mut Vec<Gate>| -> Result<()> {
        match a.format {
            Format::Json => {
                out.write_all(b"{\"schema_version\":1,\"kind\":\"decomp\",\"metadata\":")?;
                write_json(out, &metadata)?;
                out.write_all(b",\"functions\":[")?;
            }
            Format::Jsonl => {
                write_json(out, &json!({"record":"index","metadata":metadata}))?;
                out.write_all(b"\n")?;
            }
            Format::Text => {
                writeln!(
                    out,
                    "/* Function-focused analysis; not standalone C. Use --emit c for executable support. */"
                )?;
                if !selection.omitted.is_empty() {
                    writeln!(
                        out,
                        "/* Context cap: {} functions omitted; --context-functions expands it. */",
                        selection.omitted.len()
                    )?;
                }
            }
        }
        let mut first = true;
        let stats = transformed.visit_functions(&mut |package| {
            let context = facts
                .get(&package.address)
                .ok_or_else(|| io::Error::other("renderer emitted an unselected function"))?;
            all_gates.extend(gates(package.address, &package.metrics, &a.decomp));
            let parts = chunks(&package, a.decomp.chunk_lines as usize);
            match a.format {
                Format::Json | Format::Jsonl => {
                    // Body text lives only in chunks, never duplicated in the header.
                    let header = Header(&package);
                    if matches!(a.format, Format::Json) {
                        #[derive(Serialize)]
                        struct Record<'a> {
                            function: Header<'a>,
                            context: &'a Value,
                            chunks: &'a [Chunk<'a>],
                        }
                        if !first {
                            out.write_all(b",")?;
                        }
                        first = false;
                        write_json(
                            out,
                            &Record {
                                function: header,
                                context,
                                chunks: &parts,
                            },
                        )?;
                    } else {
                        #[derive(Serialize)]
                        struct Record<'a> {
                            record: &'static str,
                            function: Header<'a>,
                            context: &'a Value,
                            chunk_ids: Vec<&'a str>,
                        }
                        write_json(
                            out,
                            &Record {
                                record: "function",
                                function: header,
                                context,
                                chunk_ids: parts.iter().map(|c| c.id.as_str()).collect(),
                            },
                        )?;
                        out.write_all(b"\n")?;
                        #[derive(Serialize)]
                        struct Part<'a> {
                            record: &'static str,
                            function_address: u64,
                            chunk: Chunk<'a>,
                        }
                        for part in parts {
                            write_json(
                                out,
                                &Part {
                                    record: "chunk",
                                    function_address: package.address,
                                    chunk: part,
                                },
                            )?;
                            out.write_all(b"\n")?;
                        }
                    }
                }
                Format::Text => {
                    writeln!(
                        out,
                        "\n/* function_{:x}: {} */",
                        package.address, package.name
                    )?;
                    for part in parts {
                        if part.fragment {
                            writeln!(
                                out,
                                "/* {}: lines {}-{}, continuation fragment */",
                                part.id, part.first_line, part.last_line
                            )?;
                        }
                        out.write_all(part.text.as_bytes())?;
                    }
                    text_context(out, context)?;
                    if !package.dependencies.is_empty() {
                        writeln!(out, "\n/* Referenced support (analysis declarations) */")?;
                        for dep in &package.dependencies {
                            writeln!(out, "{}", dep.text)?;
                        }
                    }
                    writeln!(
                        out,
                        "/* Readability: {} */",
                        serde_json::to_string(&package.metrics).map_err(io::Error::other)?
                    )?;
                }
            }
            Ok(())
        })?;
        let passed = all_gates.iter().all(|g| g.passed);
        let report = json!({"passed":passed,"gates":all_gates,"unsupported":stats.unsupported});
        match a.format {
            Format::Json => {
                out.write_all(b"],\"readability\":")?;
                write_json(out, &report)?;
                out.write_all(b"}\n")?;
            }
            Format::Jsonl => {
                write_json(out, &json!({"record":"readability","analysis":report}))?;
                out.write_all(b"\n")?;
            }
            Format::Text => {
                writeln!(out, "\n/* Readability gates: {} */", report)?;
            }
        }
        out.flush()?;
        Ok(())
    };
    match &a.output {
        Some(path) => write(
            &mut io::BufWriter::new(
                File::create(path).with_context(|| path.display().to_string())?,
            ),
            &mut all_gates,
        )
        .with_context(|| path.display().to_string())?,
        None => write(&mut io::stdout().lock(), &mut all_gates)?,
    }
    if all_gates.iter().any(|g| !g.passed) {
        bail!("decompilation readability thresholds failed (report emitted)");
    }
    Ok(())
}
