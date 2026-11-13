//! Version-one reports stream records to the sink; addresses remain unsigned
//! integers and uncertainty is separate from findings or code equality.
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Write},
    path::Path,
};

use anyhow::{Context, Result};
use biara_cfg::{Cfg, ExitKind};
use biara_lift::{
    Arg, CallSite, CallSites, Callee, SizeRange,
    audit::{
        self, Finding, Input, Issue,
        object::{ObjectBound, ObjectEvidence, ObjectOrigin, ObjectPointer, ObjectQuery},
    },
};
use biara_loader::Image;
use biara_tcg::ContextInfo;
use inkwell::targets::TargetMachine;
use serde::{Serialize, Serializer, ser::SerializeSeq};
use serde_json::{Value, json};

use crate::{DiffArgs, Emit, Format, LiftArgs};

struct Rows<F>(F);
impl<F, I, T> Serialize for Rows<F>
where
    F: Fn() -> I,
    I: Iterator<Item = T>,
    T: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        for row in (self.0)() {
            seq.serialize_element(&row)?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct ImageInfo<'a> {
    path: &'a Path,
    arch: &'static str,
    os: &'static str,
    entry: u64,
}
fn image_info<'a>(path: &'a Path, image: &Image) -> ImageInfo<'a> {
    ImageInfo {
        path,
        arch: image.arch,
        os: image.os,
        entry: image.entry,
    }
}

struct Completeness<'a>(&'a Cfg);
impl Serialize for Completeness<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Status<R: Serialize, I: Serialize> {
            recovery: R,
            issues: I,
        }
        Status {
            recovery: &self.0.recovery,
            issues: Rows(|| self.0.issues()),
        }
        .serialize(serializer)
    }
}

#[derive(Serialize)]
struct Report<'a, A: Serialize> {
    schema_version: u32,
    kind: &'static str,
    image: ImageInfo<'a>,
    completeness: Completeness<'a>,
    debug: &'a biara_loader::DebugStatus,
    assumptions: &'static [&'static str],
    analysis: A,
}

fn emit(pretty: bool, path: Option<&Path>, report: &impl Serialize) -> Result<()> {
    let write = |out: &mut dyn Write| -> Result<()> {
        if pretty {
            serde_json::to_writer_pretty(&mut *out, report)?;
        } else {
            serde_json::to_writer(&mut *out, report)?;
        }
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    };
    match path {
        Some(path) => write(&mut io::BufWriter::new(
            File::create(path).with_context(|| path.display().to_string())?,
        ))
        .with_context(|| path.display().to_string()),
        None => write(&mut io::stdout().lock()),
    }
}

pub(crate) fn object_bound(image: &Image, query: ObjectQuery) -> Option<ObjectBound> {
    match query {
        ObjectQuery::Global { address } => {
            let mut symbols = image.symbols.iter().filter(|s| {
                !s.is_function
                    && s.size != 0
                    && address >= s.addr
                    && address - s.addr < s.size
                    && image.code_at(s.addr).is_none()
                    && image
                        .segments
                        .iter()
                        .any(|seg| seg.contains(s.addr) && s.size <= seg.size - (s.addr - seg.addr))
            });
            let symbol = symbols.next()?;
            if symbols.any(|s| (s.addr, s.size) != (symbol.addr, symbol.size)) {
                return None;
            }
            Some(ObjectBound {
                origin: ObjectOrigin::Global {
                    name: symbol.name.clone(),
                    address: symbol.addr,
                },
                offset: i64::try_from(address - symbol.addr).ok()?,
                size: SizeRange {
                    lo: symbol.size,
                    hi: symbol.size,
                },
                evidence: ObjectEvidence::DataSymbol {
                    name: symbol.name.clone(),
                    address: symbol.addr,
                },
            })
        }
        ObjectQuery::Stack {
            function,
            pc,
            entry_offset,
        } => {
            let object = image.stack_object(function, pc, entry_offset)?;
            Some(ObjectBound {
                origin: ObjectOrigin::Stack {
                    function,
                    name: object.name.clone(),
                    entry_offset: object.offset,
                },
                offset: entry_offset.checked_sub(object.offset)?,
                size: SizeRange {
                    lo: object.size,
                    hi: object.size,
                },
                evidence: ObjectEvidence::Dwarf { function, pc },
            })
        }
    }
}

fn arg(value: &Arg) -> Value {
    match value {
        Arg::Const(v) => json!({"kind":"constant","value":v}),
        Arg::OneOf(vs) => {
            json!({"kind":"alternatives","values":vs.iter().map(arg).collect::<Vec<_>>()})
        }
        Arg::Stack(off) => json!({"kind":"entry_stack","offset":off}),
        Arg::Incoming(reg) => json!({"kind":"incoming","register":reg}),
        Arg::Deref { reg, off } => {
            json!({"kind":"entry_load","register":reg,"offset":off,"bytes":8})
        }
        Arg::Load { base, off, bits } => {
            json!({"kind":"load","base":arg(base),"offset":off,"bits":bits})
        }
        Arg::Returned { import, pc } => {
            json!({"kind":"import_result","import":import,"address":pc})
        }
        Arg::FunctionResult { function, pc } => {
            json!({"kind":"function_result","function":function,"address":pc})
        }
        Arg::RegisterResult { function, pc, reg } => {
            json!({"kind":"register_result","function":function,"address":pc,"register":reg})
        }
        Arg::Allocation {
            function,
            pc,
            allocator,
            size,
        } => {
            json!({"kind":"allocation_site","function":function,"address":pc,"allocator":allocator,"size":size.map(size_json),"nullable":true})
        }
        Arg::Offset { base, off } => json!({"kind":"offset","base":arg(base),"offset":off}),
        Arg::Frame { function, pc, off } => {
            json!({"kind":"callee_frame","function":function,"address":pc,"offset":off})
        }
        Arg::Range { lo, hi } => json!({"kind":"unsigned_range","lo":lo,"hi":hi}),
        Arg::Expr { op, bits, args } => {
            json!({"kind":"expression","operation":op,"bits":bits,"arguments":args.iter().map(arg).collect::<Vec<_>>()})
        }
        Arg::Unknown => json!({"kind":"unknown"}),
    }
}
fn size_json(size: SizeRange) -> Value {
    json!({"lo":size.lo,"hi":size.hi})
}
fn origin_json(origin: &ObjectOrigin) -> Value {
    match origin {
        ObjectOrigin::Heap {
            function,
            pc,
            allocator,
        } => {
            json!({"kind":"allocation_site","function":function,"address":pc,"allocator":allocator})
        }
        ObjectOrigin::Global { name, address } => {
            json!({"kind":"data_symbol","name":name,"address":address})
        }
        ObjectOrigin::Stack {
            function,
            name,
            entry_offset,
        } => {
            json!({"kind":"declared_stack_object","function":function,"name":name,"entry_offset":entry_offset})
        }
    }
}
fn evidence_json(e: &ObjectEvidence) -> Value {
    match e {
        ObjectEvidence::AllocatorArguments { function, pc } => {
            json!({"kind":"allocator_arguments","function":function,"address":pc})
        }
        ObjectEvidence::DataSymbol { name, address } => {
            json!({"kind":"data_symbol","name":name,"address":address})
        }
        ObjectEvidence::Dwarf { function, pc } => {
            json!({"kind":"dwarf_location","function":function,"address":pc})
        }
    }
}
fn pointer_json(p: &ObjectPointer) -> Value {
    json!({"origin":p.origin.as_ref().map(origin_json),"offset":p.offset,
        "size":p.size.map(size_json),"nullable":p.origin.as_ref().map(|_|p.nullable),
        "unknown_extent":p.unknown_extent.map(|r| match r {
            audit::object::UnknownExtent::AllocationSizeUnknown => "allocation_size_unknown",
            audit::object::UnknownExtent::NoDataSymbol => "no_data_symbol",
            audit::object::UnknownExtent::NoDebugObject => "no_debug_object",
            audit::object::UnknownExtent::UnresolvedReturn => "unresolved_return",
            audit::object::UnknownExtent::IncomingPointer => "incoming_pointer",
            audit::object::UnknownExtent::UnknownPointer => "unknown_pointer",
            audit::object::UnknownExtent::OffsetOverflow => "offset_overflow",
        }),
        "evidence":p.evidence.iter().map(evidence_json).collect::<Vec<_>>()})
}
fn callee(c: &Callee) -> Value {
    match c {
        Callee::Import(name) => json!({"kind":"import","name":name}),
        Callee::Function(address) => json!({"kind":"function","address":address}),
        Callee::Indirect { target } => json!({"kind":"indirect","target":arg(target)}),
    }
}
pub(crate) fn call(c: &CallSite) -> Value {
    json!({"caller":c.caller,"address":c.pc,"callee":callee(&c.callee),"arguments":c.args.iter().map(arg).collect::<Vec<_>>()})
}
fn exit(kind: ExitKind) -> Value {
    match kind {
        ExitKind::Jump(to) => json!({"kind":"jump","target":to}),
        ExitKind::Call { target, ret } => json!({"kind":"call","target":target,"continuation":ret}),
        ExitKind::IndirectCall { ret, slot } => {
            json!({"kind":"indirect_call","continuation":ret,"slot":slot})
        }
        ExitKind::IndirectJump { slot } => json!({"kind":"indirect_jump","slot":slot}),
        ExitKind::Return => json!({"kind":"return"}),
        ExitKind::Syscall { next } => json!({"kind":"syscall","continuation":next}),
    }
}
pub(crate) fn finding(f: &Finding) -> Value {
    let issue = match &f.issue {
        Issue::Format {
            arg: index,
            value,
            at,
            input,
        } => {
            let input = input.as_ref().map(|i| match i {
                Input::CommandLine => json!({"kind":"command_line"}),
                Input::Environment => json!({"kind":"environment"}),
                Input::Read { import, pc } => json!({"kind":"read","import":import,"address":pc}),
            });
            json!({"kind":"nonconstant_format","argument":index,"value":arg(value),"function":at,"input":input})
        }
        Issue::Overflow { frame, below, len } => {
            json!({"kind":"frame_boundary_overflow","function":frame,"below_entry_sp":below,"length":len})
        }
        Issue::Unbounded { frame, below } => {
            json!({"kind":"unbounded_frame_write","function":frame,"below_entry_sp":below})
        }
        Issue::ObjectOverflow { object, len } => {
            json!({"kind":"object_overflow","object":pointer_json(object),"length":size_json(*len)})
        }
        Issue::ObjectUnbounded { object } => {
            json!({"kind":"unbounded_object_write","object":pointer_json(object)})
        }
    };
    json!({"site":call(&f.site),"issue":issue,"path":f.path.iter().map(call).collect::<Vec<_>>()})
}

fn report<'a, A: Serialize>(
    a: &'a LiftArgs,
    image: &'a Image,
    cfg: &'a Cfg,
    kind: &'static str,
    analysis: A,
) -> Report<'a, A> {
    Report {
        schema_version: 1,
        kind,
        image: image_info(&a.binary, image),
        completeness: Completeness(cfg),
        debug: &image.debug_status,
        assumptions: &[
            "Recovered code, not a semantic-equivalence or safety certificate",
            "ABI assumes callees do not overwrite caller register-save slots",
            "Allocation sites do not identify unique runtime objects",
        ],
        analysis,
    }
}

pub(crate) fn types(
    a: &LiftArgs,
    image: &Image,
    cfg: &Cfg,
    analysis: &impl Serialize,
) -> Result<()> {
    let mut report = report(a, image, cfg, "types", analysis);
    report.assumptions = &[
        "Observed layouts describe recovered accesses, not declared object extents",
        "Conflicting or incomplete type evidence does not authorize narrowing memory or arithmetic",
        "ABI assumes callees do not overwrite caller register-save slots",
    ];
    emit(
        matches!(a.format, Format::Text),
        a.output.as_deref(),
        &report,
    )
}

pub(crate) fn lift(
    a: &LiftArgs,
    image: &Image,
    cfg: &Cfg,
    info: &ContextInfo,
    machine: &TargetMachine,
    workers: usize,
    annotations: &biara_proto::annotations::Annotations,
) -> Result<()> {
    let name_of = |address| {
        annotations
            .functions
            .get(&address)
            .and_then(|f| f.name.as_deref())
            .or_else(|| image.function_at(address).map(|f| f.name.as_str()))
            .or_else(|| cfg.stub_import(address))
    };
    match a.emit {
        Emit::Cfg => {
            #[derive(Serialize)]
            struct CfgRows<F: Serialize, B: Serialize> {
                functions: F,
                blocks: B,
            }
            emit(
                false,
                a.output.as_deref(),
                &report(
                    a,
                    image,
                    cfg,
                    "cfg",
                    CfgRows {
                        functions: Rows(|| {
                            cfg.functions.values().map(|f|json!({"address":f.entry,"name":name_of(f.entry),"blocks":f.blocks,"calls":f.calls,"tail_calls":f.tail_calls,"may_return":f.returns}))
                        }),
                        blocks: Rows(|| {
                            cfg.blocks.iter().map(|(&pc,b)|json!({"address":pc,"end":b.end(),"instructions":b.insns,"exits":b.exits.iter().map(|e|exit(e.kind)).collect::<Vec<_>>(),"jump_targets":cfg.jump_tables.get(&pc),"jump_targets_complete":!cfg.incomplete_jump_tables.contains(&pc),"call_targets":cfg.indirect_calls.get(&pc).map(|t|json!({"targets":t.targets,"complete":t.complete}))}))
                        }),
                    },
                ),
            )
        }
        Emit::Abi => {
            let mut abis = biara_abi::analyze_with_workers(cfg, info, workers)?;
            biara_lift::annotations::apply_abi_annotations(cfg, info, &mut abis, annotations)?;
            let names = |set: &BTreeSet<u32>| {
                set.iter()
                    .map(|&g| info.globals[g as usize].name.as_deref())
                    .collect::<Vec<_>>()
            };
            emit(
                false,
                a.output.as_deref(),
                &report(
                    a,
                    image,
                    cfg,
                    "abi",
                    Rows(|| {
                        abis.iter().map(|(&address, abi)| json!({
                    "address":address,"name":name_of(address),
                    "converged":abi.analysis.converged,"rounds":abi.analysis.rounds,
                    "arguments":names(&abi.args),"stack_arguments":abi.stack_args,
                    "returns":names(&abi.returns),"preserved":names(&abi.preserved),
                    "fp_arguments":abi.fp_args,"fp_returns":abi.fp_returns,
                    "fp_conflicts":abi.fp_conflicts,"return_class":abi.ret_class,
                    "fp_argument_types":abi.fp_arg_types,"fp_return_types":abi.fp_ret_types,
                    "frame":{"size":abi.frame.size,"balanced":abi.frame.balanced,
                        "stack_positions":abi.frame.sp_at.iter().map(|(&address,&offset)|
                            json!({"address":address,"entry_offset":offset})).collect::<Vec<_>>(),
                        "accesses":abi.frame.slots.iter().map(|(&offset,&bytes)|
                            json!({"entry_offset":offset,"bytes":bytes})).collect::<Vec<_>>()
                    }
                }))
                    }),
                ),
            )
        }
        Emit::Calls | Emit::Audit => {
            let mut abis = biara_abi::analyze_with_workers(cfg, info, workers)?;
            biara_lift::annotations::apply_abi_annotations(cfg, info, &mut abis, annotations)?;
            let mut sites = CallSites::with_abis(machine, info, cfg, Some(abis))?;
            let findings = if matches!(a.emit, Emit::Audit) {
                audit::audit(
                    &mut sites,
                    &image.indirect_entries(),
                    image.main,
                    &|address, buf| image.read_const(address, buf),
                    &|q| object_bound(image, q),
                )?
            } else {
                let mut batch = BTreeSet::new();
                for &address in cfg.functions.keys() {
                    batch.insert(address);
                    if batch.len() == 64 {
                        sites.add(&batch)?;
                        batch.clear();
                    }
                }
                sites.add(&batch)?;
                Vec::new()
            };
            #[derive(Serialize)]
            struct Calls<C: Serialize, F: Serialize> {
                calls: C,
                findings: F,
            }
            let regs = sites.arg_registers();
            emit(
                false,
                a.output.as_deref(),
                &report(
                    a,
                    image,
                    cfg,
                    if matches!(a.emit, Emit::Audit) {
                        "audit"
                    } else {
                        "calls"
                    },
                    Calls {
                        calls: Rows(|| {
                            sites.sites().iter().map(|c| {
                    let mut row=call(c);
                    row["arguments"]=Value::Array(c.args.iter().enumerate().map(|(i,raw)| {
                        let value=sites.resolve_arg(raw,c.caller);
                        let alternatives=match &value {Arg::OneOf(vs)=>vs.as_slice(),v=>std::slice::from_ref(v)};
                        json!({"register":regs.get(i),"raw":arg(raw),"value":arg(&value),"object_alternatives":alternatives.iter().map(|v|pointer_json(&audit::object::pointer_facts(v,c.caller,c.pc,&|q|object_bound(image,q)))).collect::<Vec<_>>()})
                    }).collect());
                    row
                })
                        }),
                        findings: Rows(|| findings.iter().map(finding)),
                    },
                ),
            )
        }
        _ => unreachable!("raw output rejected before recovery"),
    }
}

pub(crate) struct DiffInput<'a> {
    pub image: &'a Image,
    pub cfg: &'a Cfg,
    pub program: &'a biara_diff::Program,
}

pub(crate) fn diff(
    a: &DiffArgs,
    old: DiffInput<'_>,
    new: DiffInput<'_>,
    report: &biara_proto::diff::DiffReport,
) -> Result<()> {
    #[derive(Serialize)]
    struct Report<'a> {
        schema_version: u32,
        kind: &'static str,
        old_image: ImageInfo<'a>,
        new_image: ImageInfo<'a>,
        old_completeness: Completeness<'a>,
        new_completeness: Completeness<'a>,
        old_comparison_issues: &'a [biara_diff::ComparisonIssue],
        new_comparison_issues: &'a [biara_diff::ComparisonIssue],
        comparison: &'static str,
        matches: &'a [biara_proto::diff::FunctionDiff],
        diff_issues: &'a [biara_proto::diff::DiffIssue],
    }
    emit(
        false,
        a.output.as_deref(),
        &Report {
            schema_version: biara_proto::SCHEMA_VERSION,
            kind: "diff",
            old_image: image_info(&a.old, old.image),
            new_image: image_info(&a.new, new.image),
            old_completeness: Completeness(old.cfg),
            new_completeness: Completeness(new.cfg),
            old_comparison_issues: old.program.comparison_issues(),
            new_comparison_issues: new.program.comparison_issues(),
            comparison: "normalized recovered TCG code; matching is not semantic equivalence",
            matches: &report.functions,
            diff_issues: &report.issues,
        },
    )
}
