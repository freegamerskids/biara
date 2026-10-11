//! Match recovered functions structurally, then compare their normalized TCG code.
//!
//! `Same` means equal recovered code and corresponding callees, not semantic
//! equivalence. Constants, predicates, operand relationships, helpers and memory
//! offsets participate in equality. Only proven address materializations and
//! translation bookkeeping are normalized. Fingerprints are indexing hints;
//! classification always compares the complete representation. Recursive call
//! graphs are compared by a monotone propagation over matched functions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use biara_cfg::{Cfg, CfgIssue, ExitKind};
use biara_loader::Image;
use biara_tcg::{Block, Opcode, TempId, TempKind};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};

/// A structural matching hint, never proof of code equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(pub u64);

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

fn fingerprint(shape: &Shape) -> Fingerprint {
    use std::hash::{Hash, Hasher};
    struct Fnv(u64);
    impl Hasher for Fnv {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for &byte in bytes {
                self.0 ^= u64::from(byte);
                self.0 = self.0.wrapping_mul(0x100000001b3);
            }
        }
    }
    let mut h = Fnv(0xcbf29ce484222325);
    shape.hash(&mut h);
    Fingerprint(h.finish())
}

/// Structural fingerprints of recovered functions, independent of literal
/// values and callee identities. Use `diff` for code change classification.
pub fn fingerprints(cfg: &Cfg) -> BTreeMap<u64, Fingerprint> {
    cfg.functions
        .keys()
        .map(|&entry| {
            let (code, _) = normalize(cfg, entry, None);
            (entry, fingerprint(&code.shape()))
        })
        .collect()
}

/// Why a recovered program does not support a complete comparison.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ComparisonIssue {
    Unsupported {
        function: u64,
        block: u64,
        operation: String,
    },
    Incomplete {
        function: Option<u64>,
        address: Option<u64>,
        reason: String,
    },
    /// Structurally indistinguishable functions without distinct symbol names.
    Ambiguous { functions: Vec<u64> },
}

/// How a function of one binary relates to the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    /// Equal normalized recovered code and corresponding callees.
    Same {
        old: u64,
        new: u64,
    },
    /// A definite difference in recovered code or a matched callee.
    Changed {
        old: u64,
        new: u64,
    },
    /// Ambiguous pairing, unsupported code, or incomplete recovery.
    Uncertain {
        old: u64,
        new: u64,
    },
    Added {
        new: u64,
    },
    Removed {
        old: u64,
    },
}

impl Match {
    pub fn sort_key(&self) -> (u8, u64, u64) {
        match *self {
            Self::Same { old, new } => (0, old, new),
            Self::Changed { old, new } => (1, old, new),
            Self::Uncertain { old, new } => (2, old, new),
            Self::Added { new } => (3, 0, new),
            Self::Removed { old } => (4, old, 0),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Atom {
    Literal(u64),
    Constant(u64, String),
    Local(u32, String),
    Global(String, String, String, u8, i64, Option<Box<Atom>>),
    Label(u32),
    Block(u32),
    Function(u64),
    Import(String),
    Data(String, u64, Vec<u8>),
    UnknownAddress(u64),
    Tag(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Operation {
    name: String,
    ty: String,
    vece: u8,
    outputs: Vec<Atom>,
    inputs: Vec<Atom>,
    constants: Vec<Atom>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Code {
    blocks: Vec<(Vec<Operation>, Vec<Vec<Atom>>)>,
}

type OperationShape = (String, String, u8, Vec<String>, Vec<String>, usize);
type BlockShape = (Vec<OperationShape>, Vec<Vec<String>>);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Shape(Vec<BlockShape>);

fn atom_shape(atom: &Atom) -> String {
    match atom {
        Atom::Literal(_) | Atom::Data(..) | Atom::UnknownAddress(_) => "value".into(),
        Atom::Constant(_, ty) => format!("constant:{ty}"),
        Atom::Function(_) | Atom::Import(_) => "callee".into(),
        Atom::Local(id, ty) => format!("local:{id}:{ty}"),
        Atom::Global(name, ty, base, sub, offset, parent) => {
            format!("global:{name}:{ty}:{base}:{sub}:{offset}:{parent:?}")
        }
        Atom::Label(id) => format!("label:{id}"),
        Atom::Block(id) => format!("block:{id}"),
        Atom::Tag(tag) => tag.clone(),
    }
}

impl Code {
    fn shape(&self) -> Shape {
        Shape(
            self.blocks
                .iter()
                .map(|(ops, exits)| {
                    (
                        ops.iter()
                            .map(|op| {
                                (
                                    op.name.clone(),
                                    op.ty.clone(),
                                    op.vece,
                                    op.outputs.iter().map(atom_shape).collect(),
                                    op.inputs.iter().map(atom_shape).collect(),
                                    op.constants.len(),
                                )
                            })
                            .collect(),
                        exits
                            .iter()
                            .map(|exit| exit.iter().map(atom_shape).collect())
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    fn callees(&self) -> impl Iterator<Item = u64> + '_ {
        self.blocks
            .iter()
            .flat_map(|(ops, exits)| {
                ops.iter()
                    .flat_map(|op| op.outputs.iter().chain(&op.inputs).chain(&op.constants))
                    .chain(exits.iter().flatten())
            })
            .filter_map(|a| match a {
                Atom::Function(entry) => Some(*entry),
                _ => None,
            })
    }

    fn comparison(
        &self,
        other: &Self,
        pairs: &BTreeMap<u64, u64>,
        ambiguous: &BTreeSet<u64>,
        reverse: &BTreeMap<u64, u64>,
    ) -> u8 {
        // Ambiguous references are uncertainty, not independent code changes.
        // A separate literal/opcode/operand difference still proves a change.
        let atoms = |old: &[Atom], new: &[Atom]| {
            if old.len() != new.len() {
                return 2;
            }
            old.iter()
                .zip(new)
                .map(|(old, new)| match (old, new) {
                    (Atom::Function(o), Atom::Function(n)) if pairs.get(o) == Some(n) => 0,
                    (Atom::Function(o), Atom::Function(n))
                        if ambiguous.contains(o)
                            || reverse.get(n).is_some_and(|o| ambiguous.contains(o)) =>
                    {
                        1
                    }
                    _ => {
                        if old == new {
                            0
                        } else {
                            2
                        }
                    }
                })
                .max()
                .unwrap_or(0)
        };
        if self.blocks.len() != other.blocks.len() {
            return 2;
        }
        let mut state = 0;
        for ((ops, exits), (new_ops, new_exits)) in self.blocks.iter().zip(&other.blocks) {
            if ops.len() != new_ops.len() || exits.len() != new_exits.len() {
                return 2;
            }
            for (o, n) in ops.iter().zip(new_ops) {
                if o.name != n.name || o.ty != n.ty || o.vece != n.vece {
                    return 2;
                }
                state = state
                    .max(atoms(&o.outputs, &n.outputs))
                    .max(atoms(&o.inputs, &n.inputs))
                    .max(atoms(&o.constants, &n.constants));
            }
            for (o, n) in exits.iter().zip(new_exits) {
                state = state.max(atoms(o, n));
            }
        }
        state
    }
}

/// One side of a diff, retaining full normalized code as well as matching hints.
pub struct Program {
    fps: BTreeMap<u64, Fingerprint>,
    codes: BTreeMap<u64, Code>,
    shapes: BTreeMap<u64, Shape>,
    names: BTreeMap<u64, String>,
    symbols: BTreeMap<u64, String>,
    stubs: BTreeSet<u64>,
    incomplete: BTreeSet<u64>,
    issues: Vec<ComparisonIssue>,
}

impl Program {
    pub fn new(cfg: &Cfg, image: &Image) -> Self {
        let stubs: BTreeSet<u64> = cfg
            .functions
            .keys()
            .filter(|&&e| cfg.stub_import(e).is_some())
            .copied()
            .collect();
        let symbols: BTreeMap<u64, String> = cfg
            .functions
            .keys()
            .filter_map(|&e| image.function_at(e).map(|s| (e, s.name.clone())))
            .collect();
        let names = cfg
            .functions
            .keys()
            .map(|&e| {
                (
                    e,
                    symbols
                        .get(&e)
                        .cloned()
                        .or_else(|| cfg.stub_import(e).map(|i| format!("{i}@plt")))
                        .unwrap_or_else(|| format!("{e:#x}")),
                )
            })
            .collect();
        let mut codes = BTreeMap::new();
        let mut issues = Vec::new();
        let mut incomplete = BTreeSet::new();
        for &entry in cfg.functions.keys() {
            let (code, unsupported) = normalize(cfg, entry, Some(image));
            if !unsupported.is_empty() {
                incomplete.insert(entry);
            }
            issues.extend(unsupported);
            codes.insert(entry, code);
        }
        for issue in cfg.issues() {
            let address = match &issue {
                CfgIssue::TranslationFailure { address, .. }
                | CfgIssue::UnknownIndirectCall { address }
                | CfgIssue::UnknownIndirectJump { address }
                | CfgIssue::TableLimit { address, .. } => Some(*address),
                _ => None,
            };
            let reason = format!("{issue:?}");
            let owners: Vec<u64> = cfg
                .functions
                .values()
                .filter(|f| {
                    address.is_none_or(|a| {
                        f.blocks.contains(&a)
                            || f.calls.contains(&a)
                            || f.tail_calls.contains(&a)
                            || f.blocks.iter().any(|b| {
                                cfg.blocks.get(b).is_some_and(|bb| {
                                    bb.exits
                                        .iter()
                                        .any(|exit| exit.kind.local_successors().any(|t| t == a))
                                })
                            })
                    })
                })
                .map(|f| f.entry)
                .collect();
            if owners.is_empty() {
                issues.push(ComparisonIssue::Incomplete {
                    function: None,
                    address,
                    reason,
                });
            } else {
                for entry in owners {
                    incomplete.insert(entry);
                    issues.push(ComparisonIssue::Incomplete {
                        function: Some(entry),
                        address,
                        reason: reason.clone(),
                    });
                }
            }
        }
        let shapes: BTreeMap<u64, Shape> = codes.iter().map(|(&e, c)| (e, c.shape())).collect();
        let fps = shapes
            .iter()
            .map(|(&e, shape)| (e, fingerprint(shape)))
            .collect();
        let mut duplicates: BTreeMap<&Shape, Vec<u64>> = BTreeMap::new();
        for (&e, shape) in &shapes {
            if !stubs.contains(&e) && !symbols.contains_key(&e) {
                duplicates.entry(shape).or_default().push(e);
            }
        }
        for functions in duplicates.into_values().filter(|entries| entries.len() > 1) {
            issues.push(ComparisonIssue::Ambiguous { functions });
        }
        Self {
            fps,
            codes,
            shapes,
            names,
            symbols,
            stubs,
            incomplete,
            issues,
        }
    }

    pub fn name_of(&self, entry: u64) -> Option<String> {
        self.names.get(&entry).cloned()
    }
    pub fn fingerprint(&self, entry: u64) -> Option<Fingerprint> {
        self.fps.get(&entry).copied()
    }
    /// Recovery failures, unsupported normalization, and intrinsic pairing ambiguity.
    pub fn comparison_issues(&self) -> &[ComparisonIssue] {
        &self.issues
    }
    /// `(non-stub functions, skipped import stubs)`.
    pub fn stats(&self) -> (usize, usize) {
        (self.codes.len() - self.stubs.len(), self.stubs.len())
    }
}

/// Pair unique symbol names first, then full structural shapes. Duplicate shape
/// groups are paired deterministically but conservatively classified uncertain.
/// A literal change does not destroy a structural match, and hashes never decide
/// equality. Callee changes and uncertainty propagate to a fixed point, including
/// across recursive components of any size.
pub fn diff(old: &Program, new: &Program) -> Vec<Match> {
    let mut ro: BTreeSet<u64> = old
        .codes
        .keys()
        .filter(|e| !old.stubs.contains(e))
        .copied()
        .collect();
    let mut rn: BTreeSet<u64> = new
        .codes
        .keys()
        .filter(|e| !new.stubs.contains(e))
        .copied()
        .collect();
    let mut pairs = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    let mut names: BTreeMap<&str, (Vec<u64>, Vec<u64>)> = BTreeMap::new();
    for &e in &ro {
        if let Some(name) = old.symbols.get(&e) {
            names.entry(name).or_default().0.push(e);
        }
    }
    for &e in &rn {
        if let Some(name) = new.symbols.get(&e) {
            names.entry(name).or_default().1.push(e);
        }
    }
    for (os, ns) in names.into_values() {
        if os.len() == 1 && ns.len() == 1 {
            pairs.insert(os[0], ns[0]);
            ro.remove(&os[0]);
            rn.remove(&ns[0]);
        }
    }
    let mut shapes: BTreeMap<&Shape, (Vec<u64>, Vec<u64>)> = BTreeMap::new();
    for &e in &ro {
        shapes.entry(&old.shapes[&e]).or_default().0.push(e);
    }
    for &e in &rn {
        shapes.entry(&new.shapes[&e]).or_default().1.push(e);
    }
    for (os, ns) in shapes.into_values() {
        let uncertain = os.len() != 1 || ns.len() != 1;
        for (o, n) in os.into_iter().zip(ns) {
            pairs.insert(o, n);
            ro.remove(&o);
            rn.remove(&n);
            if uncertain {
                ambiguous.insert(o);
            }
        }
    }
    let reverse: BTreeMap<u64, u64> = pairs.iter().map(|(&o, &n)| (n, o)).collect();
    // 0 = equal, 1 = uncertain, 2 = definitely changed. Incomplete recovery
    // cannot prove equality, but a known changed callee remains evidence of
    // change in its callers. Ambiguous pairings never claim definite changes.
    let mut states: BTreeMap<u64, u8> = pairs
        .iter()
        .map(|(&o, &n)| {
            let state = if ambiguous.contains(&o)
                || old.incomplete.contains(&o)
                || new.incomplete.contains(&n)
            {
                1
            } else {
                old.codes[&o].comparison(&new.codes[&n], &pairs, &ambiguous, &reverse)
            };
            (o, state)
        })
        .collect();
    let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &o in pairs.keys() {
        for callee in old.codes[&o].callees() {
            if pairs.contains_key(&callee) {
                callers.entry(callee).or_default().push(o);
            }
        }
        for callee in new.codes[&pairs[&o]].callees() {
            if let Some(&old_callee) = reverse.get(&callee) {
                callers.entry(old_callee).or_default().push(o);
            }
        }
    }
    let mut work: VecDeque<u64> = states
        .iter()
        .filter(|(_, state)| **state != 0)
        .map(|(&o, _)| o)
        .collect();
    while let Some(callee) = work.pop_front() {
        for &caller in callers.get(&callee).into_iter().flatten() {
            if !ambiguous.contains(&caller) && states[&caller] < states[&callee] {
                states.insert(caller, states[&callee]);
                work.push_back(caller);
            }
        }
    }
    let mut out: Vec<Match> = pairs
        .into_iter()
        .map(|(old, new)| match states[&old] {
            0 => Match::Same { old, new },
            2 => Match::Changed { old, new },
            _ => Match::Uncertain { old, new },
        })
        .collect();
    out.extend(ro.into_iter().map(|old| Match::Removed { old }));
    out.extend(rn.into_iter().map(|new| Match::Added { new }));
    out.sort_by_key(Match::sort_key);
    out
}

fn block_order(cfg: &Cfg, entry: u64) -> Vec<u64> {
    let f = &cfg.functions[&entry];
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut work = VecDeque::from([entry]);
    while let Some(b) = work.pop_front() {
        if !f.blocks.contains(&b) || !seen.insert(b) {
            continue;
        }
        order.push(b);
        if let Some(bb) = cfg.blocks.get(&b) {
            for exit in &bb.exits {
                work.extend(exit.kind.local_successors());
            }
            work.extend(cfg.jump_tables.get(&b).into_iter().flatten().copied());
        }
    }
    // Normally all blocks are reachable; preserve any exceptional recovery
    // fragments instead of silently ignoring them.
    order.extend(f.blocks.iter().filter(|b| !seen.contains(b)).copied());
    order
}

fn normalize(cfg: &Cfg, entry: u64, image: Option<&Image>) -> (Code, Vec<ComparisonIssue>) {
    let order = block_order(cfg, entry);
    let ids: BTreeMap<u64, u32> = order
        .iter()
        .enumerate()
        .map(|(i, &b)| (b, i as u32))
        .collect();
    let mut issues = Vec::new();
    let target = |a| {
        if let Some(import) = cfg.stub_import(a) {
            Atom::Import(import.to_owned())
        } else if let Some(&id) = ids.get(&a) {
            Atom::Block(id)
        } else if cfg.functions.contains_key(&a) {
            Atom::Function(a)
        } else {
            Atom::UnknownAddress(a)
        }
    };
    let callee = |a| {
        if let Some(import) = cfg.stub_import(a) {
            Atom::Import(import.to_owned())
        } else if cfg.functions.contains_key(&a) {
            Atom::Function(a)
        } else {
            Atom::UnknownAddress(a)
        }
    };
    let mut blocks = Vec::new();
    for b in order {
        let Some(bb) = cfg.blocks.get(&b) else {
            issues.push(ComparisonIssue::Incomplete {
                function: Some(entry),
                address: Some(b),
                reason: "missing recovered block".into(),
            });
            blocks.push((Vec::new(), Vec::new()));
            continue;
        };
        let block = &bb.block;
        let provenance = image
            .map(|image| address_materializations(block, image))
            .unwrap_or_default();
        let return_operands = if bb.exits.iter().any(|x| {
            matches!(
                x.kind,
                ExitKind::Call { .. } | ExitKind::IndirectCall { .. }
            )
        }) {
            return_address_uses(block, bb.insns.last().copied())
        } else {
            BTreeSet::new()
        };
        let mut locals = BTreeMap::new();
        let mut labels = BTreeMap::new();
        let mut ops = Vec::new();
        for (op_index, op) in block.ops.iter().enumerate() {
            if op.opcode == Opcode::InsnStart {
                continue;
            }
            if matches!(
                op.opcode,
                Opcode::ExitTb | Opcode::GotoTb | Opcode::GotoPtr | Opcode::Discard
            ) {
                continue;
            }
            // PC writes describe transfers already represented by exits. Keep
            // reads (e.g. guest code inspecting PC) and non-PC side effects.
            if !block.outputs(op).is_empty() && block.outputs(op).iter().all(|&id| is_pc(block, id))
            {
                continue;
            }
            if matches!(
                op.opcode,
                Opcode::Other | Opcode::PluginCb | Opcode::PluginMemCb
            ) {
                issues.push(ComparisonIssue::Unsupported {
                    function: entry,
                    block: b,
                    operation: block.op_name(op).to_owned(),
                });
            }
            let mut operand = |id| {
                if return_operands.contains(&(op_index, id)) {
                    return Atom::Tag("return-address".into());
                }
                temp_atom(block, id, &mut locals, |value| {
                    if let Some(address) = provenance.get(&op_index).and_then(|uses| uses.get(&id))
                    {
                        return address_atom(cfg, &ids, image, *address);
                    }
                    Atom::Literal(value)
                })
            };
            let outputs: Vec<Atom> = block.outputs(op).iter().map(|&id| operand(id)).collect();
            let inputs: Vec<Atom> = block.inputs(op).iter().map(|&id| operand(id)).collect();
            if inputs
                .iter()
                .chain(&outputs)
                .any(|a| matches!(a, Atom::UnknownAddress(_)))
            {
                issues.push(ComparisonIssue::Unsupported {
                    function: entry,
                    block: b,
                    operation: "unidentified address referent".into(),
                });
            }
            let constants = if op.opcode == Opcode::Call {
                let helper = block.helper(op);
                // No host helper address or block-local helper table index.
                vec![
                    Atom::Tag(helper.name.clone()),
                    Atom::Literal(u64::from(helper.flags)),
                    Atom::Literal(u64::from(helper.typemask)),
                ]
            } else {
                block
                    .consts(op)
                    .iter()
                    .enumerate()
                    .map(|(i, &value)| {
                        let label = op.opcode == Opcode::SetLabel
                            || op.opcode == Opcode::Br
                            || (op.opcode == Opcode::Brcond && i + 1 == block.consts(op).len());
                        if label {
                            let next = labels.len() as u32;
                            Atom::Label(*labels.entry(value).or_insert(next))
                        } else {
                            Atom::Literal(value)
                        }
                    })
                    .collect()
            };
            ops.push(Operation {
                name: block.op_name(op).to_owned(),
                ty: format!("{:?}", op.ty),
                vece: op.vece,
                outputs,
                inputs,
                constants,
            });
        }
        let mut exits = Vec::new();
        for exit in &bb.exits {
            let mut atoms = match exit.kind {
                ExitKind::Jump(a) => vec![Atom::Tag("jump".into()), target(a)],
                ExitKind::Call { target: a, ret } => {
                    vec![Atom::Tag("call".into()), callee(a), target(ret)]
                }
                ExitKind::IndirectCall { ret, slot } => {
                    let mut a = vec![Atom::Tag("indirect-call".into()), target(ret)];
                    if let Some(import) = slot.and_then(|s| cfg.imports.get(&s)) {
                        a.push(Atom::Import(import.clone()));
                    }
                    a.extend(
                        cfg.indirect_calls
                            .get(&b)
                            .into_iter()
                            .flat_map(|known| &known.targets)
                            .map(|&t| callee(t)),
                    );
                    a
                }
                ExitKind::Return => vec![Atom::Tag("return".into())],
                ExitKind::IndirectJump { slot } => {
                    let mut a = vec![Atom::Tag("indirect-jump".into())];
                    if let Some(import) = slot.and_then(|s| cfg.imports.get(&s)) {
                        a.push(Atom::Import(import.clone()));
                    }
                    a.extend(
                        cfg.jump_tables
                            .get(&b)
                            .into_iter()
                            .flatten()
                            .map(|&t| target(t)),
                    );
                    a
                }
                ExitKind::Syscall { next } => vec![Atom::Tag("syscall".into()), target(next)],
            };
            // Retain which normalized instruction owns the exit, not transient
            // raw TCG indices (which include omitted bookkeeping).
            atoms.push(Atom::Literal(
                block.ops[..exit.op]
                    .iter()
                    .filter(|op| {
                        !matches!(
                            op.opcode,
                            Opcode::InsnStart
                                | Opcode::ExitTb
                                | Opcode::GotoTb
                                | Opcode::GotoPtr
                                | Opcode::Discard
                        ) && !(block.outputs(op).iter().all(|&id| is_pc(block, id))
                            && !block.outputs(op).is_empty())
                    })
                    .count() as u64,
            ));
            exits.push(atoms);
        }
        blocks.push((ops, exits));
    }
    (Code { blocks }, issues)
}

fn is_pc(block: &Block, id: TempId) -> bool {
    block.temp(id).kind == TempKind::Global
        && block
            .temp(id)
            .name
            .as_deref()
            .is_some_and(|n| matches!(n, "pc" | "rip" | "eip"))
}

fn temp_atom(
    block: &Block,
    id: TempId,
    locals: &mut BTreeMap<TempId, u32>,
    literal: impl Fn(u64) -> Atom + Copy,
) -> Atom {
    let t = block.temp(id);
    match t.kind {
        TempKind::Const => {
            let value = if t.ty.bits() == 32 {
                t.value as u32 as u64
            } else {
                t.value as u64
            };
            match literal(value) {
                Atom::Literal(value) => Atom::Constant(
                    value,
                    format!("{:?}:{:?}:{}", t.ty, t.base_type, t.subindex),
                ),
                normalized => normalized,
            }
        }
        TempKind::Global | TempKind::Fixed => Atom::Global(
            t.name.as_deref().unwrap_or("").into(),
            format!("{:?}", t.ty),
            format!("{:?}", t.base_type),
            t.subindex,
            t.mem_offset,
            t.mem_base
                .filter(|&base| base != id)
                .map(|base| Box::new(temp_atom(block, base, locals, literal))),
        ),
        _ => {
            let next = locals.len() as u32;
            Atom::Local(
                *locals.entry(id).or_insert(next),
                format!("{:?}:{:?}:{}", t.ty, t.base_type, t.subindex),
            )
        }
    }
}

fn address_atom(cfg: &Cfg, ids: &BTreeMap<u64, u32>, image: Option<&Image>, address: u64) -> Atom {
    if let Some(import) = cfg.imports.get(&address) {
        return Atom::Import(import.clone());
    }
    if let Some(import) = cfg.stub_import(address) {
        return Atom::Import(import.to_owned());
    }
    if cfg.functions.contains_key(&address) {
        return Atom::Function(address);
    }
    if let Some(&id) = ids.get(&address) {
        return Atom::Block(id);
    }
    if let Some(image) = image
        && let Some(symbol) = image.symbols.iter().find(|s| {
            !s.is_function && s.size > 0 && address >= s.addr && address - s.addr < s.size
        })
    {
        // Bound the entire named object, never compare a truncated prefix.
        // Unsupported/writable referents cannot justify an equality claim.
        if let Some(segment) = image.segment_at(symbol.addr) {
            let available = image
                .data(segment)
                .len()
                .saturating_sub((symbol.addr - segment.addr) as usize);
            if let Ok(size) = usize::try_from(symbol.size)
                && size <= available
            {
                let mut bytes = vec![0; size];
                if image.read_const(symbol.addr, &mut bytes) {
                    return Atom::Data(symbol.name.clone(), address - symbol.addr, bytes);
                }
            }
        }
        return Atom::UnknownAddress(address);
    }
    // Address provenance does not prove a string type or object extent. In
    // particular, a zero byte in anonymous readonly data is not its boundary.
    // Keep these referents unsupported instead of claiming prefix equality.
    Atom::UnknownAddress(address)
}

/// Return-address transport can pass through local moves before reaching LR or
/// the call's stack store. Slice those uses only; matching numeric literals in
/// unrelated operations remain meaningful.
fn return_address_uses(block: &Block, call_pc: Option<u64>) -> BTreeSet<(usize, TempId)> {
    let mut uses = BTreeSet::new();
    let Some(start) = block
        .ops
        .iter()
        .rposition(|op| op.opcode == Opcode::InsnStart && Some(block.consts(op)[0]) == call_pc)
    else {
        return uses;
    };
    let mut needed = BTreeSet::new();
    for index in (start + 1..block.ops.len()).rev() {
        let op = &block.ops[index];
        let linked = block.outputs(op).iter().any(|&id| {
            block
                .temp(id)
                .name
                .as_deref()
                .is_some_and(|name| matches!(name, "lr" | "x30"))
        });
        let definition = block.outputs(op).iter().any(|id| needed.contains(id));
        for id in block.outputs(op) {
            needed.remove(id);
        }
        let input = match op.opcode {
            Opcode::Mov if linked || definition => block.inputs(op).first(),
            Opcode::QemuSt | Opcode::QemuSt2 => block.inputs(op).first(),
            _ => None,
        };
        if let Some(&id) = input {
            let temp = block.temp(id);
            if temp.kind == TempKind::Const {
                if temp.value as u64 == block.end() {
                    uses.insert((index, id));
                }
            } else {
                needed.insert(id);
            }
        }
    }
    uses
}

/// Decoding identifies address formation, then backward def-use slicing selects
/// its actual TCG operands. A coincident numeric immediate in the same guest
/// instruction is not an address use.
fn address_materializations(
    block: &Block,
    image: &Image,
) -> BTreeMap<usize, BTreeMap<TempId, u64>> {
    let mut out: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();
    let mut destinations = BTreeSet::new();
    if image.arch == "x86_64" || image.arch == "i386" {
        let Some((bytes, base)) = image.code_at(block.pc) else {
            return BTreeMap::new();
        };
        let Some(bytes) = bytes.get((block.pc - base) as usize..) else {
            return BTreeMap::new();
        };
        let mut decoder = Decoder::with_ip(
            if image.arch == "x86_64" { 64 } else { 32 },
            bytes,
            block.pc,
            DecoderOptions::NONE,
        );
        while decoder.can_decode() && decoder.ip() < block.end() {
            let insn = decoder.decode();
            if insn.is_ip_rel_memory_operand() {
                let address = insn.ip_rel_memory_address();
                out.entry(insn.ip()).or_default().insert(address, address);
                if insn.mnemonic() == Mnemonic::Lea {
                    destinations.insert(insn.ip());
                }
            }
        }
    } else if image.arch == "aarch64" {
        // ADR/ADRP and ADD-immediate are architectural address formation, unlike
        // MOVZ/MOVK, which can just as well construct numeric literals.
        let mut pages: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
        for pc in (block.pc..block.end()).step_by(4) {
            let Some((bytes, base)) = image.code_at(pc) else {
                break;
            };
            let Some(bytes) = bytes
                .get((pc - base) as usize..)
                .and_then(|bytes| bytes.get(..4))
            else {
                break;
            };
            let word = u32::from_le_bytes(bytes.try_into().unwrap());
            let rd = word & 31;
            if word & 0x1f00_0000 == 0x1000_0000 {
                let imm = i64::from(((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3));
                let imm = (imm << 43) >> 43;
                let page = word & 0x8000_0000 != 0;
                let address = if page {
                    (pc & !4095).wrapping_add((imm << 12) as u64)
                } else {
                    pc.wrapping_add(imm as u64)
                };
                out.entry(pc).or_default().insert(address, address);
                destinations.insert(pc);
                if page {
                    pages.insert(rd, (pc, address));
                } else {
                    pages.remove(&rd);
                }
            } else if word & 0xff80_0000 == 0x9100_0000 {
                let rn = (word >> 5) & 31;
                let offset =
                    u64::from((word >> 10) & 4095) << if word & (1 << 22) != 0 { 12 } else { 0 };
                if let Some(&(page_pc, page)) = pages.get(&rn) {
                    let address = page.wrapping_add(offset);
                    // Both parts represent the same proven address, retaining
                    // their roles in the op stream while ignoring link layout.
                    out.entry(page_pc).or_default().insert(page, address);
                    out.entry(pc).or_default().insert(offset, address);
                    destinations.insert(pc);
                    // ADD defines its destination even when it is also the
                    // source: the value is now page+offset, not the old page.
                    pages.remove(&rd);
                } else {
                    pages.remove(&rd);
                }
            } else {
                // Conservative invalidation: never carry provenance across a
                // possible register definition or a transfer of control.
                pages.clear();
            }
        }
    }
    address_uses(block, &out, &destinations)
}

fn address_uses(
    block: &Block,
    decoded: &BTreeMap<u64, BTreeMap<u64, u64>>,
    destinations: &BTreeSet<u64>,
) -> BTreeMap<usize, BTreeMap<TempId, u64>> {
    let mut uses = BTreeMap::new();
    let starts: Vec<(usize, u64)> = block
        .ops
        .iter()
        .enumerate()
        .filter(|(_, op)| op.opcode == Opcode::InsnStart)
        .map(|(index, op)| (index, block.consts(op)[0]))
        .collect();
    for (instruction, &(start, pc)) in starts.iter().enumerate() {
        let Some(values) = decoded.get(&pc) else {
            continue;
        };
        let end = starts
            .get(instruction + 1)
            .map_or(block.ops.len(), |&(next, _)| next);
        let mut needed = BTreeSet::new();
        for index in (start + 1..end).rev() {
            let op = &block.ops[index];
            if destinations.contains(&pc) {
                needed.extend(
                    block
                        .outputs(op)
                        .iter()
                        .copied()
                        .filter(|&id| block.temp(id).kind == TempKind::Global && !is_pc(block, id)),
                );
            }
            let definition = block.outputs(op).iter().any(|id| needed.contains(id));
            for id in block.outputs(op) {
                needed.remove(id);
            }
            let address = match op.opcode {
                Opcode::QemuLd | Opcode::QemuLd2 => block.inputs(op).first().copied(),
                Opcode::QemuSt | Opcode::QemuSt2 => block.inputs(op).last().copied(),
                _ => None,
            };
            for &id in block.inputs(op) {
                if !definition && Some(id) != address {
                    continue;
                }
                let temp = block.temp(id);
                if temp.kind == TempKind::Const {
                    let value = if temp.ty.bits() == 32 {
                        temp.value as u32 as u64
                    } else {
                        temp.value as u64
                    };
                    if let Some(&target) = values.get(&value) {
                        uses.entry(index)
                            .or_insert_with(BTreeMap::new)
                            .insert(id, target);
                    }
                } else {
                    needed.insert(id);
                }
            }
        }
    }
    uses
}

/// One line per match, naming both sides where present.
pub fn describe(m: &Match, old: &Program, new: &Program) -> String {
    let at = |p: &Program, e: u64| {
        format!(
            "{e:#x}{}",
            p.name_of(e).map(|n| format!(" <{n}>")).unwrap_or_default()
        )
    };
    match *m {
        Match::Same { old: o, new: n } => format!("same {} == {}", at(old, o), at(new, n)),
        Match::Changed { old: o, new: n } => format!("changed {} -> {}", at(old, o), at(new, n)),
        Match::Uncertain { old: o, new: n } => format!("uncertain {} ~ {}", at(old, o), at(new, n)),
        Match::Added { new: n } => format!("added {}", at(new, n)),
        Match::Removed { old: o } => format!("removed {}", at(old, o)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Cfg(#[from] biara_cfg::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(value: u64, callee: Option<u64>) -> Code {
        Code {
            blocks: vec![(
                vec![Operation {
                    name: "setcond".into(),
                    ty: "I64".into(),
                    vece: 0,
                    outputs: vec![Atom::Global(
                        "rax".into(),
                        "I64".into(),
                        "I64".into(),
                        0,
                        16,
                        None,
                    )],
                    inputs: vec![
                        Atom::Local(0, "I64".into()),
                        Atom::Constant(value, "I64".into()),
                    ],
                    constants: vec![Atom::Literal(8)],
                }],
                vec![callee.map_or_else(
                    || vec![Atom::Tag("return".into())],
                    |entry| vec![Atom::Tag("call".into()), Atom::Function(entry)],
                )],
            )],
        }
    }

    fn program(entries: Vec<(u64, Code)>, named: bool) -> Program {
        let codes: BTreeMap<u64, Code> = entries.into_iter().collect();
        let shapes: BTreeMap<u64, Shape> = codes.iter().map(|(&e, c)| (e, c.shape())).collect();
        let names: BTreeMap<u64, String> = codes.keys().map(|&e| (e, format!("f{e}"))).collect();
        Program {
            // Deliberate collisions: equality must not depend on these hints.
            fps: codes.keys().map(|&e| (e, Fingerprint(0))).collect(),
            symbols: if named {
                names.clone()
            } else {
                BTreeMap::new()
            },
            names,
            codes,
            shapes,
            stubs: BTreeSet::new(),
            incomplete: BTreeSet::new(),
            issues: Vec::new(),
        }
    }

    #[test]
    fn operands_predicates_helpers_and_offsets_are_meaningful() {
        let original = code(1, None);
        let old = program(vec![(1, original.clone())], true);
        let mut mutations = Vec::new();
        mutations.push(code(2, None));
        let mut predicate = original.clone();
        predicate.blocks[0].0[0].constants[0] = Atom::Literal(9);
        mutations.push(predicate);
        let mut operands = original.clone();
        operands.blocks[0].0[0].inputs.swap(0, 1);
        mutations.push(operands);
        let mut offset = original.clone();
        offset.blocks[0].0[0].outputs[0] =
            Atom::Global("rax".into(), "I64".into(), "I64".into(), 0, 24, None);
        mutations.push(offset);
        let mut helper_old = original.clone();
        helper_old.blocks[0].0[0].name = "call".into();
        helper_old.blocks[0].0[0].constants = vec![Atom::Tag("helper_one".into())];
        let mut helper_new = helper_old.clone();
        helper_new.blocks[0].0[0].constants = vec![Atom::Tag("helper_two".into())];
        assert!(matches!(
            diff(
                &program(vec![(1, helper_old)], true),
                &program(vec![(1, helper_new)], true)
            )[0],
            Match::Changed { .. }
        ));
        for mutation in mutations {
            assert!(matches!(
                diff(&old, &program(vec![(1, mutation)], true))[0],
                Match::Changed { .. }
            ));
        }
        assert!(matches!(diff(&old, &old)[0], Match::Same { .. }));
    }

    #[test]
    fn recursive_graphs_propagate_without_a_round_limit() {
        let entries: Vec<(u64, Code)> = (1..=40)
            .map(|entry| (entry, code(1, Some(entry % 40 + 1))))
            .collect();
        let old = program(entries.clone(), true);
        let identical = program(entries.clone(), true);
        assert!(
            diff(&old, &identical)
                .iter()
                .all(|m| matches!(m, Match::Same { .. }))
        );
        let mut changed = program(entries, true);
        changed.codes.get_mut(&1).unwrap().blocks[0].0[0].inputs[1] =
            Atom::Constant(2, "I64".into());
        assert!(
            diff(&old, &changed)
                .iter()
                .all(|m| matches!(m, Match::Changed { .. }))
        );
        let mut incomplete = identical;
        incomplete.incomplete.insert(20);
        assert!(
            diff(&old, &incomplete)
                .iter()
                .all(|m| matches!(m, Match::Uncertain { .. }))
        );
        changed.incomplete.insert(20);
        assert!(
            diff(&old, &changed)
                .iter()
                .all(|m| matches!(m, Match::Changed { .. }))
        );
    }

    #[test]
    fn duplicate_shapes_do_not_prove_correspondence() {
        let old = program(vec![(1, code(1, None)), (2, code(1, None))], false);
        let new = program(vec![(3, code(1, None)), (4, code(1, None))], false);
        assert!(
            diff(&old, &new)
                .iter()
                .all(|m| matches!(m, Match::Uncertain { .. }))
        );
    }

    #[test]
    fn corresponding_recursive_callees_ignore_rebases() {
        let old = program(vec![(1, code(1, Some(2))), (2, code(1, Some(1)))], true);
        let mut new = program(
            vec![(101, code(1, Some(102))), (102, code(1, Some(101)))],
            true,
        );
        new.symbols = BTreeMap::from([(101, "f1".into()), (102, "f2".into())]);
        assert!(
            diff(&old, &new)
                .iter()
                .all(|m| matches!(m, Match::Same { .. }))
        );
    }

    #[test]
    fn ambiguous_callee_correspondence_is_not_a_definite_caller_change() {
        let mut old = program(
            vec![
                (1, code(1, Some(2))),
                (2, code(1, None)),
                (3, code(1, None)),
            ],
            false,
        );
        old.symbols.insert(1, "caller".into());
        let mut new = program(
            vec![
                (101, code(1, Some(103))),
                (102, code(1, None)),
                (103, code(1, None)),
            ],
            false,
        );
        new.symbols.insert(101, "caller".into());
        assert!(
            diff(&old, &new)
                .iter()
                .all(|m| matches!(m, Match::Uncertain { .. }))
        );
        new.codes.get_mut(&101).unwrap().blocks[0].0[0].inputs[1] = Atom::Constant(9, "I64".into());
        assert!(
            diff(&old, &new)
                .iter()
                .any(|m| matches!(m, Match::Changed { old: 1, new: 101 }))
        );
    }
}
