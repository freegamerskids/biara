//! Bounded guest-memory provenance. Snapshots point into a sparse effect graph,
//! not copies of the frame. Different register bases may alias; only identical
//! bases and nonoverlapping byte ranges can prove a store irrelevant.
use std::collections::{BTreeMap, HashMap, HashSet};

use biara_tcg::TempId;
use inkwell::{
    AtomicOrdering,
    basic_block::BasicBlock,
    values::{BasicValueEnum, FunctionValue, InstructionOpcode, InstructionValue, Operand},
};

use crate::Arg;

const MAX_NODES: usize = 8192;
const MAX_WALK: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(crate) struct Address {
    pub reg: TempId,
    pub off: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Read<T> {
    Value { value: T, bits: u32, shift: u32 },
    Entry,
    Unknown,
}

/// A covering store resolves the read. Partial overlap, unknown sizes and
/// different bases cannot establish a value or nonaliasing.
fn store<T>(
    query: Address,
    bits: u32,
    address: Option<Address>,
    stored: u32,
    value: Option<T>,
) -> Option<Read<T>> {
    if bits == 0 || bits > 64 || !bits.is_multiple_of(8) {
        return Some(Read::Unknown);
    }
    let Some(address) = address else {
        return Some(Read::Unknown);
    };
    if address.reg != query.reg || stored == 0 || !stored.is_multiple_of(8) {
        return Some(Read::Unknown);
    }
    let (start, end) = (
        i128::from(query.off),
        i128::from(query.off) + i128::from(bits / 8),
    );
    let (lo, hi) = (
        i128::from(address.off),
        i128::from(address.off) + i128::from(stored / 8),
    );
    if end <= lo || hi <= start {
        return None;
    }
    if lo <= start && end <= hi && stored <= 64 {
        return Some(value.map_or(Read::Unknown, |value| Read::Value {
            value,
            bits: stored,
            shift: ((start - lo) * 8) as u32,
        }));
    }
    Some(Read::Unknown)
}

fn agree<T: Copy + PartialEq>(values: impl IntoIterator<Item = Read<T>>) -> Read<T> {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return Read::Unknown;
    };
    if values.all(|value| value == first) {
        first
    } else {
        Read::Unknown
    }
}

/// Iterative memoized reverse walk: diamonds share answers, cycles remain
/// unknown. `step` appends predecessor keys or returns a terminal answer.
fn walk<K: Copy + Eq + std::hash::Hash, T: Copy + PartialEq>(
    roots: &[K],
    mut step: impl FnMut(K, &mut Vec<K>) -> Option<Read<T>>,
) -> Read<T> {
    enum Work<K> {
        Visit(K),
        Finish(K, std::ops::Range<usize>),
    }
    let mut work: Vec<_> = roots.iter().copied().map(Work::Visit).collect();
    let mut answers = HashMap::new();
    let mut active = HashSet::new();
    let mut edges = Vec::new();
    let mut budget = MAX_WALK;
    while let Some(task) = work.pop() {
        match task {
            Work::Visit(key) => {
                if answers.contains_key(&key) {
                    continue;
                }
                if budget == 0 {
                    return Read::Unknown;
                }
                budget -= 1;
                if !active.insert(key) {
                    answers.insert(key, Read::Unknown);
                    continue;
                }
                let start = edges.len();
                if let Some(answer) = step(key, &mut edges) {
                    edges.truncate(start);
                    answers.insert(key, answer);
                    active.remove(&key);
                } else {
                    let range = start..edges.len();
                    work.push(Work::Finish(key, range.clone()));
                    work.extend(edges[range].iter().rev().copied().map(Work::Visit));
                }
            }
            Work::Finish(key, range) => {
                let answer = agree(
                    edges[range]
                        .iter()
                        .map(|key| answers.get(key).copied().unwrap_or(Read::Unknown)),
                );
                answers.insert(key, answer);
                active.remove(&key);
            }
        }
    }
    agree(
        roots
            .iter()
            .map(|key| answers.get(key).copied().unwrap_or(Read::Unknown)),
    )
}

fn plain(inst: InstructionValue) -> bool {
    !inst.get_volatile().unwrap_or(true)
        && inst.get_atomic_ordering().ok() == Some(AtomicOrdering::NotAtomic)
}

fn width(value: BasicValueEnum) -> u32 {
    match value {
        BasicValueEnum::IntValue(v) => v.get_type().get_bit_width(),
        BasicValueEnum::PointerValue(_) => 64,
        _ => 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Cursor<'ctx> {
    block: BasicBlock<'ctx>,
    before: Option<InstructionValue<'ctx>>,
}

pub(crate) fn read_ir<'ctx>(
    at: InstructionValue<'ctx>,
    query: (Address, u32),
    entry: BasicBlock<'ctx>,
    preds: &HashMap<BasicBlock<'ctx>, Vec<BasicBlock<'ctx>>>,
    address_of: impl Fn(BasicValueEnum<'ctx>) -> Option<Address>,
    env_home: impl Fn(Option<Operand<'ctx>>) -> bool,
    barrier: impl Fn(InstructionValue<'ctx>) -> bool,
) -> Read<BasicValueEnum<'ctx>> {
    let (query, bits) = query;
    if !plain(at) {
        return Read::Unknown;
    }
    let Some(block) = at.get_parent() else {
        return Read::Unknown;
    };
    walk(
        &[Cursor {
            block,
            before: Some(at),
        }],
        |cursor, parents| {
            let mut inst = cursor
                .before
                .and_then(|i| i.get_previous_instruction())
                .or_else(|| {
                    cursor
                        .before
                        .is_none()
                        .then(|| cursor.block.get_last_instruction())
                        .flatten()
                });
            while let Some(i) = inst {
                if i.get_opcode() == InstructionOpcode::Store && !env_home(i.get_operand(1)) {
                    let value = i.get_operand(0).and_then(|op| op.value());
                    let address = i
                        .get_operand(1)
                        .and_then(|op| op.value())
                        .and_then(&address_of);
                    if !plain(i) {
                        return Some(Read::Unknown);
                    }
                    if let Some(answer) = store(query, bits, address, value.map_or(0, width), value)
                    {
                        return Some(answer);
                    }
                } else if barrier(i) {
                    return Some(Read::Unknown);
                }
                // Consume one instruction per walk node; the shared budget also
                // bounds long straight-line scans, not just CFG predecessor count.
                inst = i.get_previous_instruction();
                if inst.is_some() {
                    parents.push(Cursor {
                        block: cursor.block,
                        before: Some(i),
                    });
                    return None;
                }
            }
            if cursor.block == entry {
                return Some(Read::Entry);
            }
            if let Some(previous) = preds.get(&cursor.block) {
                parents.extend(previous.iter().map(|&block| Cursor {
                    block,
                    before: None,
                }));
            }
            None
        },
    )
}

#[derive(serde::Serialize, serde::Deserialize)]
enum Node {
    Entry,
    Unknown,
    Join(Vec<usize>),
    Store {
        previous: usize,
        address: Option<Address>,
        bits: u32,
        value: Arg,
    },
    Barrier,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct MemoryFacts {
    nodes: Vec<Node>,
    calls: BTreeMap<u64, Vec<usize>>,
    pub limited: bool,
}

impl MemoryFacts {
    pub fn lookup(&self, pc: u64, query: Address, bits: u32) -> Read<&Arg> {
        let Some(roots) = self.calls.get(&pc) else {
            return Read::Unknown;
        };
        walk(roots, |id, parents| match self.nodes.get(id) {
            Some(Node::Entry) => Some(Read::Entry),
            Some(Node::Join(previous)) => {
                parents.extend(previous);
                None
            }
            Some(Node::Store {
                previous,
                address,
                bits: stored,
                value,
            }) => {
                if let Some(answer) = store(
                    query,
                    bits,
                    *address,
                    *stored,
                    (!matches!(value, Arg::Unknown)).then_some(value),
                ) {
                    Some(answer)
                } else {
                    parents.push(*previous);
                    None
                }
            }
            _ => Some(Read::Unknown),
        })
    }
}

pub(crate) fn collect<'ctx>(
    f: FunctionValue<'ctx>,
    address_of: impl Fn(BasicValueEnum<'ctx>) -> Option<Address>,
    env_home: impl Fn(Option<Operand<'ctx>>) -> bool,
    classify: impl Fn(BasicValueEnum<'ctx>) -> Arg,
    barrier: impl Fn(InstructionValue<'ctx>) -> bool,
    call_pc: impl Fn(InstructionValue<'ctx>) -> Option<u64>,
) -> MemoryFacts {
    let blocks = f.get_basic_blocks();
    if blocks.len() + 2 > MAX_NODES {
        return MemoryFacts {
            limited: true,
            ..Default::default()
        };
    }
    let mut facts = MemoryFacts {
        nodes: vec![Node::Entry, Node::Unknown],
        ..Default::default()
    };
    let mut heads = HashMap::new();
    let mut tails = HashMap::new();
    for &block in &blocks {
        heads.insert(block, facts.nodes.len());
        facts.nodes.push(Node::Join(Vec::new()));
    }
    for &block in &blocks {
        let mut current = heads[&block];
        for inst in block.get_instructions() {
            if let Some(pc) = call_pc(inst) {
                facts.calls.entry(pc).or_default().push(current);
            }
            let effect = if inst.get_opcode() == InstructionOpcode::Store
                && !env_home(inst.get_operand(1))
            {
                let value = inst.get_operand(0).and_then(|op| op.value());
                let address = inst
                    .get_operand(1)
                    .and_then(|op| op.value())
                    .and_then(&address_of);
                Some(if plain(inst) {
                    Node::Store {
                        previous: current,
                        address,
                        bits: value.map_or(0, width),
                        value: value.map_or(Arg::Unknown, &classify),
                    }
                } else {
                    Node::Barrier
                })
            } else {
                barrier(inst).then_some(Node::Barrier)
            };
            if let Some(effect) = effect {
                if facts.nodes.len() == MAX_NODES {
                    facts.limited = true;
                    current = 1;
                } else if current != 1 {
                    current = facts.nodes.len();
                    facts.nodes.push(effect);
                }
            }
        }
        tails.insert(block, current);
    }
    if let Some(&entry) = blocks.first()
        && let Node::Join(previous) = &mut facts.nodes[heads[&entry]]
    {
        previous.push(0);
    }
    for &block in &blocks {
        if let Some(term) = block.get_terminator() {
            for i in 0..term.get_num_operands() {
                if let Some(to) = term.get_operand(i).and_then(|op| op.block())
                    && let Some(&head) = heads.get(&to)
                    && let Node::Join(previous) = &mut facts.nodes[head]
                {
                    previous.push(tails[&block]);
                }
            }
        }
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    fn at(off: i64) -> Address {
        Address { reg: 7, off }
    }
    #[test]
    fn covering_reads_and_alias_boundaries() {
        let mut facts = MemoryFacts {
            nodes: vec![
                Node::Entry,
                Node::Store {
                    previous: 0,
                    address: Some(at(-16)),
                    bits: 64,
                    value: Arg::Const(0x1122334455667788),
                },
            ],
            calls: BTreeMap::from([(10, vec![1])]),
            limited: false,
        };
        assert_eq!(
            facts.lookup(10, at(-14), 16),
            Read::Value {
                value: &Arg::Const(0x1122334455667788),
                bits: 64,
                shift: 16
            }
        );
        assert_eq!(facts.lookup(10, at(-8), 64), Read::Entry);
        assert_eq!(facts.lookup(10, at(-10), 32), Read::Unknown);
        facts.nodes.push(Node::Store {
            previous: 1,
            address: Some(at(-15)),
            bits: 8,
            value: Arg::Const(0),
        });
        facts.calls.insert(11, vec![2]);
        assert_eq!(facts.lookup(11, at(-16), 64), Read::Unknown);
        facts.nodes.push(Node::Store {
            previous: 1,
            address: Some(Address { reg: 8, off: -16 }),
            bits: 64,
            value: Arg::Const(0),
        });
        facts.calls.insert(12, vec![3]);
        assert_eq!(facts.lookup(12, at(-16), 64), Read::Unknown);
    }
    #[test]
    fn joins_cycles_and_calls_stay_conservative() {
        let mut facts = MemoryFacts {
            nodes: vec![
                Node::Entry,
                Node::Store {
                    previous: 0,
                    address: Some(at(0)),
                    bits: 64,
                    value: Arg::Const(42),
                },
                Node::Store {
                    previous: 0,
                    address: Some(at(0)),
                    bits: 64,
                    value: Arg::Const(42),
                },
                Node::Join(vec![1, 2]),
                Node::Barrier,
                Node::Join(vec![0, 5]),
            ],
            calls: BTreeMap::from([(10, vec![3]), (11, vec![4]), (12, vec![5])]),
            limited: false,
        };
        assert_eq!(
            facts.lookup(10, at(0), 64),
            Read::Value {
                value: &Arg::Const(42),
                bits: 64,
                shift: 0
            }
        );
        facts.nodes[2] = Node::Store {
            previous: 0,
            address: Some(at(0)),
            bits: 64,
            value: Arg::Const(43),
        };
        assert_eq!(facts.lookup(10, at(0), 64), Read::Unknown);
        assert_eq!(facts.lookup(11, at(0), 64), Read::Unknown);
        assert_eq!(facts.lookup(12, at(0), 64), Read::Unknown);
    }
}
