//! A function's control-flow graph as the graph view draws it: one node per basic block with
//! its decoded instructions, and edges typed by how control reaches the target.

use std::collections::HashMap;

use biara_cfg::ExitKind;

use super::{
    disasm::{self, Insn},
    graph::{Edge, EdgeKind},
    program::Program,
};

/// A basic block with its instructions decoded.
#[derive(Clone, Debug)]
pub struct FlowNode {
    pub addr: u64,
    pub end: u64,
    pub insns: Vec<Insn>,
    /// The block ends the function: a return, or a jump out of it.
    pub exits_function: bool,
}

/// A function's blocks and the edges between them.
#[derive(Clone, Debug)]
pub struct FlowGraph {
    pub entry: u64,
    /// Nodes sorted by address; the entry block is `nodes[entry_index]`.
    pub nodes: Vec<FlowNode>,
    pub entry_index: usize,
    pub edges: Vec<Edge>,
}

/// Blocks beyond this are not drawn: the graph would be unreadable, and layout cost grows
/// faster than the node count.
pub const MAX_NODES: usize = 1500;

#[derive(Debug, PartialEq, Eq)]
pub enum FlowError {
    NotAFunction,
    TooLarge(usize),
}

impl FlowGraph {
    /// Build the graph of the function at `entry`.
    pub fn build(program: &Program, entry: u64) -> Result<FlowGraph, FlowError> {
        let function = program
            .cfg
            .functions
            .get(&entry)
            .ok_or(FlowError::NotAFunction)?;
        if function.blocks.len() > MAX_NODES {
            return Err(FlowError::TooLarge(function.blocks.len()));
        }
        // BTreeSet iterates in address order, which is the node order.
        let blocks: Vec<_> = function
            .blocks
            .iter()
            .filter_map(|b| program.cfg.blocks.get(b))
            .collect();
        let index: HashMap<u64, usize> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.pc(), i))
            .collect();
        let mut nodes = Vec::with_capacity(blocks.len());
        let mut edges = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            let mut insns = Vec::with_capacity(block.insns.len());
            for (k, &pc) in block.insns.iter().enumerate() {
                let next = block
                    .insns
                    .get(k + 1)
                    .copied()
                    .unwrap_or_else(|| block.end());
                let mut buf = vec![0u8; (next - pc) as usize];
                if program.image.read(pc, &mut buf) {
                    insns.push(disasm::decode(program.arch, pc, &buf));
                }
            }
            let (jumps, mut other): (Vec<_>, Vec<_>) = block
                .exits
                .iter()
                .map(|e| e.kind)
                .partition(|k| matches!(k, ExitKind::Jump(_)));
            let mut exits_function = block
                .exits
                .iter()
                .any(|e| matches!(e.kind, ExitKind::Return));
            let mut add = |to: u64, kind: EdgeKind| {
                if let Some(&j) = index.get(&to) {
                    edges.push(Edge {
                        from: i,
                        to: j,
                        kind,
                    });
                    true
                } else {
                    false
                }
            };
            // A block with two jump exits is a conditional branch: the target that is not
            // the next block is the taken side.
            let targets: Vec<u64> = jumps
                .iter()
                .filter_map(|k| {
                    if let ExitKind::Jump(t) = k {
                        Some(*t)
                    } else {
                        None
                    }
                })
                .collect();
            match targets.as_slice() {
                [t] => {
                    if !add(*t, EdgeKind::Unconditional) {
                        exits_function = true; // a tail call leaves the function
                    }
                }
                many => {
                    for &t in many {
                        let kind = if t == block.end() {
                            EdgeKind::NotTaken
                        } else {
                            EdgeKind::Taken
                        };
                        if !add(t, kind) {
                            exits_function = true;
                        }
                    }
                }
            }
            for k in other.drain(..) {
                match k {
                    ExitKind::Call { ret, .. } | ExitKind::IndirectCall { ret, .. } => {
                        add(ret, EdgeKind::Unconditional);
                    }
                    ExitKind::Syscall { next } => {
                        add(next, EdgeKind::Unconditional);
                    }
                    ExitKind::IndirectJump { .. } => {
                        // A jump table: one edge per case.
                        let site = block.insns.last().copied().unwrap_or(block.pc());
                        let cases = program.cfg.jump_tables.get(&site);
                        let mut any = false;
                        for &t in cases.into_iter().flatten() {
                            any |= add(t, EdgeKind::Table);
                        }
                        if !any {
                            exits_function = true;
                        }
                    }
                    ExitKind::Return | ExitKind::Jump(_) => {}
                }
            }
            nodes.push(FlowNode {
                addr: block.pc(),
                end: block.end(),
                insns,
                exits_function,
            });
        }
        let entry_index = index.get(&entry).copied().ok_or(FlowError::NotAFunction)?;
        Ok(FlowGraph {
            entry,
            nodes,
            entry_index,
            edges,
        })
    }
}
