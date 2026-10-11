//! Classify how a translation block leaves: symbolic evaluation of its TCG
//! from the block entry state, read off at every `exit_tb`.
//!
//! Values are tracked as constants, entry values of globals plus an offset,
//! or loads from such addresses; everything else is unknown. That is enough
//! to tell direct jumps, calls (a link value stored at the new stack top or
//! in the link register) and returns (pc loaded from the old stack top, or
//! taken from the link register) apart from genuinely indirect transfers.

use std::collections::HashMap;

use biara_tcg::{Block, MemOp, Opcode, TempId, TempKind, Type, call_flags};

use crate::arch::{ArchSpec, Regs};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ExitKind {
    /// Direct transfer: fallthrough, branch arm, or a jump to another function.
    Jump(u64),
    Call {
        target: u64,
        ret: u64,
    },
    /// Call through a register or memory; resumes at `ret`. `slot` is the
    /// constant address the target was loaded from, if any (a GOT entry).
    IndirectCall {
        ret: u64,
        slot: Option<u64>,
    },
    Return,
    /// pc computed at run time: jump tables, tail calls through pointers,
    /// PLT stubs (`slot` as for `IndirectCall`).
    IndirectJump {
        slot: Option<u64>,
    },
    /// System call; resumes at `next`.
    Syscall {
        next: u64,
    },
}

impl ExitKind {
    /// Addresses this exit may continue at inside the current function.
    pub fn local_successors(self) -> impl Iterator<Item = u64> {
        let (a, b) = match self {
            Self::Jump(t) => (Some(t), None),
            Self::Call { ret, .. } | Self::IndirectCall { ret, .. } => (None, Some(ret)),
            Self::Syscall { next } => (Some(next), None),
            Self::Return | Self::IndirectJump { .. } => (None, None),
        };
        a.into_iter().chain(b)
    }
}

impl std::fmt::Display for ExitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Jump(t) => write!(f, "jump {t:#x}"),
            Self::Call { target, ret } => write!(f, "call {target:#x} -> {ret:#x}"),
            Self::IndirectCall { ret, slot: None } => write!(f, "call indirect -> {ret:#x}"),
            Self::IndirectCall { ret, slot: Some(s) } => write!(f, "call [{s:#x}] -> {ret:#x}"),
            Self::Return => write!(f, "return"),
            Self::IndirectJump { slot: None } => write!(f, "jump indirect"),
            Self::IndirectJump { slot: Some(s) } => write!(f, "jump [{s:#x}]"),
            Self::Syscall { next } => write!(f, "syscall -> {next:#x}"),
        }
    }
}

/// One way out of a block, at op index `op` (an `exit_tb`, `goto_ptr`, or a
/// system-call helper call).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Exit {
    pub op: usize,
    pub kind: ExitKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sym {
    Unknown,
    Const(u64),
    /// Value of global `.0` at block entry, plus `.1`.
    Entry(TempId, i64),
    /// Guest memory at (entry value of global `.0`) + `.1`.
    Load(TempId, i64),
    /// Guest memory at a constant address.
    Mem(u64),
}

#[derive(Clone, PartialEq)]
struct State {
    temps: Vec<Sym>,
    /// Addresses at which the block's end address was stored to guest memory.
    end_stored_at: Vec<Sym>,
}

impl State {
    fn join(&mut self, other: &State) {
        for (a, b) in self.temps.iter_mut().zip(&other.temps) {
            if a != b {
                *a = Sym::Unknown;
            }
        }
        self.end_stored_at
            .retain(|s| other.end_stored_at.contains(s));
    }
}

fn mask(ty: Type) -> u64 {
    if ty.bits() >= 64 {
        u64::MAX
    } else {
        (1 << ty.bits()) - 1
    }
}

/// Guest pcs of the instructions in `block`, in order.
pub fn insn_pcs(block: &Block) -> Vec<u64> {
    block
        .ops
        .iter()
        .filter(|op| op.opcode == Opcode::InsnStart)
        .map(|op| block.consts(op)[0])
        .collect()
}

/// The exits of `block`, and the constants it leaves for others to use:
/// values of globals (other than the pc) at an exit and values stored to
/// memory, the link value excepted. Code pointers among them are function
/// entries (callbacks, stored handlers, `main` for `__libc_start_main`).
pub(crate) fn classify(block: &Block, regs: &Regs, spec: &ArchSpec) -> (Vec<Exit>, Vec<u64>) {
    let end = block.end();
    let mut cur = Some(State {
        temps: block
            .temps
            .iter()
            .enumerate()
            .map(|(i, t)| match t.kind {
                TempKind::Global => Sym::Entry(i as TempId, 0),
                TempKind::Const => Sym::Const(t.value as u64 & mask(t.ty)),
                _ => Sym::Unknown,
            })
            .collect(),
        end_stored_at: Vec::new(),
    });
    let mut pending: HashMap<u64, State> = HashMap::new();
    let mut exits = Vec::new();
    let mut constants = Vec::new();
    let globals: Vec<TempId> = block
        .temps
        .iter()
        .enumerate()
        .filter(|(_, t)| t.kind == TempKind::Global)
        .map(|(i, _)| i as TempId)
        .collect();

    for (i, op) in block.ops.iter().enumerate() {
        if op.opcode == Opcode::SetLabel {
            let label = block.consts(op)[0];
            cur = match (cur.take(), pending.remove(&label)) {
                (Some(mut a), Some(b)) => {
                    a.join(&b);
                    Some(a)
                }
                (a, b) => a.or(b),
            };
            continue;
        }
        let Some(st) = cur.as_mut() else { continue };
        let out = block.outputs(op);
        let inp = block.inputs(op);
        let k = block.consts(op);
        let m = mask(op.ty);
        let get = |st: &State, t: TempId| st.temps[t as usize];

        match op.opcode {
            Opcode::Brcond => {
                merge(&mut pending, k[1], st);
            }
            Opcode::Br => {
                merge(&mut pending, k[0], st);
                cur = None;
            }
            Opcode::ExitTb | Opcode::GotoPtr => {
                exits.push(Exit {
                    op: i,
                    kind: exit_kind(st, regs, end),
                });
                left_in_globals(st, &globals, regs, end, &mut constants);
                cur = None;
            }
            Opcode::Call => {
                let h = block.helper(op);
                if spec.is_syscall(block, op) {
                    left_in_globals(st, &globals, regs, end, &mut constants);
                    let next = insn_end(block, i);
                    exits.push(Exit {
                        op: i,
                        kind: ExitKind::Syscall { next },
                    });
                    cur = None;
                    continue;
                }
                if h.no_return() {
                    cur = None;
                    continue;
                }
                if spec.is_pointer_auth(block, op) {
                    st.temps[out[0] as usize] = get(st, inp[1]);
                    continue;
                }
                for &o in out {
                    st.temps[o as usize] = Sym::Unknown;
                }
                // Helpers may rewrite guest state through env, unless their
                // flags say otherwise (NO_READ_GLOBALS implies no writes, as
                // in tcg_reg_alloc_call). The stack pointer and link register
                // are kept: no user-mode helper moves them, and losing them
                // would hide every return in a block that also divides.
                let flags = call_flags::NO_READ_GLOBALS | call_flags::NO_WRITE_GLOBALS;
                if h.flags & flags == 0 {
                    for &g in &globals {
                        if g != regs.sp && Some(g) != regs.lr {
                            st.temps[g as usize] = Sym::Unknown;
                        }
                    }
                }
            }
            Opcode::Mov => st.temps[out[0] as usize] = get(st, inp[0]),
            Opcode::Add | Opcode::Sub => {
                let (a, b) = (get(st, inp[0]), get(st, inp[1]));
                let add = op.opcode == Opcode::Add;
                st.temps[out[0] as usize] = match (a, b) {
                    (Sym::Const(x), Sym::Const(y)) => Sym::Const(
                        if add {
                            x.wrapping_add(y)
                        } else {
                            x.wrapping_sub(y)
                        } & m,
                    ),
                    (Sym::Entry(g, o), Sym::Const(y)) => {
                        let y = sext(y, op.ty);
                        Sym::Entry(
                            g,
                            if add {
                                o.wrapping_add(y)
                            } else {
                                o.wrapping_sub(y)
                            },
                        )
                    }
                    (Sym::Const(x), Sym::Entry(g, o)) if add => {
                        Sym::Entry(g, o.wrapping_add(sext(x, op.ty)))
                    }
                    _ => Sym::Unknown,
                };
            }
            Opcode::And | Opcode::Or | Opcode::Xor | Opcode::Shl | Opcode::Shr => {
                st.temps[out[0] as usize] = match (get(st, inp[0]), get(st, inp[1])) {
                    (Sym::Const(x), Sym::Const(y)) => Sym::Const(
                        match op.opcode {
                            Opcode::And => x & y,
                            Opcode::Or => x | y,
                            Opcode::Xor => x ^ y,
                            Opcode::Shl => x.wrapping_shl(y as u32),
                            _ => x.wrapping_shr(y as u32),
                        } & m,
                    ),
                    // Masking the top bits off a 64-bit address is a no-op here.
                    (s @ Sym::Entry(..), Sym::Const(u64::MAX)) if op.opcode == Opcode::And => s,
                    _ => Sym::Unknown,
                };
            }
            Opcode::Extract | Opcode::ExtuI32I64 | Opcode::ExtI32I64 | Opcode::ExtrlI64I32 => {
                let v = get(st, inp[0]);
                st.temps[out[0] as usize] = match (op.opcode, v) {
                    (Opcode::Extract, Sym::Const(x)) => Sym::Const((x >> k[0]) & low_bits(k[1])),
                    (Opcode::ExtuI32I64, Sym::Const(x)) => Sym::Const(x & 0xffff_ffff),
                    (Opcode::ExtI32I64, Sym::Const(x)) => Sym::Const(x as u32 as i32 as i64 as u64),
                    (Opcode::ExtrlI64I32, Sym::Const(x)) => Sym::Const(x & 0xffff_ffff),
                    _ => Sym::Unknown,
                };
            }
            Opcode::QemuLd => {
                let bytes = u64::from(MemOp(k[0]).bytes());
                st.temps[out[0] as usize] = match get(st, inp[0]) {
                    Sym::Entry(g, o) if bytes == regs.word => Sym::Load(g, o),
                    Sym::Const(a) if bytes == regs.word => Sym::Mem(a),
                    _ => Sym::Unknown,
                };
            }
            Opcode::QemuSt => match get(st, inp[0]) {
                Sym::Const(v) if v == end => {
                    let addr = get(st, inp[1]);
                    st.end_stored_at.push(addr);
                }
                Sym::Const(v) => constants.push(v),
                _ => {}
            },
            _ => {
                for &o in out {
                    st.temps[o as usize] = Sym::Unknown;
                }
            }
        }
    }
    constants.sort_unstable();
    constants.dedup();
    (exits, constants)
}

/// Constants in globals other than the pc, the link value excepted.
fn left_in_globals(st: &State, globals: &[TempId], regs: &Regs, end: u64, out: &mut Vec<u64>) {
    for &g in globals {
        if let Sym::Const(v) = st.temps[g as usize]
            && g != regs.pc
            && v != end
        {
            out.push(v);
        }
    }
}

fn merge(pending: &mut HashMap<u64, State>, label: u64, st: &State) {
    pending
        .entry(label)
        .and_modify(|p| p.join(st))
        .or_insert_with(|| st.clone());
}

fn sext(v: u64, ty: Type) -> i64 {
    match ty {
        Type::I32 => v as u32 as i32 as i64,
        _ => v as i64,
    }
}

fn low_bits(len: u64) -> u64 {
    if len >= 64 { u64::MAX } else { (1 << len) - 1 }
}

/// End address of the instruction containing op `i`.
fn insn_end(block: &Block, i: usize) -> u64 {
    block.ops[i..]
        .iter()
        .find(|op| op.opcode == Opcode::InsnStart)
        .map_or(block.end(), |op| block.consts(op)[0])
}

fn exit_kind(st: &State, regs: &Regs, end: u64) -> ExitKind {
    let pc = st.temps[regs.pc as usize];
    let sp = st.temps[regs.sp as usize];
    let linked = match regs.lr {
        None => st.end_stored_at.contains(&sp),
        Some(lr) => st.temps[lr as usize] == Sym::Const(end),
    };
    // Popped return address: pc loaded from just below the final stack
    // pointer, whatever register the stack pointer was rebuilt from
    // (`leave; ret` restores it from the frame pointer). With a link
    // register: pc taken from it (`ret`), whether it still holds the entry
    // value or was reloaded from the frame.
    let returns = match (regs.lr, pc, sp) {
        (Some(lr), Sym::Entry(g, 0), _) if g == lr => true,
        (Some(lr), Sym::Entry(..) | Sym::Load(..) | Sym::Mem(_), _) => pc == st.temps[lr as usize],
        (None, Sym::Load(g, o), Sym::Entry(s, so)) => g == s && so >= o + regs.word as i64,
        _ => false,
    };
    let slot = match pc {
        Sym::Mem(a) => Some(a),
        _ => None,
    };
    match pc {
        Sym::Const(t) if linked => ExitKind::Call {
            target: t,
            ret: end,
        },
        Sym::Const(t) => ExitKind::Jump(t),
        _ if linked => ExitKind::IndirectCall { ret: end, slot },
        _ if returns => ExitKind::Return,
        _ => ExitKind::IndirectJump { slot },
    }
}
