//! TCG IR as produced by one call to `libtcg_translate`.
//!
//! Encodings (conditions, MemOp, call flags, helper type masks) mirror
//! QEMU 11.1.2: include/tcg/tcg-cond.h, include/exec/memop.h,
//! include/tcg/tcg.h and include/exec/helper-head.h.inc.

use std::{fmt, sync::Arc};

use crate::Error;
pub type TempId = u32;
pub type LabelId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Type {
    I32,
    I64,
    I128,
    V64,
    V128,
    V256,
}

impl Type {
    pub(crate) fn from_raw(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::I32),
            1 => Ok(Self::I64),
            2 => Ok(Self::I128),
            3 => Ok(Self::V64),
            4 => Ok(Self::V128),
            5 => Ok(Self::V256),
            _ => Err(Error::UnknownType(v)),
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Self::I32 => 32,
            Self::I64 | Self::V64 => 64,
            Self::I128 | Self::V128 => 128,
            Self::V256 => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TempKind {
    /// Live within one extended basic block.
    Ebb,
    /// Live across the whole translation block.
    Tb,
    /// Guest state backed by memory at `mem_base + mem_offset`.
    Global,
    /// Fixed host register; on every target this is `env`.
    Fixed,
    /// Constant; value in `Temp::value`.
    Const,
}

impl TempKind {
    pub(crate) fn from_raw(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Ebb),
            1 => Ok(Self::Tb),
            2 => Ok(Self::Global),
            3 => Ok(Self::Fixed),
            4 => Ok(Self::Const),
            _ => Err(Error::UnknownTempKind(v)),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Temp {
    pub kind: TempKind,
    pub ty: Type,
    /// Type of the whole value when this temp is half of an I128.
    pub base_type: Type,
    pub subindex: u8,
    pub mem_base: Option<TempId>,
    pub mem_offset: i64,
    pub value: i64,
    pub name: Option<Arc<str>>,
}

macro_rules! opcodes {
    ($($name:literal => $variant:ident,)*) => {
        /// Target-independent scalar TCG opcodes. Vector and backend-private
        /// opcodes map to `Other`; `Block::op_name` still names them.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        pub enum Opcode {
            $($variant,)*
            Other,
        }

        impl Opcode {
            pub(crate) fn from_name(name: &str) -> Self {
                match name {
                    $($name => Self::$variant,)*
                    _ => Self::Other,
                }
            }
        }
    };
}

opcodes! {
    "discard" => Discard,
    "set_label" => SetLabel,
    "call" => Call,
    "br" => Br,
    "brcond" => Brcond,
    "mb" => Mb,
    "mov" => Mov,
    "add" => Add,
    "and" => And,
    "andc" => Andc,
    "bswap16" => Bswap16,
    "bswap32" => Bswap32,
    "bswap64" => Bswap64,
    "clz" => Clz,
    "ctpop" => Ctpop,
    "ctz" => Ctz,
    "deposit" => Deposit,
    "divs" => Divs,
    "divs2" => Divs2,
    "divu" => Divu,
    "divu2" => Divu2,
    "eqv" => Eqv,
    "extract" => Extract,
    "extract2" => Extract2,
    "ld8u" => Ld8u,
    "ld8s" => Ld8s,
    "ld16u" => Ld16u,
    "ld16s" => Ld16s,
    "ld32u" => Ld32u,
    "ld32s" => Ld32s,
    "ld" => Ld,
    "movcond" => Movcond,
    "mul" => Mul,
    "muls2" => Muls2,
    "mulsh" => Mulsh,
    "mulu2" => Mulu2,
    "muluh" => Muluh,
    "nand" => Nand,
    "neg" => Neg,
    "negsetcond" => Negsetcond,
    "nor" => Nor,
    "not" => Not,
    "or" => Or,
    "orc" => Orc,
    "rems" => Rems,
    "remu" => Remu,
    "rotl" => Rotl,
    "rotr" => Rotr,
    "sar" => Sar,
    "setcond" => Setcond,
    "sextract" => Sextract,
    "shl" => Shl,
    "shr" => Shr,
    "st8" => St8,
    "st16" => St16,
    "st32" => St32,
    "st" => St,
    "sub" => Sub,
    "xor" => Xor,
    "addco" => Addco,
    "addc1o" => Addc1o,
    "addci" => Addci,
    "addcio" => Addcio,
    "subbo" => Subbo,
    "subb1o" => Subb1o,
    "subbi" => Subbi,
    "subbio" => Subbio,
    "ext_i32_i64" => ExtI32I64,
    "extu_i32_i64" => ExtuI32I64,
    "extrl_i64_i32" => ExtrlI64I32,
    "extrh_i64_i32" => ExtrhI64I32,
    "insn_start" => InsnStart,
    "exit_tb" => ExitTb,
    "goto_tb" => GotoTb,
    "goto_ptr" => GotoPtr,
    "plugin_cb" => PluginCb,
    "plugin_mem_cb" => PluginMemCb,
    "qemu_ld" => QemuLd,
    "qemu_st" => QemuSt,
    "qemu_ld2" => QemuLd2,
    "qemu_st2" => QemuSt2,
}

/// `libtcg_op_defs()`, shared by every block from one library.
#[derive(Debug)]
pub(crate) struct OpDefs {
    pub names: Vec<Box<str>>,
    pub opcodes: Vec<Opcode>,
    /// TCG_OPF_* per opcode.
    pub flags: Vec<u16>,
    /// Declared `(nb_oargs, nb_iargs, nb_cargs)` per opcode, from
    /// `libtcg_op_defs()`. `Call` is dynamic (per-op counts always apply);
    /// every other opcode must carry exactly its declared arity.
    pub arities: Vec<(u8, u8, u8)>,
}
/// TCG_OPF_INT: integer op, `Op::ty` is the operand type.
const OPF_INT: u16 = 0x10;
/// TCG_OPF_VECTOR: vector op, `Op::ty` and `Op::vece` are set.
const OPF_VECTOR: u16 = 0x40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cond {
    Never,
    Always,
    Eq,
    Ne,
    /// `(a & b) == 0`
    TstEq,
    /// `(a & b) != 0`
    TstNe,
    Lt,
    Ge,
    Gt,
    Le,
    Ltu,
    Geu,
    Gtu,
    Leu,
}

impl Cond {
    pub fn from_raw(v: u64) -> Option<Self> {
        Some(match v {
            0 => Self::Never,
            1 => Self::Always,
            8 => Self::Eq,
            9 => Self::Ne,
            12 => Self::TstEq,
            13 => Self::TstNe,
            2 => Self::Lt,
            3 => Self::Ge,
            6 => Self::Gt,
            7 => Self::Le,
            10 => Self::Ltu,
            11 => Self::Geu,
            14 => Self::Gtu,
            15 => Self::Leu,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Always => "always",
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::TstEq => "tsteq",
            Self::TstNe => "tstne",
            Self::Lt => "lt",
            Self::Ge => "ge",
            Self::Gt => "gt",
            Self::Le => "le",
            Self::Ltu => "ltu",
            Self::Geu => "geu",
            Self::Gtu => "gtu",
            Self::Leu => "leu",
        }
    }
}

/// Guest memory access descriptor (QEMU `MemOp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemOp(pub u64);

impl MemOp {
    /// log2 of the access size in bytes.
    pub fn size_log2(self) -> u32 {
        (self.0 & 0x7) as u32
    }

    pub fn bytes(self) -> u32 {
        1 << self.size_log2()
    }

    pub fn signed(self) -> bool {
        self.0 & 0x8 != 0
    }

    /// Byte-swapped relative to the host (little-endian here): big-endian.
    pub fn bswap(self) -> bool {
        self.0 & 0x10 != 0
    }
}

/// bswap16/bswap32 flag bits.
pub mod bswap {
    /// Input is known zero-extended from the swapped width.
    pub const IZ: u64 = 1;
    /// Output must be zero-extended.
    pub const OZ: u64 = 2;
    /// Output must be sign-extended.
    pub const OS: u64 = 4;
}

/// Helper call flags (TCG_CALL_*).
pub mod call_flags {
    pub const NO_READ_GLOBALS: u32 = 0x1;
    pub const NO_WRITE_GLOBALS: u32 = 0x2;
    pub const NO_SIDE_EFFECTS: u32 = 0x4;
    pub const NO_RETURN: u32 = 0x8;
}

/// An x87 helper's memory footprint, replacing its TCG flags (which claim
/// every helper below may write all globals) with what its bitcode body
/// actually does. `biara-lift/tests/helpers.rs` re-derives this from the
/// helper bitcode and fails if any body changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperFootprint {
    /// Writes only x87 FPU stack state, never a register global and never
    /// guest memory: looking back may continue past its calls, and lowering
    /// emits no reload after them.
    FpStack,
    /// Reads guest memory at its address operand and writes only FPU state:
    /// transparent like `FpStack` (reads kill nothing).
    FpLoad,
    /// Writes guest memory at its address operand (operand index, width in
    /// bytes) and no register global: a guest store there for slot queries,
    /// transparent for env homes.
    FpStore { addr: usize, width: i64 },
}

/// Whether the helper called `helper_{name}` writes no register
/// global: a `FpStack`/`FpLoad` footprint, or a `FpStore` (which writes
/// only its guest operand). See `Helper::preserves_globals`.
pub fn preserves_globals(name: &str) -> bool {
    helper_footprint(name).is_some()
}

/// The footprint of the helper called `helper_{name}`, or `None` if it is
/// opaque (any other helper: assume it reads and writes everything).
pub fn helper_footprint(name: &str) -> Option<HelperFootprint> {
    Some(match name {
        "fpush" | "fpop" | "fincstp" | "fdecstp" | "fmov_ST0_STN" | "fmov_STN_ST0" => {
            HelperFootprint::FpStack
        }
        "fldt_ST0" | "flds_ST0" => HelperFootprint::FpLoad,
        "fstt_ST0" => HelperFootprint::FpStore { addr: 1, width: 10 },
        _ => return None,
    })
}

/// Value type of one helper signature slot (dh_typecode_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperType {
    Void,
    I32,
    S32,
    I64,
    S64,
    Ptr,
    I128,
}

impl HelperType {
    fn from_code(c: u32) -> Result<Self, Error> {
        match c {
            0 => Ok(Self::Void),
            2 => Ok(Self::I32),
            3 => Ok(Self::S32),
            4 => Ok(Self::I64),
            5 => Ok(Self::S64),
            6 => Ok(Self::Ptr),
            7 => Ok(Self::I128),
            _ => Err(Error::UnknownHelperType(c)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Helper {
    pub name: String,
    /// Host address of the helper inside the loaded libtcg.
    pub addr: usize,
    pub flags: u32,
    pub typemask: u32,
}

impl Helper {
    /// C symbol of the helper (QEMU's DEF_HELPER naming).
    pub fn symbol(&self) -> String {
        format!("helper_{}", self.name)
    }

    pub fn ret(&self) -> Result<HelperType, Error> {
        HelperType::from_code(self.typemask & 7)
    }

    /// Signature slots after the return slot (up to 10). Each item is
    /// validated: unknown typecodes surface as `Err`, never truncation.
    /// Note `take_while` stops at the first zero slot, so a zero return
    /// slot with nonzero param slots still yields those params.
    pub fn params(&self) -> impl Iterator<Item = Result<HelperType, Error>> + '_ {
        (1..=10)
            .map(|slot| (self.typemask >> (slot * 3)) & 7)
            .take_while(|&c| c != 0)
            .map(HelperType::from_code)
    }

    /// Eager validated parameter list (convenience over `params`).
    /// Also validates the return slot: unknown codes are `Err` even when
    /// no parameter slots are present.
    pub fn params_vec(&self) -> Result<Vec<HelperType>, Error> {
        let _ = self.ret()?;
        self.params().collect()
    }

    pub fn no_return(&self) -> bool {
        self.flags & call_flags::NO_RETURN != 0
    }

    /// Whether the helper writes no register global: a `FpStack`/`FpLoad`
    /// footprint, or a `FpStore` (see `helper_footprint`; verified by
    /// `biara-lift/tests/helpers.rs`). Every other helper is opaque (flags
    /// alone do not show this: these carry no `NO_WRITE_GLOBALS`).
    pub fn preserves_globals(&self) -> bool {
        preserves_globals(&self.name)
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct Op {
    pub opcode: Opcode,
    /// Index into the library's op table (stable only per build).
    pub opc: u32,
    /// Operand type of integer and vector ops; I32 otherwise.
    pub ty: Type,
    pub vece: u8,
    pub(crate) nb_out: u8,
    pub(crate) nb_in: u8,
    pub(crate) nb_const: u8,
    pub(crate) temps: u32,
    pub(crate) consts: u32,
}

/// Exit value of an `exit_tb` naming a goto_tb slot.
pub const EXIT_TB_LINKED: u64 = libtcg_sys::LIBTCG_EXIT_TB_LINKED as u64;

#[derive(Clone, Debug)]
pub struct Temps {
    /// Shared context descriptors when identical, otherwise this TB's exact
    /// global prefix. Every block keeps an Arc, not repeated Temp records.
    /// TempIds below `globals.len()` index this prefix.
    pub(crate) globals: Arc<[Temp]>,
    /// Per-block temps: every `TempId` at or above `globals.len()`.
    pub(crate) local: Vec<Temp>,
}

impl Temps {
    /// Look up a temp in the shared prefix or local tail.
    pub fn get(&self, index: usize) -> Option<&Temp> {
        if index < self.globals.len() {
            self.globals.get(index)
        } else {
            self.local.get(index - self.globals.len())
        }
    }

    /// Number of shared globals (the local temps start at this `TempId`).
    pub fn nb_globals(&self) -> usize {
        self.globals.len()
    }

    /// Global prefix; block-owned only when its descriptors differ.
    pub fn shared(&self) -> &Arc<[Temp]> {
        &self.globals
    }

    /// The block's own temps (past the shared prefix).
    pub fn locals(&self) -> &[Temp] {
        &self.local
    }

    /// All temps: globals first, then locals.
    pub fn iter(&self) -> impl Iterator<Item = &Temp> + '_ {
        self.globals.iter().chain(self.local.iter())
    }

    /// All temps: globals first, then locals.
    pub fn len(&self) -> usize {
        self.globals.len() + self.local.len()
    }

    /// Whether the collection contains no temporaries.
    pub fn is_empty(&self) -> bool {
        self.globals.is_empty() && self.local.is_empty()
    }
}

impl std::ops::Index<usize> for Temps {
    type Output = Temp;
    fn index(&self, id: usize) -> &Temp {
        self.get(id).expect("TCG temp index out of bounds")
    }
}

impl<'a> IntoIterator for &'a Temps {
    type Item = &'a Temp;
    type IntoIter = std::iter::Chain<std::slice::Iter<'a, Temp>, std::slice::Iter<'a, Temp>>;
    fn into_iter(self) -> Self::IntoIter {
        self.globals.iter().chain(self.local.iter())
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub pc: u64,
    /// Bytes of guest code covered.
    pub size: u32,
    pub icount: u32,
    pub ops: Vec<Op>,
    /// All temps: the context's shared globals `[0, nb_globals)` then the
    /// block's own temps. `len`/`iter`/`Index`/`Block::temp` cover both, so
    /// `TempId` values and lookups are unchanged.
    pub temps: Temps,
    pub helpers: Vec<Helper>,
    pub nb_labels: u32,
    pub(crate) temp_args: Vec<TempId>,
    pub(crate) const_args: Vec<u64>,
    pub(crate) defs: Arc<OpDefs>,
}

impl Block {
    pub fn outputs(&self, op: &Op) -> &[TempId] {
        let s = op.temps as usize;
        &self.temp_args[s..s + op.nb_out as usize]
    }

    pub fn inputs(&self, op: &Op) -> &[TempId] {
        let s = op.temps as usize + op.nb_out as usize;
        &self.temp_args[s..s + op.nb_in as usize]
    }

    pub fn consts(&self, op: &Op) -> &[u64] {
        let s = op.consts as usize;
        &self.const_args[s..s + op.nb_const as usize]
    }

    pub fn op_name(&self, op: &Op) -> &str {
        &self.defs.names[op.opc as usize]
    }

    pub fn temp(&self, id: TempId) -> &Temp {
        &self.temps[id as usize]
    }

    /// Helper called by a `call` op.
    pub fn helper(&self, op: &Op) -> &Helper {
        debug_assert_eq!(op.opcode, Opcode::Call);
        &self.helpers[self.consts(op)[0] as usize]
    }

    /// Guest address one past the last translated instruction.
    pub fn end(&self) -> u64 {
        self.pc + u64::from(self.size)
    }
}

/// Incremental construction from the C arrays; see `Libtcg::translate`.
pub(crate) struct BlockBuilder {
    block: Block,
}

impl BlockBuilder {
    pub fn new(
        pc: u64,
        size: u32,
        icount: u32,
        nb_labels: u32,
        defs: Arc<OpDefs>,
        globals: Arc<[Temp]>,
    ) -> Self {
        Self {
            block: Block {
                pc,
                size,
                icount,
                ops: Vec::new(),
                temps: Temps {
                    globals,
                    local: Vec::new(),
                },
                helpers: Vec::new(),
                nb_labels,
                temp_args: Vec::new(),
                const_args: Vec::new(),
                defs,
            },
        }
    }

    pub fn reserve(
        &mut self,
        ops: usize,
        temp_args: usize,
        const_args: usize,
        temps: usize,
        helpers: usize,
    ) {
        self.block.ops.reserve_exact(ops);
        self.block.temp_args.reserve_exact(temp_args);
        self.block.const_args.reserve_exact(const_args);
        // `temps` counts every temp including the shared global prefix;
        // only the block-local tail needs storage.
        self.block
            .temps
            .local
            .reserve_exact(temps.saturating_sub(self.block.temps.nb_globals()));
        self.block.helpers.reserve_exact(helpers);
    }

    pub fn temp(&mut self, t: Temp) {
        self.block.temps.local.push(t);
    }

    /// Shared-prefix length: `TempId`s below this index the globals.
    pub fn nb_globals(&self) -> usize {
        self.block.temps.nb_globals()
    }

    pub fn helper(&mut self, h: Helper) {
        self.block.helpers.push(h);
    }

    pub fn op(
        &mut self,
        opc: u32,
        ty: Type,
        vece: u8,
        outputs: &[u64],
        inputs: &[u64],
        consts: &[u64],
    ) {
        let b = &mut self.block;
        let op = Op {
            opcode: b.defs.opcodes[opc as usize],
            opc,
            ty,
            vece,
            nb_out: outputs.len() as u8,
            nb_in: inputs.len() as u8,
            nb_const: consts.len() as u8,
            temps: b.temp_args.len() as u32,
            consts: b.const_args.len() as u32,
        };
        b.temp_args
            .extend(outputs.iter().chain(inputs).map(|&t| t as TempId));
        b.const_args.extend_from_slice(consts);
        b.ops.push(op);
    }

    pub fn finish(self) -> Block {
        self.block
    }
}

impl fmt::Display for Block {
    /// Close to QEMU's `-d op` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let temp = |id: TempId| -> String {
            let t = self.temp(id);
            match (&t.name, t.kind) {
                (Some(n), _) => n.to_string(),
                (None, TempKind::Const) => format!("${:#x}", t.value),
                (None, TempKind::Ebb) => format!("tmp{id}"),
                (None, _) => format!("loc{id}"),
            }
        };
        for op in &self.ops {
            let consts = self.consts(op);
            match op.opcode {
                Opcode::InsnStart => {
                    write!(f, "\n ----")?;
                    for c in consts {
                        write!(f, " {c:016x}")?;
                    }
                    writeln!(f)?;
                    continue;
                }
                Opcode::Call => {
                    let h = self.helper(op);
                    write!(f, " call {},$0x{:x},${}", h.name, h.flags, op.nb_out)?;
                    for &t in self.outputs(op).iter().chain(self.inputs(op)) {
                        write!(f, ",{}", temp(t))?;
                    }
                    writeln!(f)?;
                    continue;
                }
                _ => {}
            }
            let name = self.op_name(op);
            let flags = self.defs.flags[op.opc as usize];
            if flags & OPF_INT != 0 {
                write!(f, " {name}_i{} ", op.ty.bits())?;
            } else if flags & OPF_VECTOR != 0 {
                write!(f, " {name} v{},e{},", op.ty.bits(), 8 << op.vece)?;
            } else {
                write!(f, " {name} ")?;
            }
            let mut sep = "";
            for &t in self.outputs(op).iter().chain(self.inputs(op)) {
                write!(f, "{sep}{}", temp(t))?;
                sep = ",";
            }
            match op.opcode {
                Opcode::Brcond => write!(
                    f,
                    "{sep}{},$L{}",
                    Cond::from_raw(consts[0]).map_or("?", Cond::name),
                    consts[1]
                )?,
                Opcode::Setcond | Opcode::Negsetcond | Opcode::Movcond => write!(
                    f,
                    "{sep}{}",
                    Cond::from_raw(consts[0]).map_or("?", Cond::name)
                )?,
                Opcode::SetLabel | Opcode::Br => write!(f, "$L{}", consts[0])?,
                Opcode::QemuLd | Opcode::QemuSt | Opcode::QemuLd2 | Opcode::QemuSt2 => {
                    let m = MemOp(consts[0]);
                    write!(
                        f,
                        "{sep}{}{}{}",
                        if m.bswap() { "be" } else { "le" },
                        if m.signed() { "s" } else { "u" },
                        8 << m.size_log2()
                    )?
                }
                _ => {
                    for c in consts {
                        write!(f, "{sep}${c:#x}")?;
                        sep = ",";
                    }
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
