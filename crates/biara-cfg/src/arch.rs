//! The little ISA and platform knowledge recovery needs: which global is
//! the stack pointer, how return addresses travel, which helpers are
//! system calls, and what to assume where the code itself cannot tell
//! (unknown callees, system calls, helpers reading registers behind TCG's
//! back). Everything else is read from the TCG. Specs are per architecture
//! and operating system (`"linux"` for ELF, `"windows"` for PE, `"darwin"`
//! for Mach-O), which differ in calling and system-call conventions.

use biara_tcg::{Block, ContextInfo, Op, TempId, TempKind};

#[derive(Clone, Copy, Debug)]
pub enum ReturnConvention {
    /// `call` pushes the return address; `ret` pops it into pc.
    Stack { word: u64 },
    /// `call` writes the return address to this register; `ret` jumps to it.
    LinkRegister(&'static str),
}

/// A floating-point/vector state lane passed like an argument or result.
///
/// FP/vector state lives in env memory rather than in TCG globals, so these
/// name state lanes by their env byte range (`base`, `stride`, `count`),
/// the widths the convention passes there, and the argument slot each lane
/// fills. Lane `i` occupies `base + i * stride`: `lane_bytes` bytes for a
/// float/double argument or result, `vec_bytes` bytes where the convention
/// passes whole vectors in the same lanes (`0` where vectors never travel
/// in registers). `slot` is the argument position the lane fills (SysV and
/// AAPCS64 number FP/vector slots separately from integer slots; Win64
/// shares one position sequence across integer and FP arguments).
/// `regs` names the same lane for reports, where the architecture gives it
/// one (`xmm0`, `q0`); empty where lanes have no register name. Only lanes
/// the implementation passes in registers are listed; the rest travel in
/// memory or not at all.
#[derive(Clone, Copy, Debug)]
pub struct FpLane {
    /// Env offset of lane 0, in bytes.
    pub base: i64,
    /// Distance between lane starts, in bytes.
    pub stride: u64,
    /// Lanes the convention passes in registers, in order.
    pub count: u32,
    /// Argument position the first lane fills; lane `i` fills `slot + i`
    /// (SysV/AAPCS64: position among FP/vector slots; Win64: position in the
    /// shared integer/FP argument sequence).
    pub slot: u32,
    /// Scalar width in bytes (`4` or `8`): what a float/double argument or
    /// result occupies at the lane start. Bit-pattern traffic through the
    /// same state without float/vector evidence stays raw words, never this.
    pub lane_bytes: u32,
    /// Vector width in bytes where the convention passes whole vectors in
    /// the same lanes (`16` for 128-bit views, `0` where vectors never
    /// travel in registers). Observed lane traffic selects between the two.
    pub vec_bytes: u32,
    /// Register name per lane, for reports; empty when unnamed.
    pub regs: &'static [&'static str],
}

/// Native FP/vector state backing one [`FpLane`] table: the actual env
/// bytes a lane load/store transports. `lanes[i]` owns
/// `base + i * stride .. base + i * stride + width`, where `width` is the
/// observed access width (4 scalar32, 8 scalar64, 16 vector128). Partial
/// loads/stores transport exactly their bytes: a scalar64 load moves the
/// low 8 bytes of the 16-byte lane, a scalar32 the low 4, a vector128 the
/// whole lane. The rest of the lane is left alone, never fabricated.
#[derive(Clone, Copy, Debug)]
pub struct FpState {
    /// Env offset of lane 0, in bytes (matches the lane table).
    pub base: i64,
    /// Distance between lane starts, in bytes (matches the lane table).
    pub stride: u64,
}

/// How a return value travels back to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReturnClass {
    /// One scalar in the convention's first result register.
    Direct,
    /// A small aggregate in two result registers (`rax:rdx`, `x0:x1`).
    /// Establishing this needs evidence the two registers carry one value
    /// (one caller-observed 128-bit or paired value), never merely two
    /// live result registers at once; otherwise facts stay per-register.
    Pair,
    /// A larger aggregate through a caller-provided pointer (the hidden
    /// `sret` argument): a dedicated slot carrying an address the callee
    /// stores its result through, not a value it reads. Which slot is
    /// per-convention (SysV: first integer argument; AArch64: `x8`, never
    /// the first integer argument `x0`); see `CallConv::sret_slot`.
    Memory,
}

/// Register usage of code that cannot be analysed (by global name).
#[derive(Clone, Copy, Debug)]
pub struct CallConv {
    /// Argument registers, in order. For calls, only a prefix is taken to
    /// be read: up to the last one the caller wrote.
    pub args: &'static [&'static str],
    /// Registers results come back in; the first carries a scalar result.
    pub results: &'static [&'static str],
    /// Registers it may change; all others are left unchanged.
    pub clobbers: &'static [&'static str],
    /// Bytes of the caller's stack, from the stack pointer at the call
    /// (above the return address where one is pushed), the callee owns and
    /// may write: Win64's home space for the register arguments.
    pub home: u64,
    /// Floating-point/vector lanes passed in state, in order. Empty where
    /// the convention passes none in registers.
    pub fp_args: &'static [FpLane],
    /// Floating-point/vector lanes carrying a result, in order. Empty where
    /// results travel in integer registers or memory only.
    pub fp_results: &'static [FpLane],
    /// Native state backing `fp_args`/`fp_results`: the actual env bytes
    /// lane loads/stores transport. `None` where the convention passes no
    /// FP/vector state in registers.
    pub fp_state: Option<FpState>,
    /// How an aggregate result travels: [`ReturnClass::Direct`] for plain
    /// scalars, [`ReturnClass::Pair`] where two registers carry one value,
    /// [`ReturnClass::Memory`] where the caller passes a hidden pointer.
    /// Which slot carries that pointer is per-convention (SysV: the first
    /// integer argument; AArch64: `x8`, never `x0`); `None` where the
    /// convention has no hidden-pointer slot (system calls).
    pub ret_class: ReturnClass,
    /// Register carrying the hidden `sret` pointer when `ret_class` is
    /// [`ReturnClass::Memory`]; `None` where results never travel that way.
    /// This names the slot, not a claim about any function: per-function
    /// evidence lives in `biara_abi::FunctionAbi::ret_class`.
    pub sret_slot: Option<&'static str>,
}

/// A helper call that is a system call.
#[derive(Clone, Copy, Debug)]
pub struct SyscallHelper {
    pub name: &'static str,
    /// Required constant value of the first argument after `env` (the
    /// exception number for targets that enter the kernel by exception).
    pub excp: Option<u64>,
}

impl ArchSpec {
    /// Whether call op `op` of `block` performs a system call.
    pub fn is_syscall(&self, block: &Block, op: &Op) -> bool {
        let h = block.helper(op);
        self.syscall_helpers.iter().any(|s| {
            s.name == h.name
                && s.excp.is_none_or(|v| {
                    block.inputs(op).get(1).is_some_and(|&t| {
                        let t = block.temp(t);
                        t.kind == TempKind::Const && t.value as u64 == v
                    })
                })
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ArchSpec {
    pub arch: &'static str,
    pub os: &'static str,
    /// Name of the stack-pointer global.
    pub sp: &'static str,
    /// Alignment of instruction addresses.
    pub insn_align: u64,
    pub ret: ReturnConvention,
    /// The registers calling conventions talk about, for reports.
    pub registers: &'static [&'static str],
    /// Helpers that perform a system call and resume after the instruction.
    pub syscall_helpers: &'static [SyscallHelper],
    /// The system call convention.
    pub syscall: CallConv,
    /// Assumed for callees that are not lifted (imports, indirect calls).
    pub unknown_call: CallConv,
    /// Registers that helpers read and write through env rather than as
    /// arguments and results: (name, reads, writes). Unlisted helpers read
    /// none.
    pub helper_regs: &'static [HelperRegs],
    /// `helper_regs` lists every helper that writes registers (`registers`)
    /// through env; otherwise unlisted helpers may write any global unless
    /// their TCG flags say they do not.
    pub helper_regs_complete: bool,
    /// Helpers that sign, authenticate or strip a pointer: taken to return
    /// their first argument after `env` unchanged and to use nothing. A
    /// signature only fills address bits a valid pointer leaves clear, and
    /// authenticating a correctly signed pointer removes it again, so
    /// `paciasp ... autiasp; ret` still returns to the caller's lr.
    pub pointer_auth_helpers: &'static [&'static str],
}

impl ArchSpec {
    /// Whether call op `op` of `block` is a pointer-authentication helper.
    pub fn is_pointer_auth(&self, block: &Block, op: &Op) -> bool {
        self.pointer_auth_helpers
            .contains(&block.helper(op).name.as_str())
            && block.outputs(op).len() == 1
            && block.inputs(op).len() >= 2
    }
}

/// A helper's registers accessed through env: (name, reads, writes).
pub type HelperRegs = (&'static str, RegSet, RegSet);

/// Registers a helper reads or writes behind TCG's back.
#[derive(Clone, Copy, Debug)]
pub enum RegSet {
    Named(&'static [&'static str]),
    /// Registers numbered by the 5-bit fields at these bit offsets of the
    /// helper's first argument after `env` (a constant syndrome), indexing
    /// `names`; numbers past its end (the zero register) name nothing.
    /// Every one of `names` if the argument is not constant.
    Fields {
        offsets: &'static [u32],
        names: &'static [&'static str],
    },
}

impl RegSet {
    /// The register names `op` (a call of the helper) accesses.
    pub fn names(&self, block: &Block, op: &Op) -> Vec<&'static str> {
        match *self {
            RegSet::Named(names) => names.to_vec(),
            RegSet::Fields { offsets, names } => {
                let arg = block.inputs(op).get(1).map(|&t| block.temp(t));
                match arg {
                    Some(t) if t.kind == TempKind::Const => offsets
                        .iter()
                        .filter_map(|&o| names.get(((t.value as u64 >> o) & 31) as usize).copied())
                        .collect(),
                    _ => names.to_vec(),
                }
            }
        }
    }
}

const RAX: RegSet = RegSet::Named(&["rax"]);
const X86_64_DIV: RegSet = RegSet::Named(&["rax", "rdx"]);
/// FEAT_MOPS: destination, source and size registers (MOP_ISS in
/// target/arm/syndrome.h).
const MOPS: RegSet = RegSet::Fields {
    offsets: &[10, 5, 0],
    names: AARCH64_GPRS,
};

/// System V AMD64 SSE lanes: `xmm_regs[r]` at `960 + 64 * r` (a 512-bit
/// `ZMMReg` each). The convention passes eight FP/vector slots `xmm0-7` in
/// order, numbered separately from the integer slots: the low 8 bytes carry
/// a `double`, the low 4 a `float`, and the whole 16 bytes a vector.
/// SysV scalar results come back in `xmm0`; a `_Decimal`/complex-style SSE
/// aggregate result uses `xmm0`/`xmm1`.
/// DWARF `CPUX86State`: `xmm_regs` at 960, `xmm_t0` at 3008.
const X86_64_SSE_ARGS: &[FpLane] = &[FpLane {
    base: 960,
    stride: 64,
    count: 8,
    slot: 0,
    lane_bytes: 8,
    vec_bytes: 16,
    regs: &[],
}];
/// AAPCS64 SIMD lanes: `vfp.zregs[r]` at `3888 + 256 * r` (a 2048-bit
/// `ARMVectorReg` each). The convention passes eight FP/vector slots
/// `v0-7` in order, numbered separately from the integer slots; homogeneous
/// FP/vector aggregates take up to four lanes `v0-3`. Scalar results come
/// back in `v0`; homogeneous FP/vector aggregate results in `v0-3`.
const AARCH64_SIMD_ARGS: &[FpLane] = &[FpLane {
    base: 3888,
    stride: 256,
    count: 8,
    slot: 0,
    lane_bytes: 8,
    vec_bytes: 16,
    regs: &[],
}];
/// Microsoft x64 vector lanes share the same `xmm_regs` state, but Win64
/// numbers arguments in one shared position sequence: integer register,
/// then `xmm0-3` filling positions by argument order, not eight independent
/// FP slots. Only the first four lanes are modelled, starting at the
/// position the selection assigns per argument.
const X86_64_WIN_SSE_ARGS: &[FpLane] = &[FpLane {
    base: 960,
    stride: 64,
    count: 4,
    slot: 0,
    lane_bytes: 8,
    vec_bytes: 16,
    regs: &[],
}];

/// x86-64 with the System V conventions (Linux, macOS).
const X86_64_LINUX: ArchSpec = ArchSpec {
    arch: "x86_64",
    os: "linux",
    sp: "rsp",
    insn_align: 1,
    ret: ReturnConvention::Stack { word: 8 },
    registers: &[
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ],
    syscall_helpers: &[SyscallHelper {
        name: "syscall",
        excp: None,
    }],
    syscall: CallConv {
        args: &["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
        results: &["rax"],
        clobbers: &["rax", "rcx", "r11", "cc_op", "cc_dst", "cc_src", "cc_src2"],
        home: 0,
        fp_args: &[],
        fp_results: &[],
        fp_state: None,
        ret_class: ReturnClass::Direct,
        sret_slot: None,
    },
    // System V AMD64. Integer results in `rax`/`rdx`; FP scalar results in
    // `xmm0`, SSE aggregate results in `xmm0`/`xmm1`; larger aggregates
    // travel through the hidden pointer in the first integer slot (`rdi`).
    unknown_call: CallConv {
        args: &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        results: &["rax", "rdx"],
        clobbers: &[
            "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "cc_op", "cc_dst",
            "cc_src", "cc_src2",
        ],
        home: 0,
        fp_args: X86_64_SSE_ARGS,
        fp_results: X86_64_SSE_ARGS,
        fp_state: Some(FpState {
            base: 960,
            stride: 64,
        }),
        ret_class: ReturnClass::Direct,
        sret_slot: Some("rdi"),
    },
    // From env->regs[] uses in target/i386/tcg/{int,misc}_helper.c (QEMU
    // 11.1.2); the rest (seg_helper.c) is system-mode only.
    helper_regs: &[
        ("divb_AL", RAX, RAX),
        ("idivb_AL", RAX, RAX),
        ("divw_AX", X86_64_DIV, X86_64_DIV),
        ("idivw_AX", X86_64_DIV, X86_64_DIV),
        ("divl_EAX", X86_64_DIV, X86_64_DIV),
        ("idivl_EAX", X86_64_DIV, X86_64_DIV),
        ("divq_EAX", X86_64_DIV, X86_64_DIV),
        ("idivq_EAX", X86_64_DIV, X86_64_DIV),
        ("aaa", RAX, RAX),
        ("aas", RAX, RAX),
        ("daa", RAX, RAX),
        ("das", RAX, RAX),
        (
            "cpuid",
            RegSet::Named(&["rax", "rcx"]),
            RegSet::Named(&["rax", "rbx", "rcx", "rdx"]),
        ),
        ("rdtsc", RegSet::Named(&[]), X86_64_DIV),
    ],
    helper_regs_complete: true,
    pointer_auth_helpers: &[],
};

const AARCH64_LINUX: ArchSpec = ArchSpec {
    arch: "aarch64",
    os: "linux",
    sp: "sp",
    insn_align: 4,
    ret: ReturnConvention::LinkRegister("lr"),
    registers: AARCH64_REGS,
    // `svc` raises EXCP_SWI (target/arm/cpu.h); linux-user performs the call
    // and resumes at the pc the translator stored.
    syscall_helpers: &[SyscallHelper {
        name: "exception_with_syndrome",
        excp: Some(2),
    }],
    syscall: CallConv {
        args: &["x8", "x0", "x1", "x2", "x3", "x4", "x5"],
        results: &["x0"],
        clobbers: &["x0"],
        home: 0,
        fp_args: &[],
        fp_results: &[],
        fp_state: None,
        ret_class: ReturnClass::Direct,
        sret_slot: None,
    },
    // AAPCS64: x0-x7 arguments, x0-x1 integer results, v0-v7 FP/vector
    // slots; scalar FP results in `v0`, homogeneous FP/vector aggregates in
    // `v0-3`; larger aggregates travel through the hidden pointer in `x8`
    // (never `x0`). x9-x18 and lr are caller-saved, as are the NZCV flags.
    unknown_call: CallConv {
        args: AARCH64_ARGS,
        results: &["x0", "x1"],
        clobbers: &[
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x18", "lr", "NF", "ZF", "CF", "VF",
        ],
        home: 0,
        fp_args: AARCH64_SIMD_ARGS,
        fp_results: AARCH64_SIMD_ARGS,
        fp_state: Some(FpState {
            base: 3888,
            stride: 256,
        }),
        ret_class: ReturnClass::Direct,
        sret_slot: Some("x8"),
    },
    // From env->xregs[] uses in target/arm/tcg/*.c (QEMU 11.1.2): only the
    // FEAT_MOPS helpers, on registers named by their syndrome argument.
    helper_regs: &[
        ("setp", MOPS, MOPS),
        ("setm", MOPS, MOPS),
        ("sete", MOPS, MOPS),
        ("setgp", MOPS, MOPS),
        ("setgm", MOPS, MOPS),
        ("setge", MOPS, MOPS),
        ("cpyp", MOPS, MOPS),
        ("cpym", MOPS, MOPS),
        ("cpye", MOPS, MOPS),
        ("cpyfp", MOPS, MOPS),
        ("cpyfm", MOPS, MOPS),
        ("cpyfe", MOPS, MOPS),
    ],
    helper_regs_complete: true,
    // FEAT_PAuth (target/arm/tcg/helper-a64-defs.h); pacga computes a
    // signature rather than signing its operand, so it is not listed.
    pointer_auth_helpers: &[
        "pacia",
        "pacib",
        "pacda",
        "pacdb",
        "autia",
        "autib",
        "autda",
        "autdb",
        "autia_combined",
        "autib_combined",
        "autda_combined",
        "autdb_combined",
        "xpaci",
        "xpacd",
    ],
};

const AARCH64_ARGS: &[&str] = &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];

/// AAPCS64 with x18 reserved to the platform (Apple's and Microsoft's ABIs).
const AARCH64_X18_RESERVED: CallConv = CallConv {
    args: AARCH64_ARGS,
    results: &["x0", "x1"],
    clobbers: &[
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "lr", "NF", "ZF", "CF", "VF",
    ],
    home: 0,
    fp_args: AARCH64_SIMD_ARGS,
    fp_results: AARCH64_SIMD_ARGS,
    fp_state: Some(FpState {
        base: 3888,
        stride: 256,
    }),
    ret_class: ReturnClass::Direct,
    sret_slot: Some("x8"),
};

const SPECS: &[ArchSpec] = &[
    X86_64_LINUX,
    // macOS: System V, and the same system-call registers (the call number
    // carries a class in its high bits).
    ArchSpec {
        os: "darwin",
        ..X86_64_LINUX
    },
    ArchSpec {
        os: "windows",
        // Microsoft x64: rcx, rdx, r8, r9; rdi and rsi are callee-saved; the
        // caller leaves 32 bytes of home space above the return address.
        unknown_call: CallConv {
            args: &["rcx", "rdx", "r8", "r9"],
            results: &["rax"],
            clobbers: &[
                "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc_op", "cc_dst", "cc_src",
                "cc_src2",
            ],
            home: 32,
            fp_args: X86_64_WIN_SSE_ARGS,
            fp_results: X86_64_WIN_SSE_ARGS,
            fp_state: Some(FpState {
                base: 960,
                stride: 64,
            }),
            ret_class: ReturnClass::Direct,
            sret_slot: Some("rcx"),
        },
        ..X86_64_LINUX
    },
    AARCH64_LINUX,
    ArchSpec {
        os: "darwin",
        // `svc #0x80` with the call number in x16; x0 and x1 return, the
        // carry flag tells an error.
        syscall: CallConv {
            args: &["x16", "x0", "x1", "x2", "x3", "x4", "x5"],
            results: &["x0", "x1"],
            clobbers: &["x0", "x1", "CF"],
            home: 0,
            fp_args: &[],
            fp_results: &[],
            fp_state: None,
            ret_class: ReturnClass::Direct,
            sret_slot: None,
        },
        unknown_call: AARCH64_X18_RESERVED,
        ..AARCH64_LINUX
    },
    ArchSpec {
        os: "windows",
        unknown_call: AARCH64_X18_RESERVED,
        ..AARCH64_LINUX
    },
];

const AARCH64_GPRS: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "lr",
];

const AARCH64_REGS: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "lr", "sp",
];

/// The spec for QEMU target `arch` running on `os` (`"linux"`, `"windows"`
/// or `"darwin"`).
pub fn spec(arch: &str, os: &str) -> Option<&'static ArchSpec> {
    SPECS.iter().find(|s| s.arch == arch && s.os == os)
}

/// `ArchSpec` with global names resolved against a context.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Regs {
    pub pc: TempId,
    pub sp: TempId,
    pub lr: Option<TempId>,
    pub word: u64,
}

impl Regs {
    pub fn resolve(spec: &ArchSpec, info: &ContextInfo) -> Option<Self> {
        let find = |name: &str| {
            info.globals
                .iter()
                .position(|g| g.name.as_deref() == Some(name))
                .map(|i| i as TempId)
        };
        let (lr, word) = match spec.ret {
            ReturnConvention::Stack { word } => (None, word),
            ReturnConvention::LinkRegister(lr) => (Some(find(lr)?), u64::from(info.guest_bits / 8)),
        };
        Some(Self {
            pc: info.pc_global,
            sp: find(spec.sp)?,
            lr,
            word,
        })
    }
}
