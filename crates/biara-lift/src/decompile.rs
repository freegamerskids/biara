//! C output: the lifted program with the recovered calling conventions
//! enforced, simplified by LLVM, and printed as C with recovered types.
//!
//! 1. `lift` with the ABI analysis (`biara_abi::analyze`).
//! 2. ABI form (cpp/abi_form.cpp): every function `void f(ptr %env)`
//!    becomes `ret f(args...)` over its argument registers and stack
//!    arguments, returning its return registers. Registers are locals, the
//!    stack frame is a local array; direct calls pass arguments, imports and
//!    pointers are called with the convention's argument registers, system
//!    calls go to `biara_syscall`. Established floating-point/vector lanes
//!    become typed ABI parameters/results; untyped or conflicting bit traffic
//!    retains raw words. Helper-visible state remains in `biara_cpu`, with
//!    bit-preserving transfers between that state and typed ABI slots.
//!    `prepare_c` stops here, keeping only the module and compact
//!    summaries (owned strings/scalars); the caller can then drop the
//!    recovery CFG, ABI tables, and libtcg guard.
//! 3. Function-local optimisation (no inlining): registers and frame slots
//!    that never escape become SSA values; flag computations no caller
//!    reads disappear.
//!    Jump tables become switches on their index (cpp/index_switches.cpp).
//!    Guest strings and import shapes are recovered from constant guest
//!    memory. `PreparedC::transform` does this; the image may go away
//!    once it returns.
//!    `DecompileOptions` bounds function-pass workers to
//!    `max(1, available_parallelism - 1)`; an explicit request can only lower
//!    that limit. Each worker owns its LLVM context and target machine and
//!    optimizes at most 32 function bodies plus referenced declarations/data.
//!    Inputs and results are exchanged as bitcode; merges follow module order.
//!    The caller computes one job, so it is included in the worker count.
//!    Recovery, ABI conversion, cross-function analyses and output stay serial.
//!    Small functions can be slower in parallel because isolation and merging
//!    add overhead; one worker runs the original pipeline without round trips.
//! 4. C (cpp/cgen.cpp): pointer variables typed by reusable, offset-aware
//!    access layouts shared with `TransformedC::layout_facts`/`type_facts`.
//!    Accessed extents never become declared object bounds; generic callees
//!    do not merge unrelated objects, and incompatible widths remain conflicts.
//!    Frames that escape become structs; loops/branches are conservatively
//!    structured with gotos retained where needed. Scalar/vector bitcasts use
//!    representation-preserving C unions, not numeric casts. Integer-vector
//!    views and lane extraction retain the optimized IR's bit representation.
//!    Layout-derived integer addresses and callback expressions convert to
//!    their inferred pointer types before dereference or invocation.
//!    Integer widths, wraps, effects and unresolved calls remain those of the
//!    recovered program.
//!    Recovered strings with one module reference inline at known text-consuming
//!    imports. Shared strings retain named storage; raw-address uses and imports
//!    that may expose pointer identity are not inlined.
//!    `TransformedC::render` streams to a sink in bounded chunks, retaining
//!    one function body, not the whole source. Dependencies are emitted
//!    before their first function use; section order can differ.
//!    `TransformedC::visit_functions` instead streams one `FunctionPackage`
//!    at a time: body first, referenced support, names, source contributors
//!    and readability metrics. `select_functions` bounds presentation without
//!    deleting executable code. Consumer errors stop delivery; panics never
//!    unwind across the native renderer boundary.
//!    `apply_debug_names` and `apply_debug_objects` accept proven entry-register
//!    bindings and range-valid whole stack objects. Ambiguous bindings and
//!    unsupported locations keep neutral names; source type spellings remain
//!    evidence rather than permission to narrow arithmetic or memory access.
//!
//! The result is plain C (GNU extensions: `__int128`, packed structs,
//! `__builtin_*`) for the host; it is as right as the ABI analysis, and
//! guest memory is host memory at the guest address, as in the lifted IR.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString, c_char, c_void},
};

use biara_abi::FunctionAbi;
use biara_cfg::{Cfg, ExitKind, ReturnConvention};
use biara_tcg::{ContextInfo, TempId, TempKind, Type, call_flags};
use inkwell::{
    context::Context,
    module::Module,
    passes::PassBuilderOptions,
    targets::TargetMachine,
    values::{AsValueRef, CallSiteValue, InstructionOpcode},
};

use crate::{
    DISPATCH, DebugName, DebugObject, DecompileOptions, Error, FunctionPackage, RUN, SYSCALL,
    lower::PC_MD, memory,
};

#[repr(C)]
struct Reg {
    home: i64,
    bits: u32,
    name: *const c_char,
    thread: u32,
}

#[repr(C)]
struct Sig {
    func: *mut c_void,
    args: *const u32,
    nargs: u32,
    stack_args: *const i64,
    nstack: u32,
    rets: *const u32,
    nrets: u32,
    below: u64,
    above: u64,
    entry: u64,
    balanced: u32,
    preserved: *const u32,
    npreserved: u32,
    // Per-parameter ABI kinds (`KIND_*` below, length `nargs + nstack`;
    // stack slots always `KIND_I64`). Null would mean all-integer, but Rust
    // always passes the array.
    arg_kinds: *const u32,
    // Per-result ABI kinds (`KIND_*`, length `nrets`); always passed.
    ret_kinds: *const u32,
    // Return shape (`RET_*` below).
    ret_class: u32,
    // Hidden-`sret` parameter position (`u32::MAX` unless `RET_MEMORY`).
    sret_param: u32,
}

// ABI value kinds: the native LLVM type a slot lowers to. Must match
// `BIARA_KIND_*` in cpp/abi_form.cpp.
const KIND_I64: u32 = 1;
const KIND_F32: u32 = 2;
const KIND_F64: u32 = 3;
const KIND_VEC128: u32 = 4;
const KIND_SRET: u32 = 6;
const KIND_RAW: u32 = 7;
const KIND_CONFLICT: u32 = 8;
// Return shapes; must match `BIARA_RET_*` in cpp/abi_form.cpp.
const RET_DIRECT: u32 = 0;
const RET_PAIR: u32 = 1;
const RET_MEMORY: u32 = 2;
const CALL_DIRECT: u32 = 0;
const CALL_IMPORT: u32 = 1;
const CALL_INDIRECT: u32 = 2;
const CALL_SYSCALL: u32 = 3;

#[repr(C)]
struct Call {
    inst: *mut c_void,
    kind: u32,
    import: *const c_char,
    arity: u32,
    ret: u64,
}

const HELPER_READS: u32 = 1;
const HELPER_WRITES: u32 = 2;
const HELPER_PURE: u32 = 4;

#[repr(C)]
struct HelperRole {
    symbol: *const c_char,
    mode: u32,
    listed: u32,
    reads: *const u32,
    nreads: u32,
    writes: *const u32,
    nwrites: u32,
}

#[repr(C)]
struct Conv {
    sp: u32,
    pc: u32,
    pop: i64,
    args: *const u32,
    nargs: u32,
    ret: u32,
    sys_args: *const u32,
    nsys: u32,
    sys_ret: u32,
    env_size: u64,
    margin: u64,
}

#[repr(C)]
pub(crate) struct CField {
    pub(crate) off: i64,
    pub(crate) bytes: u32,
    pub(crate) name: *const c_char,
}

/// Copied data (`R_*_COPY`): address and size in the image, host-linked name.
#[repr(C)]
struct DataSymbol {
    addr: u64,
    size: u64,
    name: *const c_char,
}

/// A guest string literal at a call argument: its address and C-escaped text.
#[repr(C)]
struct GuestStr {
    addr: u64,
    text: *const c_char,
}

/// A called import's declaration: parameter count, which take strings,
/// and whether calls vary in count (then `, ...`).
#[repr(C)]
struct Proto {
    name: *const c_char,
    nargs: u32,
    strmask: u64,
    ellipsis: u32,
}

unsafe extern "C" {
    #[allow(clippy::too_many_arguments)]
    fn biara_abi_form(
        module: *mut c_void,
        conv: *const Conv,
        regs: *const Reg,
        nregs: usize,
        sigs: *const Sig,
        nsigs: usize,
        calls: *const Call,
        ncalls: usize,
        helpers: *const HelperRole,
        nhelpers: usize,
        drop: *const *mut c_void,
        ndrop: usize,
        err: *mut *mut c_char,
    ) -> i32;
    fn biara_fold_frames(module: *mut c_void) -> usize;
    fn biara_div_sugar(module: *mut c_void) -> usize;
    fn biara_dup_returns(module: *mut c_void) -> usize;
    fn biara_index_switches(module: *mut c_void, read: ReadFn, ctx: *mut c_void) -> usize;
    fn biara_parallel_function_passes(
        module: *mut c_void,
        machine: *mut c_void,
        pipeline: *const c_char,
        workers: usize,
        error: *mut *mut c_char,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn biara_emit_c_cached(
        layouts: *mut c_void,
        module: *mut c_void,
        cpu: *const CField,
        ncpu: usize,
        conv_args: *const *const c_char,
        nconv: usize,
        margin: u64,
        banner: *const c_char,
        unsupported: *mut usize,
        data: *const DataSymbol,
        ndata: usize,
        strings: *const GuestStr,
        nstrings: usize,
        protos: *const Proto,
        nprotos: usize,
        syms: *const GuestStr,
        nsyms: usize,
        mode: u32,
        write: WriteFn,
        ctx: *mut c_void,
    ) -> i32;
}

/// Rendered C statistics: how many constructs printed as placeholders
/// (`/* unsupported ... */`).
pub struct CStats {
    pub unsupported: usize,
}

/// Sink for C output chunks; `render` writes every chunk in order.
type WriteFn = unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> i32;

/// Bytes of CPU state before env (`CPUArchState` sits inside `ArchCPU`;
/// lifted code touches the icount and I/O flags just before it).
const MARGIN: u64 = 256;

/// Arguments a fixed-arity import takes; `None` for variadic or unknown
/// imports (whose arity is inferred from the registers set at the call).
fn fixed_arity(import: &str) -> Option<u32> {
    Some(match import.split('@').next().unwrap_or(import) {
        "abort" | "exit" | "_exit" | "_Exit" | "quick_exit" | "getchar" | "clock" | "rand"
        | "__stack_chk_fail" | "__fortify_fail" => 0,
        "strlen" | "strdup" | "strndup" | "atoi" | "atol" | "atoll" | "abs" | "labs" | "llabs"
        | "malloc" | "free" | "fclose" | "ftell" | "perror" | "puts" | "putchar" | "getenv"
        | "system" | "unlink" | "close" | "getpid" | "getuid" | "puts_unlocked"
        | "strlen_ifunc" => 1,
        "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp" | "strchr" | "strrchr" | "strstr"
        | "memcmp" | "calloc" | "realloc" | "fopen" | "rename" | "strcmp_ifunc" => 2,
        "memcpy" | "memmove" | "memset" | "memcmp_ifunc" | "fread" | "fwrite" | "fseek"
        | "fseek_ifunc" | "qsort" | "raise" | "kill" | "link" | "mkdir" | "rmdir" | "chdir"
        | "chmod" | "strncpy" | "strncat" | "strcat" | "strcpy" | "strtol" | "strtoul"
        | "strtoll" | "strtoull" | "calloc_ifunc" | "fread_unlocked" | "fwrite_unlocked" => 3,
        "bsearch" | "pread" | "pwrite" | "lseek" => 4,
        _ => return None,
    })
}

/// A called import's shape: most and fewest arguments any call passes.
struct ProtoShape {
    min_args: u32,
    max_args: u32,
}

/// String literals passed to imports: `(address, C-escaped text)` for
/// every constant argument at a string position (`audit::string_args`)
/// that reads as a NUL-terminated printable string, plus every called
/// import's argument shape (for typed declarations). `read` is the same
/// guest-memory reader used for jump tables.
fn guest_strings(
    module: &Module<'_>,
    read: Reader,
    max_len: usize,
    ptr_bits: u32,
) -> (Vec<(u64, CString)>, BTreeMap<String, ProtoShape>) {
    use inkwell::values::BasicValueEnum;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut protos: BTreeMap<String, ProtoShape> = BTreeMap::new();
    // A constant address holding a NUL-terminated printable string.
    let mut try_addr = |addr: u64| {
        if addr == 0 || !seen.insert(addr) {
            return;
        }
        let mut buf = vec![0u8; max_len + 1];
        if !read(addr, &mut buf) {
            return;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(max_len + 1);
        if len > max_len {
            return;
        }
        let bytes = &buf[..len];
        if bytes.is_empty()
            || !bytes
                .iter()
                .all(|&b| b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b))
        {
            return;
        }
        let mut text = String::with_capacity(len);
        for &b in bytes {
            match b {
                b'"' => text.push_str("\\\""),
                b'\\' => text.push_str("\\\\"),
                b'\n' => text.push_str("\\n"),
                b'\t' => text.push_str("\\t"),
                _ => text.push(b as char),
            }
        }
        if text.contains("*/") {
            text = text.replace("*/", "* /");
        }
        if let Ok(c) = CString::new(text) {
            out.push((addr, c));
        }
    };
    for f in module.get_functions() {
        for bb in f.get_basic_blocks() {
            for inst in bb.get_instructions() {
                if inst.get_opcode() != InstructionOpcode::Call {
                    continue;
                }
                let Ok(call) = CallSiteValue::try_from(inst) else {
                    continue;
                };
                let Some(callee) = call.get_called_fn_value() else {
                    continue;
                };
                // Lifted callees have bodies; only imports take guest strings.
                // Helpers take the CPU state through env, not C values.
                if callee.count_basic_blocks() != 0 {
                    continue;
                }
                let raw_name = callee.get_name();
                let raw_name = raw_name.to_str().unwrap_or_default();
                if raw_name.starts_with("helper_") {
                    continue;
                }
                let name = match callee.get_name().to_str() {
                    Ok(n) => n.split('@').next().unwrap_or(n).to_owned(),
                    Err(_) => continue,
                };
                let nargs = call.count_arguments();
                protos
                    .entry(name.clone())
                    .and_modify(|p| {
                        p.min_args = p.min_args.min(nargs);
                        p.max_args = p.max_args.max(nargs);
                    })
                    .or_insert(ProtoShape {
                        min_args: nargs,
                        max_args: nargs,
                    });
                let positions = crate::audit::string_args(&name);
                if positions.is_empty() {
                    continue;
                }
                for &idx in positions {
                    // Call operands are the arguments, then the callee.
                    match inst.get_operand(idx as u32) {
                        Some(inkwell::values::Operand::Value(BasicValueEnum::IntValue(v))) => {
                            match v.get_zero_extended_constant() {
                                Some(a) => try_addr(a),
                                None => continue,
                            }
                        }
                        _ => continue,
                    };
                }
            }
        }
    }
    // Constants that never reach a call as constants (a default string
    // chosen by a branch, a table of messages): any pointer-width constant
    // operand that reads as a string. Only used strings are emitted, so
    // extras only cost reads.
    for f in module.get_functions() {
        for bb in f.get_basic_blocks() {
            for inst in bb.get_instructions() {
                for op in inst.get_operands() {
                    if let Some(inkwell::values::Operand::Value(BasicValueEnum::IntValue(v))) = op {
                        if v.get_type().get_bit_width() != ptr_bits {
                            continue;
                        }
                        if let Some(a) = v.get_zero_extended_constant() {
                            try_addr(a);
                        }
                    }
                }
            }
        }
    }
    (out, protos)
}

type ReadFn = unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> i32;
type Reader<'r> = &'r dyn Fn(u64, &mut [u8]) -> bool;

unsafe extern "C" fn read_cb(ctx: *mut c_void, addr: u64, buf: *mut u8, len: usize) -> i32 {
    let read = unsafe { &*(ctx as *const Reader) };
    read(addr, unsafe { std::slice::from_raw_parts_mut(buf, len) }) as i32
}

/// Compact summaries kept after the recovery CFG/ABI data go away: only
/// owned strings and scalars (`name_of` results, global layouts, banner,
/// data symbols, guest address width). Never a copy of the CFG/TCG.
struct Summaries {
    cpu: Vec<(i64, u32, String)>,
    conv_args: Vec<String>,
    banner: String,
    data: Vec<(u64, u64, String)>,
    fns: Vec<(u64, String)>,
    entries: BTreeMap<u64, String>,
    guest_bits: u32,
}

/// C decompilation after lifting and the ABI form, but before the
/// reader-dependent simplification/rendering. Holds the lifted module
/// plus compact summaries; the caller can drop the recovery CFG, ABI
/// tables, and libtcg guard once this is built.
pub struct PreparedC<'ctx> {
    module: Module<'ctx>,
    summaries: Summaries,
}

/// Owned, reusable analysis evidence shared with C rendering.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TypeFacts {
    pub layouts: crate::layouts::LayoutFacts,
    pub signatures: Vec<crate::signatures::FuncSig>,
}

/// Simplified ABI-form module plus the string/import tables `render`
/// needs; the guest-memory reader is no longer required.
pub struct TransformedC<'ctx> {
    // Native analysis holds LLVM references; drop it before the module.
    layouts: Option<crate::layouts::Handle>,
    layout_debug_dirty: bool,
    module: Module<'ctx>,
    cpu: Vec<(i64, u32, String)>,
    conv_args: Vec<String>,
    banner: String,
    data: Vec<(u64, u64, String)>,
    fns: Vec<(u64, String)>,
    entries: BTreeMap<u64, String>,
    strings: Vec<(u64, String)>,
    protos: Vec<(String, u32, u64, bool)>,
}

/// Lift every function of `cfg` and put it in ABI form. The returned
/// stage owns its module and compact summaries only; drop `cfg`, `abis`,
/// and the libtcg guard before the expensive `transform`/`render`.
#[allow(clippy::too_many_arguments)]
pub fn prepare_c<'ctx>(
    cx: &'ctx Context,
    machine: &TargetMachine,
    info: &ContextInfo,
    cfg: &Cfg,
    abis: &BTreeMap<u64, FunctionAbi>,
    name_of: &dyn Fn(u64) -> Option<String>,
    banner: &str,
    data: &BTreeMap<u64, (String, u64)>,
) -> Result<PreparedC<'ctx>, Error> {
    let spec = cfg.spec(&info.arch)?;
    // Unique names (symbols repeat across static functions): C needs them,
    // and calls are matched to functions by name.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for &e in cfg.functions.keys() {
        *seen
            .entry(name_of(e).unwrap_or_else(|| format!("sub_{e:x}")))
            .or_default() += 1;
    }
    let names: BTreeMap<u64, String> = cfg
        .functions
        .keys()
        .map(|&e| {
            let n = name_of(e).unwrap_or_else(|| format!("sub_{e:x}"));
            let n = if seen[&n] > 1 {
                format!("{n}_{e:x}")
            } else {
                n
            };
            (e, n)
        })
        .collect();
    let name = |e: u64| names[&e].clone();
    let module = crate::lift_with(
        cx,
        machine,
        info,
        cfg,
        Some(abis),
        &|e| names.get(&e).cloned(),
        "c",
        None,
    )?;

    // Registers: every integer global in env, plus one synthetic lane
    // register per convention FP/vector lane with a real env home (base +
    // index * stride). Lane homes are actual FP state, never placeholder
    // GPRs: `Sig.args` entries for FP lanes name these homes, so entry,
    // call, and return transport reads/writes real lane bytes.
    let env_global = info.env_global;
    let mut reg_ids: Vec<TempId> = Vec::new();
    let mut reg_names: Vec<CString> = Vec::new();
    for (i, g) in info.globals.iter().enumerate() {
        if g.kind == TempKind::Global
            && g.mem_base == Some(env_global)
            && matches!(g.ty, Type::I32 | Type::I64)
        {
            reg_ids.push(i as TempId);
            reg_names.push(CString::new(g.name.as_deref().unwrap_or("reg")).unwrap());
        }
    }
    // Synthetic FP lane homes, appended after the GPRs in lane-table
    // order (args then results, deduplicated by home). Each lane home is
    // `home = base + index * stride` with a 128-bit slot width; kinds
    // select scalar32/64 vs vector128 transport widths in C++. Homes also
    // record the lane's physical argument position (`slot + index`):
    // SysV/AAPCS64 number FP slots from 0 in their own sequence, Win64
    // from its shared integer/FP position, so mixed GPR/FP order stays
    // keyed by physical slot instead of two appended banks.
    let mut fp_names: Vec<CString> = Vec::new();
    let mut fp_homes: Vec<(i64, u32, u32)> = Vec::new();
    {
        let mut push_lane = |base: i64, stride: u64, count: u32, slot: u32, tag: &str| {
            for i in 0..count {
                let home = base + i as i64 * stride as i64;
                if !fp_homes.iter().any(|(h, _, _)| *h == home) {
                    fp_names.push(CString::new(format!("{tag}{i}")).unwrap());
                    // 128-bit home width; scalar transport moves the low
                    // 4/8 bytes of it (see laneAt/C++ partial stores).
                    fp_homes.push((home, 128, slot + i));
                }
            }
        };
        for lane in spec.unknown_call.fp_args {
            push_lane(lane.base, lane.stride, lane.count, lane.slot, "fp");
        }
        for lane in spec.unknown_call.fp_results {
            push_lane(lane.base, lane.stride, lane.count, lane.slot, "fpr");
        }
    }
    let mut regs: Vec<Reg> = reg_ids
        .iter()
        .zip(&reg_names)
        .map(|(&g, n)| Reg {
            home: info.globals[g as usize].mem_offset,
            bits: info.globals[g as usize].ty.bits(),
            name: n.as_ptr(),
            // x86 segment bases: thread state, not arguments.
            thread: u32::from(n.to_bytes().ends_with(b"_base")),
        })
        .collect();
    // FP lane homes join the register table after the GPRs; their indices
    // are `reg_ids.len() + position`. `by_name`/`index` only cover GPRs;
    // lane indices below resolve positionally into `regs`.
    let fp_base = regs.len() as u32;
    regs.extend(
        fp_homes
            .iter()
            .zip(&fp_names)
            .map(|(&(home, bits, _), n)| Reg {
                home,
                bits,
                name: n.as_ptr(),
                thread: 0,
            }),
    );
    // Lane index to register-table position: `fp_homes` holds lanes in
    // lane-table order (args then results, deduplicated by home), so the
    // position of lane `l` is its index in that order. Lanes are keyed by
    // physical slot (`FpLane::slot` + lane), which is what makes Win64's
    // shared integer/FP sequence physical rather than an appended bank:
    // SysV/AAPCS64 lanes start at slot 0 of their own sequence, Win64
    // lanes at their shared-sequence position.
    let fp_index = |lane: u32| -> Result<u32, Error> {
        fp_homes
            .iter()
            .position(|&(_, _, slot)| slot == lane)
            .map(|position| fp_base + position as u32)
            .ok_or_else(|| Error::Llvm(format!("no FP lane {lane}")))
    };
    let index = |g: TempId| reg_ids.iter().position(|&r| r == g).map(|i| i as u32);
    let by_name = |n: &str| -> Result<u32, Error> {
        info.globals
            .iter()
            .position(|g| g.name.as_deref() == Some(n))
            .and_then(|g| index(g as TempId))
            .ok_or_else(|| Error::Llvm(format!("no register {n}")))
    };
    let all = |ns: &[&str]| ns.iter().map(|n| by_name(n)).collect::<Result<Vec<_>, _>>();
    let sp = by_name(spec.sp)?;
    let pc = index(info.pc_global).ok_or_else(|| Error::Llvm("pc is not a register".into()))?;
    let conv_args = all(spec.unknown_call.args)?;
    let sys_args = all(spec.syscall.args)?;
    let (pop, bias, word) = match spec.ret {
        ReturnConvention::Stack { word } => (word as i64, word, word),
        ReturnConvention::LinkRegister(_) => (0, 0, u64::from(info.guest_bits / 8)),
    };

    // Signatures: the convention's registers, up to the last one used, as in
    // the original calling convention (other registers a function reads are
    // taken to be incidental: merged into, or used by IPA register
    // allocation).
    let prefix = |set: &BTreeSet<TempId>, regs: &[u32]| -> Vec<u32> {
        let n = regs
            .iter()
            .rposition(|&r| set.contains(&reg_ids[r as usize]))
            .map_or(0, |i| i + 1);
        regs[..n].to_vec()
    };
    let results = all(spec.unknown_call.results)?;
    let convention_clobbers = all(spec.unknown_call.clobbers)?;
    struct Owned {
        args: Vec<u32>,
        stack: Vec<i64>,
        rets: Vec<u32>,
        balanced: bool,
        preserved: Vec<u32>,
        arg_kinds: Vec<u32>,
        ret_kinds: Vec<u32>,
        ret_class: u32,
        sret_param: u32,
    }
    let stubs: BTreeSet<u64> = cfg
        .functions
        .keys()
        .copied()
        .filter(|&e| cfg.stub_import(e).is_some())
        .collect();
    let mut owned = Vec::new();
    let mut entries = Vec::new();
    for (&e, abi) in abis {
        if stubs.contains(&e) || !cfg.functions.contains_key(&e) {
            continue;
        }
        let kept: Vec<u32> = if abi.analysis.converged {
            abi.preserved.iter().filter_map(|&g| index(g)).collect()
        } else {
            (0..reg_ids.len() as u32)
                .filter(|r| *r != sp && *r != pc && !convention_clobbers.contains(r))
                .collect()
        };
        // Slots always name their physical homes. SysV/AAPCS64 have
        // independent integer/FP sequences; Win64 shares one sequence.
        let mut argsel = if abi.analysis.converged {
            prefix(&abi.args, &conv_args)
        } else {
            conv_args.clone()
        };
        let kind = |lane: u32, types: &BTreeMap<u32, biara_abi::LaneType>| {
            if abi.fp_conflicts.contains(&lane) {
                KIND_CONFLICT
            } else {
                match types.get(&lane) {
                    Some(biara_abi::LaneType::Float32) => KIND_F32,
                    Some(biara_abi::LaneType::Float64) => KIND_F64,
                    Some(biara_abi::LaneType::Vector128) => KIND_VEC128,
                    None => KIND_RAW,
                }
            }
        };
        let fp_count = abi.fp_args.last().map_or(0, |lane| lane + 1);
        let mut arg_kinds = vec![KIND_I64; argsel.len()];
        if spec.unknown_call.home != 0 {
            let count = argsel.len().max(fp_count as usize);
            argsel.clear();
            arg_kinds.clear();
            for (position, &reg) in conv_args.iter().enumerate().take(count) {
                let lane = position as u32;
                if abi.fp_args.contains(&lane) {
                    argsel.push(fp_index(lane)?);
                    arg_kinds.push(kind(lane, &abi.fp_arg_types));
                } else {
                    argsel.push(reg);
                    arg_kinds.push(KIND_I64);
                }
            }
        } else {
            for lane in 0..fp_count {
                argsel.push(fp_index(lane)?);
                arg_kinds.push(kind(lane, &abi.fp_arg_types));
            }
        }
        let mut retsel = if cfg.functions[&e].returns {
            if abi.analysis.converged {
                prefix(&abi.returns, &results)
            } else {
                results.clone()
            }
        } else {
            Vec::new()
        };
        let mut ret_kinds = vec![KIND_I64; retsel.len()];
        if cfg.functions[&e].returns {
            for &lane in &abi.fp_returns {
                retsel.push(fp_index(lane)?);
                ret_kinds.push(kind(lane, &abi.fp_ret_types));
            }
        }
        let sret_reg = spec
            .unknown_call
            .sret_slot
            .and_then(|n| {
                info.globals
                    .iter()
                    .position(|g| g.name.as_deref() == Some(n))
            })
            .and_then(|g| index(g as TempId))
            .unwrap_or(sp);
        let mut ret_class = RET_DIRECT;
        let mut sret_param = u32::MAX;
        match abi.ret_class {
            Some(biara_cfg::ReturnClass::Pair) if retsel.len() == 2 => {
                ret_class = RET_PAIR;
            }
            Some(biara_cfg::ReturnClass::Memory) => {
                if let Some(position) = argsel.iter().position(|&r| r == sret_reg) {
                    arg_kinds[position] = KIND_SRET;
                    sret_param = position as u32;
                } else {
                    sret_param = argsel.len() as u32;
                    argsel.push(sret_reg);
                    arg_kinds.push(KIND_SRET);
                }
                retsel.clear();
                ret_kinds.clear();
                ret_class = RET_MEMORY;
            }
            _ => {}
        }
        owned.push(Owned {
            args: argsel,
            stack: abi.stack_args.iter().copied().collect(),
            rets: retsel,
            balanced: abi.analysis.converged && abi.frame.balanced,
            preserved: kept,
            arg_kinds,
            ret_kinds,
            ret_class,
            sret_param,
        });
        entries.push((e, abi.frame.size));
    }
    let mut sigs = Vec::new();
    for ((e, size), o) in entries.iter().zip(&owned) {
        let f = module
            .get_function(&name(*e))
            .ok_or_else(|| Error::Llvm(format!("{} not lifted", name(*e))))?;
        // Room for pushes the analysis does not count (return addresses),
        // and the entry stack pointer aligned as a call leaves it.
        let below = (size + 32).next_multiple_of(16) + bias;
        let top = o.stack.iter().copied().max().map_or(0, |m| m + 8);
        let above = (top.max(word as i64) as u64 + 16).next_multiple_of(16);
        sigs.push(Sig {
            func: f.as_value_ref().cast(),
            args: o.args.as_ptr(),
            nargs: o.args.len() as u32,
            stack_args: o.stack.as_ptr(),
            nstack: o.stack.len() as u32,
            rets: o.rets.as_ptr(),
            nrets: o.rets.len() as u32,
            balanced: u32::from(o.balanced),
            preserved: o.preserved.as_ptr(),
            npreserved: o.preserved.len() as u32,
            arg_kinds: o.arg_kinds.as_ptr(),
            ret_kinds: o.ret_kinds.as_ptr(),
            ret_class: o.ret_class,
            sret_param: o.sret_param,
            below,
            above,
            entry: *e,
        });
    }

    // What every call of the lifted code stands for.
    let pc_kind = cx.get_kind_id(PC_MD);
    let mut import_names: Vec<CString> = Vec::new();
    let stub_names: BTreeMap<String, u64> = stubs.iter().map(|&e| (name(e), e)).collect();
    let mut raw_calls = Vec::new();
    let lifted_names: BTreeSet<String> = cfg
        .functions
        .keys()
        .filter(|e| !stubs.contains(e))
        .map(|&e| name(e))
        .collect();
    let import_id = |n: &str, names: &mut Vec<CString>| {
        let n = n.split('@').next().unwrap_or(n);
        let c = CString::new(n).unwrap();
        match names.iter().position(|x| *x == c) {
            Some(i) => i,
            None => {
                names.push(c);
                names.len() - 1
            }
        }
    };
    for f in module.get_functions() {
        if f.count_basic_blocks() == 0 {
            continue;
        }
        for bb in f.get_basic_blocks() {
            for inst in bb.get_instructions() {
                if inst.get_opcode() != InstructionOpcode::Call {
                    continue;
                }
                let Some(callee) = CallSiteValue::try_from(inst)
                    .ok()
                    .and_then(|c| c.get_called_fn_value())
                else {
                    continue;
                };
                let callee = callee.get_name().to_str().unwrap_or_default().to_owned();
                let raw = inst.as_value_ref().cast();
                if callee == SYSCALL {
                    raw_calls.push((raw, CALL_SYSCALL, None, 0, u32::MAX));
                    continue;
                }
                let stub = stub_names.get(&callee).copied();
                let lifted = lifted_names.contains(&callee);
                if callee != DISPATCH && stub.is_none() && !lifted {
                    continue;
                }
                let pc = inst
                    .get_metadata(pc_kind)
                    .and_then(|m| m.get_node_values()?.first().copied())
                    .and_then(|v| v.into_int_value().get_zero_extended_constant());
                let exit = pc.and_then(|pc| {
                    let (_, b) = cfg.blocks.range(..=pc).next_back()?;
                    b.exits.iter().map(|x| x.kind).find(|k| {
                        matches!(
                            k,
                            ExitKind::Call { .. }
                                | ExitKind::IndirectCall { .. }
                                | ExitKind::Jump(_)
                                | ExitKind::IndirectJump { .. }
                        )
                    })
                });
                let (target, slot, ret) = match exit {
                    Some(ExitKind::Call { target, ret }) => (Some(target), None, ret),
                    Some(ExitKind::IndirectCall { ret, slot }) => (None, slot, ret),
                    Some(ExitKind::Jump(t)) => (Some(t), None, 0),
                    Some(ExitKind::IndirectJump { slot }) => (None, slot, 0),
                    _ => (None, None, 0),
                };
                let import = stub
                    .and_then(|s| cfg.stub_import(s))
                    .or_else(|| target.and_then(|t| cfg.stub_import(t)))
                    .or_else(|| slot.and_then(|s| cfg.imports.get(&s).map(String::as_str)));
                let (kind, import) = match (lifted, import) {
                    (true, _) => (CALL_DIRECT, None),
                    (false, Some(i)) => (CALL_IMPORT, Some(import_id(i, &mut import_names))),
                    (false, None) => (CALL_INDIRECT, None),
                };
                // Imports of known fixed arity use exactly that many
                // arguments (extra live registers are not arguments).
                // Variadic imports (printf, open, ...) keep inference.
                let arity = match (kind, import) {
                    (CALL_IMPORT, Some(i)) => {
                        fixed_arity(&import_names[i].to_string_lossy()).map_or(u32::MAX, |n| n)
                    }
                    _ => u32::MAX,
                };
                raw_calls.push((raw, kind, import, ret, arity));
            }
        }
    }
    let calls: Vec<Call> = raw_calls
        .iter()
        .map(|&(inst, kind, import, ret, arity)| Call {
            inst,
            kind,
            import: import.map_or(std::ptr::null(), |i| import_names[i].as_ptr()),
            arity,
            ret,
        })
        .collect();

    // Helpers, as the lowering treats them. Where the spec lists every
    // helper that accesses the convention's registers through env, only
    // those registers (and the other globals: flags, pc, segment bases)
    // travel through it.
    let others: Vec<u32> = (0..reg_ids.len() as u32)
        .filter(|&r| {
            let n = info.globals[reg_ids[r as usize] as usize].name.as_deref();
            !n.is_some_and(|n| spec.registers.contains(&n))
        })
        .collect();
    let listed: BTreeMap<&str, (Vec<u32>, Vec<u32>)> = spec
        .helper_regs
        .iter()
        .map(|&(name, reads, writes)| {
            let ids = |set: biara_cfg::RegSet| -> Result<Vec<u32>, Error> {
                let (biara_cfg::RegSet::Named(ns) | biara_cfg::RegSet::Fields { names: ns, .. }) =
                    set;
                let mut v = all(ns)?;
                v.extend(&others);
                Ok(v)
            };
            Ok((name, (ids(reads)?, ids(writes)?)))
        })
        .collect::<Result<_, Error>>()?;
    let none = (others.clone(), others.clone());
    let mut helper_syms: Vec<CString> = Vec::new();
    let mut roles = Vec::new();
    for h in cfg.helpers() {
        let reads = h.flags & call_flags::NO_READ_GLOBALS == 0;
        let writes = reads
            && h.flags & call_flags::NO_WRITE_GLOBALS == 0
            && !h.no_return()
            && !h.preserves_globals();
        let regs = listed
            .get(h.name.as_str())
            .or(spec.helper_regs_complete.then_some(&none));
        helper_syms.push(CString::new(h.symbol()).unwrap());
        let pure = h.flags & call_flags::NO_SIDE_EFFECTS != 0;
        roles.push((
            if reads { HELPER_READS } else { 0 }
                | if writes { HELPER_WRITES } else { 0 }
                | if pure { HELPER_PURE } else { 0 },
            regs,
        ));
    }
    let helpers: Vec<HelperRole> = helper_syms
        .iter()
        .zip(&roles)
        .map(|(s, &(mode, regs))| HelperRole {
            symbol: s.as_ptr(),
            mode,
            listed: u32::from(regs.is_some()),
            reads: regs.map_or(std::ptr::null(), |r| r.0.as_ptr()),
            nreads: regs.map_or(0, |r| r.0.len() as u32),
            writes: regs.map_or(std::ptr::null(), |r| r.1.as_ptr()),
            nwrites: regs.map_or(0, |r| r.1.len() as u32),
        })
        .collect();

    let mut drop: Vec<*mut c_void> = stubs
        .iter()
        .filter_map(|&e| module.get_function(&name(e)))
        .map(|f| f.as_value_ref().cast())
        .collect();
    for d in [RUN, DISPATCH, SYSCALL] {
        if let Some(f) = module.get_function(d) {
            drop.push(f.as_value_ref().cast());
        }
    }
    let conv = Conv {
        sp,
        pc,
        pop,
        args: conv_args.as_ptr(),
        nargs: conv_args.len() as u32,
        ret: results[0],
        sys_args: sys_args.as_ptr(),
        nsys: sys_args.len() as u32,
        sys_ret: by_name(spec.syscall.results[0])?,
        env_size: info.env_size as u64,
        margin: MARGIN,
    };
    let mut err = std::ptr::null_mut();
    let failed = unsafe {
        biara_abi_form(
            module.as_mut_ptr().cast(),
            &conv,
            regs.as_ptr(),
            regs.len(),
            sigs.as_ptr(),
            sigs.len(),
            calls.as_ptr(),
            calls.len(),
            helpers.as_ptr(),
            helpers.len(),
            drop.as_ptr(),
            drop.len(),
            &mut err,
        )
    };
    if failed != 0 {
        let msg = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        unsafe { libc_free(err.cast()) };
        return Err(Error::Llvm(format!("ABI form: {msg}")));
    }
    module
        .verify()
        .map_err(|e| Error::Llvm(format!("ABI form: {e}")))?;
    // Tag actual ABI-form guest identities, before display sanitization and
    // scalar passes. Generated dispatchers and import declarations stay untagged.
    let entries: BTreeMap<_, _> = names
        .into_iter()
        .filter(|(_, name)| {
            module
                .get_function(name)
                .is_some_and(|f| f.count_basic_blocks() != 0)
        })
        .collect();
    // MetadataAsValue unwraps single-scalar tuples. A version operand keeps
    // these global attachments as MDNodes, as LLVMGlobalSetMetadata requires.
    for (&entry, name) in &entries {
        module
            .get_function(name)
            .unwrap()
            .as_global_value()
            .set_metadata(
                cx.metadata_node(&[
                    cx.i64_type().const_int(entry, false).into(),
                    cx.i32_type().const_int(1, false).into(),
                ]),
                cx.get_kind_id("biara.entry"),
            );
        module
            .get_function(name)
            .unwrap()
            .as_global_value()
            .set_metadata(
                cx.metadata_node(&[
                    cx.i32_type()
                        .const_int(
                            match cfg.os {
                                "linux" => 1,
                                "darwin" => 2,
                                "windows" => 3,
                                _ => 0,
                            },
                            false,
                        )
                        .into(),
                    cx.i32_type().const_int(1, false).into(),
                ]),
                cx.get_kind_id("biara.os"),
            );
    }

    // Names in the CPU state: every global in env.
    let cpu: Vec<(i64, u32, String)> = info
        .globals
        .iter()
        .filter(|g| g.kind == TempKind::Global && g.mem_base == Some(env_global))
        .filter_map(|g| Some((g.mem_offset, g.ty.bits() / 8, g.name.clone()?.to_string())))
        .collect();
    let conv_names: Vec<String> = conv_args
        .iter()
        .map(|&r| reg_names[r as usize].to_string_lossy().into_owned())
        .collect();
    let data_syms: Vec<(u64, u64, String)> = data
        .iter()
        .map(|(&addr, (n, size))| (addr, *size, n.clone()))
        .collect();
    // Function addresses name themselves in comments
    // (`__libc_start_main(0x4003e0 /* guest_main */, ...)`).
    let mut fn_entries: Vec<u64> = cfg.functions.keys().copied().collect();
    fn_entries.sort();
    let mut fns = Vec::with_capacity(fn_entries.len());
    for e in fn_entries {
        let mut n = name_of(e).unwrap_or_else(|| format!("sub_{e:x}"));
        if n == "main" && cfg.stub_import(e).is_none() {
            // Printed as `guest_main` (C's own `main` wraps it).
            n = "guest_main".to_owned();
        }
        if n.contains("*/") {
            n = n.replace("*/", "* /");
        }
        fns.push((e, n));
    }
    Ok(PreparedC {
        module,
        summaries: Summaries {
            cpu,
            conv_args: conv_names,
            banner: banner.replace("*/", "* /"),
            data: data_syms,
            fns,
            entries,
            guest_bits: info.guest_bits,
        },
    })
}

impl<'ctx> PreparedC<'ctx> {
    /// Simplify the ABI form and recover guest strings/prototypes.
    /// `read` only needs constant guest memory; the image may be
    /// released once this returns.
    /// Function-pass concurrency comes from `options`; LLVM state is never
    /// shared between computing threads. Cross-function transformations and
    /// rendering remain serial. Capture options before changing CPU affinity.
    pub fn transform(
        self,
        machine: &TargetMachine,
        read: Reader<'_>,
        options: DecompileOptions,
    ) -> Result<TransformedC<'ctx>, Error> {
        let PreparedC { module, summaries } = self;
        simplify(&module, machine, options)?;
        // Jump tables: switch on the index rather than on code addresses.
        let indexed = unsafe {
            biara_index_switches(
                module.as_mut_ptr().cast(),
                read_cb,
                &read as *const Reader as *mut c_void,
            )
        };
        if indexed > 0 {
            function_passes(
                &module,
                machine,
                c"function(simplifycfg,instcombine<no-verify-fixpoint>,adce,simplifycfg)",
                options,
            )?;
        }
        let (strings, shapes) = guest_strings(&module, read, 96, summaries.guest_bits);
        // Typed import declarations: `const char *` at string positions,
        // `uint64_t` elsewhere, up to the most arguments any call passes.
        let mut shape_names: Vec<&String> = shapes.keys().collect();
        shape_names.sort();
        let mut protos = Vec::with_capacity(shape_names.len());
        for name in shape_names {
            let shape = &shapes[name];
            let mut mask = 0u64;
            for &i in crate::audit::string_args(name) {
                if i < 64 {
                    mask |= 1u64 << i;
                }
            }
            // Fixed parameters cover every call; `, ...` covers the rest.
            protos.push((
                (*name).clone(),
                shape.min_args,
                mask,
                shape.min_args != shape.max_args,
            ));
        }
        Ok(TransformedC {
            layouts: None,
            layout_debug_dirty: false,
            module,
            cpu: summaries.cpu,
            conv_args: summaries.conv_args,
            banner: summaries.banner,
            data: summaries.data,
            fns: summaries.fns,
            entries: summaries.entries,
            strings: strings
                .into_iter()
                .map(|(addr, text)| (addr, text.into_string().unwrap_or_default()))
                .collect(),
            protos,
        })
    }
}

/// Callback state for `render`: the Rust sink plus the first error.
struct RenderState<'w> {
    out: &'w mut dyn std::io::Write,
    err: Option<std::io::Error>,
}

unsafe extern "C" fn write_cb(ctx: *mut c_void, p: *const c_char, n: usize) -> i32 {
    let state = unsafe { &mut *(ctx as *mut RenderState) };
    if state.err.is_some() {
        return 1;
    }
    // Never unwind across FFI: catch panics, record them as errors.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state
            .out
            .write_all(unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n) })
    }));
    match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            state.err = Some(e);
            1
        }
        Err(_) => {
            state.err = Some(std::io::Error::other("C sink panicked"));
            1
        }
    }
}

struct PackageState<'a> {
    consumer: &'a mut dyn FnMut(FunctionPackage) -> std::io::Result<()>,
    err: Option<std::io::Error>,
}
unsafe extern "C" fn package_cb(ctx: *mut c_void, p: *const c_char, n: usize) -> i32 {
    let state = unsafe { &mut *(ctx as *mut PackageState) };
    if state.err.is_some() {
        return 1;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let package =
            serde_json::from_slice(unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n) })
                .map_err(std::io::Error::other)?;
        (state.consumer)(package)
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            state.err = Some(e);
            1
        }
        Err(_) => {
            state.err = Some(std::io::Error::other("decompilation consumer panicked"));
            1
        }
    }
}

impl<'ctx> TransformedC<'ctx> {
    fn ensure_layouts(&mut self) -> Result<(), Error> {
        if let Some(layouts) = &mut self.layouts {
            if self.layout_debug_dirty {
                layouts.apply_debug(&self.module)?;
            }
        } else {
            self.layouts = Some(crate::layouts::Handle::build(
                &self.module,
                &self.cpu,
                MARGIN,
            )?);
        }
        self.layout_debug_dirty = false;
        Ok(())
    }

    /// Reusable observed layout evidence. Sizes describe accessed bytes, not
    /// declared object extents; conflicts and bounded-analysis status remain
    /// explicit. The renderer consumes this same cached analysis.
    pub fn layout_facts(&mut self) -> Result<crate::layouts::LayoutFacts, Error> {
        self.ensure_layouts()?;
        self.layouts.as_ref().unwrap().facts()
    }

    /// Layout evidence and the ABI types of the transformed functions.
    pub fn type_facts(&mut self) -> Result<TypeFacts, Error> {
        let layouts = self.layout_facts()?;
        let signatures = crate::signatures::summarize(&self.module, &layouts)?;
        Ok(TypeFacts {
            layouts,
            signatures,
        })
    }

    /// Visit independent guest-function records in deterministic presentation
    /// order. One function is buffered; callback errors/panics stop immediately.
    /// The caller owns any sink flushing (unlike `render`, this is not a sink).
    pub fn visit_functions(
        mut self,
        consumer: &mut dyn FnMut(FunctionPackage) -> std::io::Result<()>,
    ) -> Result<CStats, Error> {
        let mut state = PackageState {
            consumer,
            err: None,
        };
        let result = self.emit(
            1,
            package_cb,
            &mut state as *mut PackageState as *mut c_void,
        );
        if let Some(e) = state.err {
            return Err(Error::Io(e));
        }
        result
    }

    /// Select analysis bodies only, in the supplied root/context order.
    /// Code and call declarations remain intact for faithful C rendering.
    pub fn select_functions(&mut self, entries: &[u64]) {
        let cx = self.module.get_context();
        let kind = cx.get_kind_id("biara.present");
        for name in self.entries.values() {
            self.module
                .get_function(name)
                .unwrap()
                .as_global_value()
                .set_metadata(cx.metadata_node(&[]), kind);
        }
        let mut seen = BTreeSet::new();
        for (order, entry) in entries.iter().enumerate() {
            if !seen.insert(entry) {
                continue;
            }
            if let Some(f) = self
                .entries
                .get(entry)
                .and_then(|name| self.module.get_function(name))
            {
                f.as_global_value().set_metadata(
                    cx.metadata_node(&[
                        cx.i64_type().const_int(order as u64, false).into(),
                        cx.i32_type().const_int(1, false).into(),
                    ]),
                    kind,
                );
            }
        }
    }

    /// Annotate unique entry-register bindings; do not rename LLVM values or
    /// alter signatures. The renderer preserves original names as evidence.
    pub fn apply_debug_names(&mut self, names: &[DebugName]) {
        let cx = self.module.get_context();
        let kind = cx.get_kind_id("biara.debug_name");
        for (&entry, symbol) in &self.entries {
            let mut bindings: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
            let mut used: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
            for n in names
                .iter()
                .filter(|n| n.function == entry && !n.name.is_empty())
            {
                bindings.entry(&n.register).or_default().insert(&n.name);
                used.entry(&n.name).or_default().insert(&n.register);
            }
            let nodes: Vec<_> = bindings
                .into_iter()
                .filter_map(|(reg, names)| {
                    if names.len() != 1 {
                        return None;
                    }
                    let name = names.into_iter().next().unwrap();
                    if used[name].len() != 1 {
                        return None;
                    }
                    Some(
                        cx.metadata_node(&[
                            cx.metadata_string(reg).into(),
                            cx.metadata_string(name).into(),
                        ])
                        .into(),
                    )
                })
                .collect();
            self.module
                .get_function(symbol)
                .unwrap()
                .as_global_value()
                .set_metadata(cx.metadata_node(&nodes), kind);
        }
    }

    /// Supply range-specific declared objects. The renderer requires an exact
    /// whole-slot match and source coverage; absent/ambiguous bindings stay neutral.
    pub fn apply_debug_objects(&mut self, objects: &[DebugObject]) {
        self.layout_debug_dirty = true;
        let cx = self.module.get_context();
        let kind = cx.get_kind_id("biara.debug_objects");
        for (&entry, symbol) in &self.entries {
            let nodes: Vec<_> = objects
                .iter()
                .filter(|o| o.function == entry && o.start < o.end && o.size != 0)
                .map(|o| {
                    cx.metadata_node(&[
                        cx.i64_type().const_int(o.start, false).into(),
                        cx.i64_type().const_int(o.end, false).into(),
                        cx.i64_type().const_int(o.offset as u64, true).into(),
                        cx.i64_type().const_int(o.size, false).into(),
                        cx.metadata_string(&o.name).into(),
                        cx.metadata_string(o.type_name.as_deref().unwrap_or(""))
                            .into(),
                    ])
                    .into()
                })
                .collect();
            self.module
                .get_function(symbol)
                .unwrap()
                .as_global_value()
                .set_metadata(cx.metadata_node(&nodes), kind);
        }
    }

    /// Emit the C source to `out`, chunk by chunk. No full C buffer
    /// exists on either side: `biara_emit_c_cached` streams bounded
    /// pieces and stops at the first failed write, which surfaces here.
    /// Flushes the sink on success and returns the placeholder count.
    pub fn render(mut self, out: &mut dyn std::io::Write) -> Result<CStats, Error> {
        let mut state = RenderState { out, err: None };
        let result = self.emit(0, write_cb, &mut state as *mut RenderState as *mut c_void);
        if let Some(error) = state.err {
            return Err(Error::Io(error));
        }
        let stats = result?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.out.flush()))
            .unwrap_or_else(|_| Err(std::io::Error::other("C sink panicked")))?;
        Ok(stats)
    }

    fn emit(&mut self, mode: u32, write: WriteFn, ctx: *mut c_void) -> Result<CStats, Error> {
        self.ensure_layouts()?;
        let cpu_names: Vec<CString> = self
            .cpu
            .iter()
            .map(|(_, _, n)| CString::new(n.as_str()).unwrap())
            .collect();
        let cpu_fields: Vec<CField> = self
            .cpu
            .iter()
            .zip(&cpu_names)
            .map(|((off, bytes, _), n)| CField {
                off: MARGIN as i64 + off,
                bytes: *bytes,
                name: n.as_ptr(),
            })
            .collect();
        let conv_names: Vec<CString> = self
            .conv_args
            .iter()
            .map(|n| CString::new(n.as_str()).unwrap())
            .collect();
        let conv_ptrs: Vec<*const c_char> = conv_names.iter().map(|n| n.as_ptr()).collect();
        let data_names: Vec<CString> = self
            .data
            .iter()
            .map(|(_, _, n)| CString::new(n.as_str()).unwrap())
            .collect();
        let data_syms: Vec<DataSymbol> = self
            .data
            .iter()
            .zip(&data_names)
            .map(|((addr, size, _), name)| DataSymbol {
                addr: *addr,
                size: *size,
                name: name.as_ptr(),
            })
            .collect();
        let fn_names: Vec<CString> = self
            .fns
            .iter()
            .map(|(_, n)| CString::new(n.as_str()).unwrap())
            .collect();
        let fn_syms: Vec<GuestStr> = self
            .fns
            .iter()
            .zip(&fn_names)
            .map(|((addr, _), name)| GuestStr {
                addr: *addr,
                text: name.as_ptr(),
            })
            .collect();
        let string_syms: Vec<CString> = self
            .strings
            .iter()
            .map(|(_, t)| CString::new(t.as_str()).unwrap())
            .collect();
        let string_ptrs: Vec<GuestStr> = self
            .strings
            .iter()
            .zip(&string_syms)
            .map(|((addr, _), text)| GuestStr {
                addr: *addr,
                text: text.as_ptr(),
            })
            .collect();
        let proto_names: Vec<CString> = self
            .protos
            .iter()
            .map(|(n, _, _, _)| CString::new(n.as_str()).unwrap())
            .collect();
        let proto_syms: Vec<Proto> = self
            .protos
            .iter()
            .zip(&proto_names)
            .map(|((_, nargs, mask, ellipsis), name)| Proto {
                name: name.as_ptr(),
                nargs: *nargs,
                strmask: *mask,
                ellipsis: u32::from(*ellipsis),
            })
            .collect();
        let banner = CString::new(self.banner.as_str()).unwrap();
        let mut unsupported = 0usize;
        let failed = unsafe {
            biara_emit_c_cached(
                self.layouts.as_ref().unwrap().as_ptr(),
                self.module.as_mut_ptr().cast(),
                cpu_fields.as_ptr(),
                cpu_fields.len(),
                conv_ptrs.as_ptr(),
                conv_ptrs.len(),
                MARGIN,
                banner.as_ptr(),
                &mut unsupported,
                data_syms.as_ptr(),
                data_syms.len(),
                string_ptrs.as_ptr(),
                string_ptrs.len(),
                proto_syms.as_ptr(),
                proto_syms.len(),
                fn_syms.as_ptr(),
                fn_syms.len(),
                mode,
                write,
                ctx,
            )
        };
        if failed != 0 {
            return Err(Error::Llvm("C emitter stopped".into()));
        }
        Ok(CStats { unsupported })
    }
}

unsafe extern "C" {
    #[link_name = "free"]
    fn libc_free(p: *mut c_void);
}

fn function_passes(
    module: &Module<'_>,
    machine: &TargetMachine,
    pipeline: &CStr,
    options: DecompileOptions,
) -> Result<(), Error> {
    let mut error = std::ptr::null_mut();
    let failed = unsafe {
        biara_parallel_function_passes(
            module.as_mut_ptr().cast(),
            machine.as_mut_ptr().cast(),
            pipeline.as_ptr(),
            options.workers(),
            &mut error,
        )
    };
    let message = if error.is_null() {
        None
    } else {
        let message = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        unsafe { libc_free(error.cast()) };
        Some(message)
    };
    if failed != 0 {
        return Err(Error::Llvm(message.unwrap_or_else(|| {
            "function-local passes failed without a diagnostic".into()
        })));
    }
    Ok(())
}

/// Function-local cleanup of the ABI form: promote registers, fold the
/// frame address arithmetic into the frame allocas (until nothing new
/// folds), then the usual scalar pipeline; no inlining.
fn simplify(
    module: &Module<'_>,
    machine: &TargetMachine,
    options: DecompileOptions,
) -> Result<(), Error> {
    let run = |p: &CStr| function_passes(module, machine, p, options);
    for _ in 0..4 {
        run(c"function(sroa,early-cse<memssa>,instcombine<no-verify-fixpoint>)")?;
        memory::rebase_guest_pointers(module)?;
        let folded = unsafe { biara_fold_frames(module.as_mut_ptr().cast()) };
        if folded == 0 {
            break;
        }
    }
    run(
        c"function(sroa,instcombine<no-verify-fixpoint>,simplifycfg,gvn,dse,adce,\
         instcombine<no-verify-fixpoint>,simplifycfg)",
    )?;
    module
        .run_passes("globaldce", machine, PassBuilderOptions::create())
        .map_err(|e| Error::Llvm(e.to_string()))?;
    // Plain divisions read as `/` and `%`: fold the prelude calls whose
    // high half only extends the low back into `sdiv`/`srem`.
    let sugared = unsafe { biara_div_sugar(module.as_mut_ptr().cast()) };
    if sugared > 0 {
        run(c"function(simplifycfg,instcombine<no-verify-fixpoint>,adce)")?;
    }
    // One `return` per arm instead of a `common_ret_op` join: duplicate a
    // return-only block into unconditionally-branching predecessors, then
    // clean up what died.
    let duped = unsafe { biara_dup_returns(module.as_mut_ptr().cast()) };
    if duped > 0 {
        run(c"function(simplifycfg,adce)")?;
    }
    module.verify().map_err(|e| Error::Llvm(e.to_string()))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn render_reports_deferred_write_failure() {
        let cx = Context::create();
        let module = cx.create_module("sink");
        let ty = cx.i64_type();
        let function = module.add_function("answer", ty.fn_type(&[], false), None);
        let builder = cx.create_builder();
        builder.position_at_end(cx.append_basic_block(function, "entry"));
        builder
            .build_return(Some(&ty.const_int(42, false)))
            .unwrap();
        let transformed = TransformedC {
            layouts: None,
            layout_debug_dirty: false,
            module,
            cpu: Vec::new(),
            conv_args: Vec::new(),
            banner: String::new(),
            data: Vec::new(),
            fns: Vec::new(),
            entries: BTreeMap::new(),
            strings: Vec::new(),
            protos: Vec::new(),
        };
        // This small output fits in BufWriter. The underlying write only
        // fails when render flushes, not during the native callbacks.
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let mut sink = std::io::BufWriter::new(full);
        let Err(Error::Io(error)) = transformed.render(&mut sink) else {
            panic!("render must report the deferred disk-full error");
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
    }

    fn package_module<'ctx>(cx: &'ctx Context) -> TransformedC<'ctx> {
        let module = cx.create_module("packages");
        let ty = cx.i64_type();
        let builder = cx.create_builder();
        let mut entries = BTreeMap::new();
        for (entry, name) in [(0x1000, "first"), (0x2000, "second")] {
            let f = module.add_function(name, ty.fn_type(&[], false), None);
            f.as_global_value().set_metadata(
                cx.metadata_node(&[
                    ty.const_int(entry, false).into(),
                    cx.i32_type().const_int(1, false).into(),
                ]),
                cx.get_kind_id("biara.entry"),
            );
            builder.position_at_end(cx.append_basic_block(f, "entry"));
            builder
                .build_return(Some(&ty.const_int(entry, false)))
                .unwrap();
            entries.insert(entry, name.to_owned());
        }
        TransformedC {
            layouts: None,
            layout_debug_dirty: false,
            module,
            cpu: Vec::new(),
            conv_args: Vec::new(),
            banner: String::new(),
            data: Vec::new(),
            fns: Vec::new(),
            entries,
            strings: Vec::new(),
            protos: Vec::new(),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn generated_c_preserves_scalar_and_vector_bits() {
        let cx = Context::create();
        let ir = inkwell::memory_buffer::MemoryBuffer::create_from_memory_range_copy(
            br#"
                define double @flip_sign(double %x) {
                    %bits = bitcast double %x to i64
                    %flipped = xor i64 %bits, -9223372036854775808
                    %result = bitcast i64 %flipped to double
                    ret double %result
                }
                define <4 x float> @flip_vector(<4 x float> %x) {
                    %bits = bitcast <4 x float> %x to i128
                    %flipped = xor i128 %bits, 18446744073709551615
                    %result = bitcast i128 %flipped to <4 x float>
                    ret <4 x float> %result
                }
                define i64 @vector_word(<4 x float> %x) {
                    %bits = bitcast <4 x float> %x to <2 x i64>
                    %word = extractelement <2 x i64> %bits, i32 1
                    ret i64 %word
                }
            "#,
            "bit-patterns",
        );
        let mut transformed = package_module(&cx);
        transformed.module = cx.create_module_from_ir(ir).unwrap();
        transformed.entries.clear();
        let mut source = Vec::new();
        transformed.render(&mut source).unwrap();
        source.extend_from_slice(
            br#"
            int main(void) {
                uint64_t values[] = {0, 0x8000000000000000ull, 0x3ff0000000000000ull,
                    0x7ff0000000000000ull, 0x7ff8000012345678ull, 0xfff8000012345678ull};
                for (unsigned i = 0; i < sizeof(values)/sizeof(*values); ++i) {
                    union { uint64_t bits; double value; } in = {.bits = values[i]};
                    union { uint64_t bits; double value; } out = {.value = flip_sign(in.value)};
                    if (out.bits != (in.bits ^ 0x8000000000000000ull)) return 1;
                }
                union { biara_u128 bits; biara_v4f value; } in = {
                    .bits = ((biara_u128)0x800000007fc01234ull << 64) | 0x7fc0567800000000ull};
                union { biara_u128 bits; biara_v4f value; } out = {.value = flip_vector(in.value)};
                if (out.bits != (in.bits ^ 0xffffffffffffffffull)) return 2;
                if (vector_word(in.value) != 0x800000007fc01234ull) return 3;
                return 0;
            }
        "#,
        );
        let dir = std::env::temp_dir().join(format!("biara-bit-patterns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = dir.join("generated.c");
        let binary = dir.join("generated");
        std::fs::write(&c, source).unwrap();
        let output = std::process::Command::new(env!("BIARA_CLANG"))
            .args(["-std=gnu17", "-O1", "-Wall", "-Werror"])
            .arg(&c)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            std::process::Command::new(&binary)
                .status()
                .unwrap()
                .success()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn generated_strings_preserve_bytes_and_escaping_pointer_identity() {
        let cx = Context::create();
        let make = || {
            let ir = inkwell::memory_buffer::MemoryBuffer::create_from_memory_range_copy(
                br#"
                declare i32 @strcmp(i64, i64)
                declare i64 @strlen(i64)
                declare i64 @capture(i64)
                define i32 @only(i64 %s) !biara.entry !0 {
                    %r = call i32 @strcmp(i64 %s, i64 12288)
                    ret i32 %r
                }
                define i32 @shared_a(i64 %s) !biara.entry !1 {
                    %r = call i32 @strcmp(i64 %s, i64 16384)
                    ret i32 %r
                }
                define i32 @shared_b(i64 %s) !biara.entry !2 {
                    %r = call i32 @strcmp(i64 %s, i64 16384)
                    ret i32 %r
                }
                define i64 @escape_a() !biara.entry !3 {
                    %r = call i64 @capture(i64 20480)
                    ret i64 %r
                }
                define i64 @escape_b() !biara.entry !4 {
                    %r = call i64 @capture(i64 24576)
                    ret i64 %r
                }
                define i64 @raw_length() !biara.entry !5 {
                    %r = call i64 @strlen(i64 28672)
                    ret i64 %r
                }
                define i64 @raw_address() !biara.entry !6 {
                    ret i64 28672
                }
                !0 = !{i64 4096}
                !1 = !{i64 4097}
                !2 = !{i64 4098}
                !3 = !{i64 4099}
                !4 = !{i64 4100}
                !5 = !{i64 4101}
                !6 = !{i64 4102}
            "#,
                "strings",
            );
            let mut transformed = package_module(&cx);
            transformed.module = cx.create_module_from_ir(ir).unwrap();
            transformed.entries.clear();
            transformed.strings = vec![
                (0x3000, r#"quote\" slash\\\n\0019"#.into()),
                (0x4000, "shared".into()),
                (0x5000, "same bytes".into()),
                (0x6000, "same bytes".into()),
                (0x7000, "raw".into()),
            ];
            transformed.protos = vec![
                ("strcmp".into(), 2, 3, false),
                ("strlen".into(), 1, 1, false),
                ("capture".into(), 1, 1, false),
            ];
            transformed
        };
        let mut complete = Vec::new();
        make().render(&mut complete).unwrap();
        let mut dependencies = BTreeMap::new();
        let mut bodies = String::new();
        make()
            .visit_functions(&mut |package| {
                for dependency in package.dependencies {
                    dependencies.entry(dependency.id).or_insert(dependency.text);
                }
                bodies.push_str(&package.body);
                Ok(())
            })
            .unwrap();
        let packaged = format!(
            "#include <stdint.h>\n{}{}",
            dependencies.into_values().collect::<String>(),
            bodies,
        )
        .into_bytes();
        let harness = br#"
            uint64_t capture(const char *s) { return (uint64_t)s; }
            int main(void) {
                if (only((uint64_t)"quote\" slash\\\n\0019") != 0) return 1;
                if (shared_a((uint64_t)"shared") != 0 ||
                    shared_b((uint64_t)"shared") != 0) return 2;
                // Equal text at distinct escaping addresses is not one object.
                if (escape_a() == escape_b()) return 3;
                if (raw_length() != 3 || raw_address() != 0x7000) return 4;
                return 0;
            }
        "#;
        let dir = std::env::temp_dir().join(format!("biara-strings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (mode, mut source) in [("complete", complete), ("packaged", packaged)] {
            source.extend_from_slice(harness);
            let c = dir.join(format!("{mode}.c"));
            let binary = dir.join(mode);
            std::fs::write(&c, source).unwrap();
            let output = std::process::Command::new(env!("BIARA_CLANG"))
                .args(["-std=gnu17", "-O1", "-fno-builtin", "-Wall", "-Werror"])
                .arg(&c)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                std::process::Command::new(&binary)
                    .status()
                    .unwrap()
                    .success(),
                "{mode}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn package_consumer_error_stops_before_later_functions() {
        let cx = Context::create();
        let mut visits = Vec::new();
        let error = package_module(&cx)
            .visit_functions(&mut |package| {
                visits.push((package.address, package.metrics.casts));
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            })
            .err()
            .unwrap();
        assert!(matches!(error,Error::Io(e) if e.kind()==std::io::ErrorKind::PermissionDenied));
        // A `(void)` parameter list is not an expression cast.
        assert_eq!(visits, vec![(0x1000, 0)]);
    }

    #[test]
    fn package_consumer_panic_does_not_cross_native_boundary() {
        let cx = Context::create();
        let mut visits = 0;
        let result = package_module(&cx).visit_functions(&mut |_| {
            visits += 1;
            panic!("consumer failed");
        });
        assert!(matches!(result, Err(Error::Io(_))));
        assert_eq!(visits, 1);
    }

    #[test]
    fn failed_function_round_can_be_followed_by_a_successful_round() {
        let cx = Context::create();
        let transformed = package_module(&cx);
        let machine = crate::host_machine().unwrap();
        let options = DecompileOptions::with_workers(std::num::NonZeroUsize::new(2).unwrap());
        let error = function_passes(
            &transformed.module,
            &machine,
            c"function(biara.invalid.pass)",
            options,
        )
        .unwrap_err();
        assert!(matches!(error, Error::Llvm(_)));
        function_passes(
            &transformed.module,
            &machine,
            c"function(instcombine<no-verify-fixpoint>,simplifycfg)",
            options,
        )
        .unwrap();
        let engine = transformed
            .module
            .create_jit_execution_engine(inkwell::OptimizationLevel::None)
            .unwrap();
        for (name, expected) in [("first", 0x1000), ("second", 0x2000)] {
            let function = unsafe {
                engine
                    .get_function::<unsafe extern "C" fn() -> u64>(name)
                    .unwrap()
            };
            assert_eq!(unsafe { function.call() }, expected);
        }
    }

    #[test]
    fn failed_worker_restores_bodies_before_retry() {
        let cx = Context::create();
        let transformed = package_module(&cx);
        let machine = crate::host_machine().unwrap();
        let options = DecompileOptions::with_workers(std::num::NonZeroUsize::new(2).unwrap());
        let invalid =
            transformed
                .module
                .add_function("invalid", cx.i64_type().fn_type(&[], false), None);
        let block = cx.append_basic_block(invalid, "entry");
        let builder = cx.create_builder();
        builder.position_at_end(block);
        // A real worker parse/verification failure, after extraction; the
        // pipeline itself is valid. Fix the input and retry the same module.
        builder
            .build_return(Some(&cx.i32_type().const_int(42, false)))
            .unwrap();
        let error = function_passes(
            &transformed.module,
            &machine,
            c"function(instcombine<no-verify-fixpoint>,simplifycfg)",
            options,
        )
        .unwrap_err();
        assert!(matches!(error, Error::Llvm(_)));
        invalid
            .get_first_basic_block()
            .unwrap()
            .get_terminator()
            .unwrap()
            .erase_from_basic_block();
        builder.position_at_end(invalid.get_first_basic_block().unwrap());
        builder
            .build_return(Some(&cx.i64_type().const_int(42, false)))
            .unwrap();
        function_passes(
            &transformed.module,
            &machine,
            c"function(instcombine<no-verify-fixpoint>,simplifycfg)",
            options,
        )
        .unwrap();
        let engine = transformed
            .module
            .create_jit_execution_engine(inkwell::OptimizationLevel::None)
            .unwrap();
        for (name, expected) in [("first", 0x1000), ("second", 0x2000), ("invalid", 42)] {
            let function = unsafe {
                engine
                    .get_function::<unsafe extern "C" fn() -> u64>(name)
                    .unwrap()
            };
            assert_eq!(unsafe { function.call() }, expected);
        }
    }

    #[test]
    fn grouped_round_preserves_private_calls_and_shared_global_state() {
        let cx = Context::create();
        let source = b"
            @factor = internal constant i64 7
            @state = internal global i64 11
            define i64 @first(i64 %x) {
                %v = call i64 @leaf(i64 %x)
                %k = load i64, ptr @factor
                %r = add i64 %v, %k
                ret i64 %r
            }
            define i64 @second(i64 %x) {
                %v = call i64 @leaf(i64 %x)
                %k = load i64, ptr @state
                %r = add i64 %v, %k
                ret i64 %r
            }
            define internal i64 @leaf(i64 %x) {
                %r = call i64 @leaf2(i64 %x)
                ret i64 %r
            }
            define internal i64 @leaf2(i64 %x) {
                %v = mul i64 %x, 3
                %k = load i64, ptr @factor
                %r = add i64 %v, %k
                ret i64 %r
            }
            define void @set_state(i64 %x) {
                store i64 %x, ptr @state
                ret void
            }
        \0";
        // LLVM's text parser reads the sentinel immediately after the slice.
        let buffer = inkwell::memory_buffer::MemoryBuffer::create_from_memory_range(
            &source[..source.len() - 1],
            "shared-state",
        );
        let module = cx.create_module_from_ir(buffer).unwrap();
        let machine = crate::host_machine().unwrap();
        function_passes(
            &module,
            &machine,
            c"function(instcombine<no-verify-fixpoint>,simplifycfg,gvn)",
            DecompileOptions::with_workers(std::num::NonZeroUsize::new(2).unwrap()),
        )
        .unwrap();
        let engine = module
            .create_jit_execution_engine(inkwell::OptimizationLevel::None)
            .unwrap();
        let first = unsafe {
            engine
                .get_function::<unsafe extern "C" fn(u64) -> u64>("first")
                .unwrap()
        };
        let second = unsafe {
            engine
                .get_function::<unsafe extern "C" fn(u64) -> u64>("second")
                .unwrap()
        };
        let set_state = unsafe {
            engine
                .get_function::<unsafe extern "C" fn(u64)>("set_state")
                .unwrap()
        };
        assert_eq!(unsafe { second.call(5) }, 33);
        for state in [0, 19, u64::MAX] {
            unsafe { set_state.call(state) };
            for x in [0u64, 1, 1 << 63, u64::MAX] {
                let value = x.wrapping_mul(3).wrapping_add(7);
                assert_eq!(unsafe { first.call(x) }, value.wrapping_add(7));
                assert_eq!(unsafe { second.call(x) }, value.wrapping_add(state));
            }
        }
    }
}
