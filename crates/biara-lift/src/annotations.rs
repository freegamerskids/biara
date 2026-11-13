//! Annotation inputs (C4): user/agent-supplied function names, C
//! signatures and struct layouts.
//!
//! Names need no ABI-map change: they flow into lifting through the caller's
//! `name_of` closure and are re-applied to prepared/transformed modules by
//! [`crate::PreparedC::apply_annotations`] and
//! [`crate::TransformedC::apply_annotations`] as LLVM renames, so direct
//! calls (which reference the renamed `FunctionValue`) stay consistent.
//! Globals rename through the caller's `data` table plus
//! [`crate::TransformedC::apply_annotations`]; struct fields rename through
//! layout-analysis display renames (ids, sizes, offsets and bindings never
//! move).
//!
//! Explicit signatures adjust the recovered ABI map here, before lifting:
//! each declared parameter/result type selects the matching ABI lane kind
//! (integer/pointer/float/double/boolean) for the slot the convention
//! already assigns positionally, and records the canonical C spelling for
//! `biara.c_type`/`biara.c_return` attributes plus [`crate::FuncSig`]
//! declared facts. The declaration is authoritative for valid ABI
//! locations, including formals the recovery did not observe (unused
//! parameters still occupy their convention slot); it never invents
//! frame facts. Supported grammar (exact; anything else is a loud error,
//! never a silent downgrade): `ret name(params)` with one return type
//! and a parenthesized list; scalar types `void` (return only),
//! 8-bit integers (`char`, `signed char`, `unsigned char`, `int8_t`,
//! `uint8_t`), 16-bit integers (`short`, `signed short`,
//! `unsigned short`, `int16_t`, `uint16_t`), 32-bit integers (`int`,
//! `signed`, `unsigned`, `int32_t`, `uint32_t`, `long` on LLP64 Windows,
//! `enum E`), 64-bit integers (`long` on LP64, `long long`, `int64_t`,
//! `uint64_t`, `size_t`, `uintptr_t`, `intptr_t`), `bool`/`_Bool` (real
//! boolean, `i1` transport), `float`, `double`; pointers `T *` (any
//! depth, `const`-qualified, arrays decay); named struct pointers
//! `struct name *` (declared in
//! [`biara_proto::annotations::Annotations::structs`]). `long` width
//! resolves by guest model (`cfg.os == "windows"` means LLP64 32-bit,
//! otherwise LP64 64-bit). Unsupported: variadics, function pointers,
//! by-value aggregates, 128-bit by-value scalars, `void` parameters,
//! empty `()` lists, and parameter counts the convention cannot place.
//! Annotations on unknown addresses are ignored (they resolve nowhere).
//! Argument and result declarations record into separate explicit sets
//! (no shared per-physical-register override): AAPCS64 `x0` as argument
//! and result stay independent.

use std::collections::BTreeMap;

use biara_abi::{FunctionAbi, LaneType};
use biara_cfg::Cfg;
use biara_proto::annotations::Annotations;
use biara_tcg::ContextInfo;

use crate::Error;

/// User-declared struct layout, re-exported for layout-rename callers.
pub type StructDecl = biara_proto::annotations::StructAnnotation;

/// The k-th lane of the convention's FP sequence, counting contiguous
/// `FpLane` tables in order. `None` where the convention passes no such
/// lane in registers.
fn float_lane(spec: &biara_cfg::ArchSpec, float_index: u32) -> Option<u32> {
    let mut remaining = float_index;
    let mut base = 0u32;
    for table in spec.unknown_call.fp_args {
        if remaining < table.count {
            return Some(base + remaining);
        }
        remaining -= table.count;
        base += table.count;
    }
    None
}
/// `true` on LLP64 guests (Windows): `long` is 32 bits there, 64 on LP64.
fn long_is_32(cfg: &Cfg) -> bool {
    cfg.os == "windows"
}
/// One declared C type: scalar width/signedness, boolean, float/double,
/// pointer (and, for struct pointers, which declared struct it names),
/// plus the canonical spelling consumed as `biara.c_type`/`biara.c_return`
/// and [`crate::FuncSig`] declared facts.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CType {
    Void,
    /// Integer with declared width and signedness. Signedness is
    /// orthogonal to LLVM transport (integers are sign-agnostic in IR);
    /// it is preserved separately so rendering spells the declared C
    /// type (`int16_t` stays signed) while transport stays bit-exact.
    Int {
        bits: u32,
        signed: bool,
    },
    /// Real boolean (`bool`/`_Bool`): `i1` transport, `_Bool` spelling.
    Bool,
    Float32,
    Float64,
    Ptr {
        depth: u32,
        pointee_struct: Option<String>,
        spelling: String,
    },
}

impl CType {
    /// Canonical faithful C spelling for attributes and declared facts.
    fn spelling(&self) -> String {
        match self {
            CType::Void => "void".to_owned(),
            CType::Int { bits, signed } => match (bits, signed) {
                (8, true) => "int8_t".to_owned(),
                (8, false) => "uint8_t".to_owned(),
                (16, true) => "int16_t".to_owned(),
                (16, false) => "uint16_t".to_owned(),
                (32, true) => "int32_t".to_owned(),
                (32, false) => "uint32_t".to_owned(),
                (64, true) => "int64_t".to_owned(),
                (64, false) => "uint64_t".to_owned(),
                _ => "uint64_t".to_owned(),
            },
            CType::Bool => "_Bool".to_owned(),
            CType::Float32 => "float".to_owned(),
            CType::Float64 => "double".to_owned(),
            CType::Ptr { spelling, .. } => spelling.clone(),
        }
    }
}

/// A parsed explicit signature: return type plus parameter types in order.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSig {
    ret: CType,
    params: Vec<CType>,
    variadic: bool,
}

/// Split a top-level comma list (depth tracks `<>()[]`; quotes skipped).
fn split_top_level(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0u32;
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else if bytes[i] == quote {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            b'(' | b'<' | b'[' => depth += 1,
            b')' | b'>' | b']' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(text[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = text[start..].trim();
    if !tail.is_empty() || !parts.is_empty() {
        parts.push(tail.to_owned());
    }
    parts
}

/// Parse one C type spelling into a [`CType`]. `structs` holds declared
/// struct names for `struct name *` validation. `long_is_32` selects the
/// guest data model (LLP64 Windows vs LP64): `long` spellings resolve to
/// 32 bits on LLP64, 64 on LP64. `const`/`volatile` on scalars are
/// transport-neutral; pointer `const` normalizes into the canonical
/// spelling (`const char *` keeps its qualifier, others drop inner
/// qualifiers the transport ignores).
fn parse_type_impl(
    text: &str,
    structs: &BTreeMap<String, biara_proto::annotations::StructAnnotation>,
    long_is_32: bool,
) -> Result<CType, String> {
    let mut core = text.trim().to_owned();
    if core.is_empty() {
        return Err("empty type".into());
    }
    // Strip a trailing parameter name: `int foo`, `char *s`, `struct p *ctx`. The name is the
    // final identifier, whether a space or a `*` precedes it (`*s` is the usual C spelling), but
    // never a type word, and never the tag of a bare `struct tag`.
    if !core.ends_with('*') && !core.ends_with(']') && !core.contains('(') {
        let name_len = core
            .bytes()
            .rev()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        let (head, candidate) = core.split_at(core.len() - name_len);
        let head = head.trim_end();
        let is_keyword = matches!(
            candidate,
            "void"
                | "char"
                | "short"
                | "int"
                | "long"
                | "float"
                | "double"
                | "signed"
                | "unsigned"
                | "const"
                | "volatile"
                | "struct"
                | "bool"
                | "_Bool"
        ) || candidate.starts_with("uint")
            || candidate.starts_with("int")
            || candidate.starts_with("biara_");
        let is_struct_tag = head.rsplit(char::is_whitespace).next() == Some("struct");
        if name_len > 0 && !head.is_empty() && !is_keyword && !is_struct_tag {
            core = head.to_owned();
        }
    }
    // Function-pointer declarators (`int (*f)(int)`) are unsupported.
    if core.contains('(') {
        return Err(format!("unsupported type {text:?}"));
    }
    // Count pointer depth; `const`/`volatile` qualifiers are transport-neutral.
    let mut depth = 0u32;
    while core.trim_end().ends_with('*') {
        depth += 1;
        core = core.trim_end()[..core.trim_end().len() - 1]
            .trim_end()
            .to_owned();
    }
    // Array declarators (`int a[4]`) decay to a pointer, like C parameters.
    if let Some(bracket) = core.find('[') {
        let suffix = core[bracket..].trim();
        if !suffix.starts_with('[') || !suffix.ends_with(']') {
            return Err(format!("unsupported type {text:?}"));
        }
        depth += 1;
        core = core[..bracket].trim().to_owned();
        if core.is_empty() {
            return Err(format!("unsupported type {text:?}"));
        }
    }
    // A bare `struct name` by value is an aggregate: unsupported.
    if core.trim_start().starts_with("struct") && depth == 0 {
        return Err(format!(
            "by-value struct {text:?} needs aggregate ABI support"
        ));
    }
    if depth > 0 {
        let inner = core.trim();
        if inner.trim_start().starts_with("struct") {
            let name = inner.trim_start()["struct".len()..].trim();
            if name.is_empty() || name.contains(char::is_whitespace) || name.contains('*') {
                return Err(format!("unsupported type {text:?}"));
            }
            if !structs.contains_key(name) {
                return Err(format!("undeclared struct {name:?}"));
            }
            let mut spelling = format!("struct {name} ");
            spelling.push_str(&"*".repeat(depth as usize));
            return Ok(CType::Ptr {
                depth,
                pointee_struct: Some(name.to_owned()),
                spelling,
            });
        }
        if inner.contains('(') || inner.contains('[') {
            return Err(format!("unsupported type {text:?}"));
        }
        // Canonical plain-pointer spelling: `void *` for `void` base,
        // `const char *` for char bases (the only qualifier the renderer
        // distinguishes), otherwise the normalized base plus stars.
        let words: Vec<&str> = inner
            .split_whitespace()
            .filter(|w| *w != "volatile")
            .collect();
        let has_const = words.iter().any(|w| *w == "const");
        let base_words: Vec<&str> = words.into_iter().filter(|w| *w != "const").collect();
        let base = base_words.join(" ");
        let spelling = if base == "void" {
            format!("void {}", "*".repeat(depth as usize))
        } else if base == "char" && has_const {
            format!("const char {}", "*".repeat(depth as usize))
        } else if base.is_empty() {
            return Err(format!("unsupported type {text:?}"));
        } else {
            format!("{base} {}", "*".repeat(depth as usize))
        };
        let spelling = spelling.trim().to_owned();
        return Ok(CType::Ptr {
            depth,
            pointee_struct: None,
            spelling,
        });
    }
    let words: Vec<&str> = core
        .split_whitespace()
        .filter(|w| *w != "const" && *w != "volatile")
        .collect();
    let normalized = words.join(" ");
    // Widths are declared exactly; the ABI former coerces 8/16-bit lanes
    // (extend into the register slot, truncate out) so declared narrow
    // types lower and render exactly. `long` resolves by guest model.
    let long_bits = if long_is_32 { 32 } else { 64 };
    let ty = match normalized.as_str() {
        "void" => CType::Void,
        "float" => CType::Float32,
        "double" => CType::Float64,
        // `bool`/`_Bool` are the real boolean type: `i1` transport,
        // `_Bool` spelling. Never a 32-bit integer disguise.
        "bool" | "_Bool" => CType::Bool,
        // Signedness follows the spelling: plain `char` is unsigned
        // here (x86-64 System V / AAPCS64 default), `signed`/`int*_t`
        // signed variants are signed, `enum` is unsigned 32-bit.
        "char" | "unsigned char" => CType::Int {
            bits: 8,
            signed: false,
        },
        "signed char" => CType::Int {
            bits: 8,
            signed: true,
        },
        "short" | "short int" | "unsigned short" | "unsigned short int" => CType::Int {
            bits: 16,
            signed: false,
        },
        "signed short" | "signed short int" => CType::Int {
            bits: 16,
            signed: true,
        },
        "int" | "unsigned" | "unsigned int" => CType::Int {
            bits: 32,
            signed: false,
        },
        "signed" | "signed int" => CType::Int {
            bits: 32,
            signed: true,
        },
        "int8_t" => CType::Int {
            bits: 8,
            signed: true,
        },
        "uint8_t" => CType::Int {
            bits: 8,
            signed: false,
        },
        "int16_t" => CType::Int {
            bits: 16,
            signed: true,
        },
        "uint16_t" => CType::Int {
            bits: 16,
            signed: false,
        },
        "int32_t" => CType::Int {
            bits: 32,
            signed: true,
        },
        "uint32_t" => CType::Int {
            bits: 32,
            signed: false,
        },
        "uint64_t" | "size_t" | "uintptr_t" => CType::Int {
            bits: 64,
            signed: false,
        },
        "int64_t" | "intptr_t" => CType::Int {
            bits: 64,
            signed: true,
        },
        "biara_u128" | "biara_i128" | "__int128" | "unsigned __int128" => {
            return Err(format!(
                "128-bit by-value {text:?} needs aggregate ABI support"
            ));
        }
        "float complex" | "double complex" => return Err(format!("unsupported type {text:?}")),
        _ if normalized.starts_with("enum ") => CType::Int {
            bits: 32,
            signed: false,
        },
        // `long` spellings resolve by guest model; match textually first.
        _ if matches!(
            normalized.as_str(),
            "long"
                | "long int"
                | "unsigned long"
                | "unsigned long int"
                | "signed long"
                | "signed long int"
        ) =>
        {
            let signed = normalized.starts_with("signed");
            CType::Int {
                bits: long_bits,
                signed,
            }
        }
        _ if matches!(
            normalized.as_str(),
            "long long" | "unsigned long long" | "signed long long"
        ) =>
        {
            let signed = normalized.starts_with("signed");
            CType::Int { bits: 64, signed }
        }
        _ => return Err(format!("unsupported type {text:?}")),
    };
    Ok(ty)
}

/// Parse one C type spelling with LP64 `long` (tests and model-free
/// callers); guest-aware callers use [`parse_type_impl`] via
/// [`parse_signature_impl`].
fn parse_type(
    text: &str,
    structs: &BTreeMap<String, biara_proto::annotations::StructAnnotation>,
) -> Result<CType, String> {
    parse_type_impl(text, structs, false)
}

/// Parse `ret name(params)` with the guest `long` model.
fn parse_signature_impl(
    text: &str,
    structs: &BTreeMap<String, biara_proto::annotations::StructAnnotation>,
    long_is_32: bool,
) -> Result<ParsedSig, String> {
    let open = text
        .find('(')
        .ok_or_else(|| format!("signature {text:?} lacks a parameter list"))?;
    let close = text
        .rfind(')')
        .ok_or_else(|| format!("signature {text:?} lacks a parameter list"))?;
    if close < open {
        return Err(format!("signature {text:?} lacks a parameter list"));
    }
    let head = text[..open].trim();
    let params_text = text[open + 1..close].trim();
    if head.is_empty() {
        return Err(format!("signature {text:?} lacks a return type"));
    }
    if !text[close + 1..].trim().is_empty() {
        return Err(format!("signature {text:?} has trailing tokens"));
    }
    // Head is `<ret> <name>`; the name is display-only here. Only `*`
    // characters between the return spelling and the name belong to the
    // return type: split at the last whitespace, then count trailing
    // stars on the return side plus leading stars on the name side.
    let split = head.rfind([' ', '\t']).map(|i| i + 1).unwrap_or(0);
    let (ret_side, name_side) = head.split_at(split);
    let name_core = name_side.trim_start_matches('*').trim();
    if name_core.is_empty() || name_core.contains(char::is_whitespace) || name_core.contains('*') {
        return Err(format!("signature {text:?} lacks a function name"));
    }
    let ret_stars = ret_side.trim_end().len() - ret_side.trim_end().trim_end_matches('*').len()
        + (name_side.len() - name_side.trim_start_matches('*').len());
    let mut ret_spelling = ret_side.trim().trim_end_matches('*').trim().to_owned();
    for _ in 0..ret_stars {
        ret_spelling.push('*');
    }
    if ret_spelling.trim().is_empty() {
        return Err(format!("signature {text:?} lacks a return type"));
    }
    let ret = parse_type_impl(&ret_spelling, structs, long_is_32)?;
    if params_text.is_empty() {
        return Err(format!(
            "signature {text:?} lacks a parameter list (use (void) for no parameters)"
        ));
    }
    if params_text == "void" {
        return Ok(ParsedSig {
            ret,
            params: Vec::new(),
            variadic: false,
        });
    }
    let mut params = Vec::new();
    let mut variadic = false;
    for part in split_top_level(params_text) {
        if part.trim() == "..." {
            variadic = true;
            continue;
        }
        if variadic {
            return Err(format!("signature {text:?} has parameters after ..."));
        }
        if part.trim().is_empty() {
            return Err(format!("signature {text:?} has an empty parameter"));
        }
        let ty = parse_type_impl(&part, structs, long_is_32)?;
        if ty == CType::Void {
            return Err(format!("signature {text:?} has a void parameter"));
        }
        params.push(ty);
    }
    Ok(ParsedSig {
        ret,
        params,
        variadic,
    })
}

/// Parse `ret name(params)` with LP64 `long` (tests and model-free
/// callers); guest-aware callers thread `cfg.os` through
/// [`parse_signature_impl`] in [`apply_abi_annotations`].
fn parse_signature(
    text: &str,
    structs: &BTreeMap<String, biara_proto::annotations::StructAnnotation>,
) -> Result<ParsedSig, String> {
    parse_signature_impl(text, structs, false)
}

/// Merge annotations into the recovered ABI map.
///
/// Names are applied at lift/render time, not here. Each explicit
/// signature selects ABI lane kinds for the slots the convention already
/// assigns positionally: integer parameters keep their integer lanes,
/// pointer parameters become pointer lanes, `float`/`double` parameters
/// require the matching established FP lane (conflicting or absent lane
/// evidence is a loud conflict, never a quiet downgrade), `_Bool`
/// parameters become `i1` lanes, and `void` returns drop recovered
/// results. Pointer results become the convention's first integer result
/// lane carrying a pointer. Declarations are authoritative for valid ABI
/// locations (including unused formals at valid slots and standard
/// spilled stack scalars via existing stack-arg support); they never
/// invent frame facts. Argument and result lanes record into separate
/// explicit sets. The declared parameter order is preserved in
/// `explicit_order_*` so the lifter emits interleaved LLVM formals.
pub fn apply_abi_annotations(
    cfg: &Cfg,
    info: &ContextInfo,
    abis: &mut BTreeMap<u64, FunctionAbi>,
    annotations: &Annotations,
) -> Result<(), Error> {
    annotations
        .validate()
        .map_err(|e| Error::Llvm(e.to_string()))?;
    let long_is_32 = long_is_32(cfg);
    for (&address, function) in &annotations.functions {
        let Some(spelling) = function.signature.as_deref() else {
            continue;
        };
        let Some(abi) = abis.get_mut(&address) else {
            continue;
        };
        let parsed =
            parse_signature_impl(spelling, &annotations.structs, long_is_32).map_err(|detail| {
                Error::Unsupported {
                    pc: address,
                    what: format!("explicit signature {spelling:?}: {detail}"),
                }
            })?;
        if parsed.variadic {
            return Err(Error::Unsupported {
                pc: address,
                what: format!(
                    "explicit signature {spelling:?}: variadic ABI support is not implemented"
                ),
            });
        }
        apply_signature(cfg, info, address, abi, &parsed, spelling)?;
    }
    Ok(())
}

/// Positional lane assignment for one parsed signature.
fn apply_signature(
    cfg: &Cfg,
    info: &ContextInfo,
    address: u64,
    abi: &mut FunctionAbi,
    parsed: &ParsedSig,
    spelling: &str,
) -> Result<(), Error> {
    let unsupported = |detail: String| Error::Unsupported {
        pc: address,
        what: format!("explicit signature {spelling:?}: {detail}"),
    };
    let spec = cfg.spec(&info.arch).map_err(crate::Error::from)?;
    let shared_sequence = spec.unknown_call.home != 0;
    // Register ids for the convention's integer lanes, in order.
    let mut int_lanes: Vec<u32> = Vec::new();
    for name in spec.unknown_call.args {
        let Some(position) = info
            .globals
            .iter()
            .position(|g| g.name.as_deref() == Some(name))
        else {
            return Err(unsupported(format!(
                "convention register {name} is missing"
            )));
        };
        int_lanes.push(position as u32);
    }
    // SysV/AAPCS64 number FP slots separately; Win64 (`home != 0`) shares
    // one position sequence across integer and FP arguments: the k-th
    // declared parameter fills position k regardless of kind, so integer
    // positions advance past float parameters.
    let fp_capacity: usize = spec
        .unknown_call
        .fp_args
        .iter()
        .map(|t| t.count as usize)
        .sum::<usize>();
    // Standard stack spill: first stack-argument offset above the return
    // address / home space. SysV pushes the return address (8); Win64
    // reserves 32 bytes of home space above it (40); AAPCS64 links the
    // return (offset 0).
    let stack_base: i64 = match cfg.os {
        "windows" => 40,
        _ if info.arch == "aarch64" => 0,
        _ => 8,
    };
    let stack_width: i64 = 8;
    if parsed.params.len() > int_lanes.len() + fp_capacity + 32 {
        return Err(unsupported(format!(
            "too many parameters ({} > convention slots)",
            parsed.params.len(),
        )));
    }
    // Lowest unclaimed stack offset: past recovered stack args (which keep
    // their offsets) so declared spills never collide with them.
    let mut next_stack: i64 = abi
        .stack_args
        .last()
        .copied()
        .map_or(stack_base, |m| m + stack_width);
    next_stack = next_stack.max(stack_base);
    next_stack = ((next_stack + stack_width - 1) / stack_width) * stack_width;
    let mut int_cursor = 0usize;
    let mut float_cursor = 0u32;
    let mut order_lanes: Vec<u32> = Vec::new();
    let mut order_stack: Vec<i64> = Vec::new();
    let mut order_spellings: Vec<String> = Vec::new();
    for (index, param) in parsed.params.iter().enumerate() {
        let int_slot = if shared_sequence { index } else { int_cursor };
        let tag = || format!("parameter {}", index + 1);
        let push_order = |lanes: &mut Vec<u32>,
                          stacks: &mut Vec<i64>,
                          spellings: &mut Vec<String>,
                          lane: u32,
                          stack: i64,
                          spelling: String| {
            lanes.push(lane);
            stacks.push(stack);
            spellings.push(spelling);
        };
        match param {
            CType::Int { bits, signed } => {
                if int_slot < int_lanes.len() {
                    let lane = int_lanes[int_slot];
                    int_cursor += 1;
                    // Authoritative for valid slots: unused lanes are kept.
                    abi.args.insert(lane);
                    match bits {
                        8 => {
                            abi.explicit_narrow_args.insert(lane, 8);
                        }
                        16 => {
                            abi.explicit_narrow_args.insert(lane, 16);
                        }
                        32 | 64 => {
                            abi.explicit_narrow_args.remove(&lane);
                        }
                        _ => {
                            return Err(unsupported(format!("{}: bad integer width {bits}", tag())));
                        }
                    }
                    if *signed {
                        abi.explicit_signed_args.insert(lane);
                    } else {
                        abi.explicit_signed_args.remove(&lane);
                    }
                    abi.explicit_bool_args.remove(&lane);
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        lane,
                        0,
                        param.spelling(),
                    );
                } else {
                    // Spill past the register file: standard stack slot.
                    let off = next_stack;
                    next_stack += stack_width;
                    abi.stack_args.insert(off);
                    match bits {
                        8 | 16 | 32 => {
                            abi.explicit_stack_narrow.insert(off, *bits);
                        }
                        64 => {
                            abi.explicit_stack_narrow.remove(&off);
                        }
                        _ => {
                            return Err(unsupported(format!("{}: bad integer width {bits}", tag())));
                        }
                    }
                    if *signed {
                        abi.explicit_stack_signed.insert(off);
                    } else {
                        abi.explicit_stack_signed.remove(&off);
                    }
                    abi.explicit_stack_bool.remove(&off);
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        u32::MAX,
                        off,
                        param.spelling(),
                    );
                }
            }
            CType::Bool => {
                if int_slot < int_lanes.len() {
                    let lane = int_lanes[int_slot];
                    int_cursor += 1;
                    abi.args.insert(lane);
                    abi.explicit_bool_args.insert(lane);
                    abi.explicit_narrow_args.remove(&lane);
                    abi.explicit_signed_args.remove(&lane);
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        lane,
                        0,
                        param.spelling(),
                    );
                } else {
                    let off = next_stack;
                    next_stack += stack_width;
                    abi.stack_args.insert(off);
                    abi.explicit_stack_bool.insert(off);
                    abi.explicit_stack_narrow.remove(&off);
                    abi.explicit_stack_signed.remove(&off);
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        u32::MAX,
                        off,
                        param.spelling(),
                    );
                }
            }
            CType::Ptr {
                pointee_struct,
                spelling,
                ..
            } => {
                if int_slot < int_lanes.len() {
                    let lane = int_lanes[int_slot];
                    int_cursor += 1;
                    abi.args.insert(lane);
                    abi.explicit_ptr_args.insert(lane);
                    abi.explicit_narrow_args.remove(&lane);
                    abi.explicit_signed_args.remove(&lane);
                    abi.explicit_bool_args.remove(&lane);
                    if let Some(name) = pointee_struct {
                        abi.explicit_struct_args.insert(lane, name.clone());
                    } else {
                        abi.explicit_struct_args.remove(&lane);
                    }
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        lane,
                        0,
                        spelling.clone(),
                    );
                } else {
                    let off = next_stack;
                    next_stack += stack_width;
                    abi.stack_args.insert(off);
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        u32::MAX,
                        off,
                        spelling.clone(),
                    );
                }
            }
            CType::Float32 | CType::Float64 => {
                let want = if matches!(param, CType::Float32) {
                    LaneType::Float32
                } else {
                    LaneType::Float64
                };
                if shared_sequence {
                    // Win64 shared slots: the k-th declared parameter fills
                    // position k; integer positions advance past FP params.
                    let position = index;
                    if position >= int_lanes.len() {
                        return Err(unsupported(format!("{}: no convention slot", tag())));
                    }
                    float_lane(spec, position as u32).ok_or_else(|| {
                        unsupported(format!("{}: no convention float lane", tag()))
                    })?;
                    abi.fp_args.insert(position as u32);
                    abi.fp_arg_types.insert(position as u32, want);
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        u32::MAX - 1,
                        position as i64,
                        param.spelling(),
                    );
                } else {
                    let lane = float_lane(spec, float_cursor).ok_or_else(|| {
                        unsupported(format!("{}: no convention float lane", tag()))
                    })?;
                    float_cursor += 1;
                    // Authoritative: establish the declared lane even when
                    // recovery saw only raw bits there.
                    if abi.fp_conflicts.contains(&lane) {
                        return Err(unsupported(format!(
                            "{}: conflicting float lane evidence",
                            tag()
                        )));
                    }
                    match abi.fp_arg_types.get(&lane) {
                        Some(other) if *other != want => {
                            return Err(unsupported(format!(
                                "{}: declared float conflicts with recovered {other:?} lane",
                                tag()
                            )));
                        }
                        _ => {
                            abi.fp_args.insert(lane);
                            abi.fp_arg_types.insert(lane, want);
                        }
                    }
                    push_order(
                        &mut order_lanes,
                        &mut order_stack,
                        &mut order_spellings,
                        u32::MAX - 2,
                        lane as i64,
                        param.spelling(),
                    );
                }
            }
            CType::Void => return Err(unsupported("void parameter".into())),
        }
    }
    abi.explicit_order_lanes = order_lanes;
    abi.explicit_order_stack = order_stack;
    abi.explicit_order_spellings = order_spellings;
    // Return: `void` drops results; integer/pointer/bool returns keep the
    // first result lane; float returns need the matching lane. Result
    // lanes record into the separate `*_rets` sets: an AAPCS64 `x0`
    // argument declaration never aliases the result declaration.
    match &parsed.ret {
        CType::Void => {
            abi.returns.clear();
            abi.fp_returns.clear();
            abi.fp_ret_types.clear();
            abi.ret_class = None;
            abi.explicit_return_spelling = "void".to_owned();
        }
        CType::Int { bits, signed } => {
            if abi.returns.is_empty() && abi.fp_returns.is_empty() {
                // Authoritative: claim the convention's first integer
                // result lane when recovery found no result.
                let first_result = spec.unknown_call.results.first().and_then(|name| {
                    info.globals
                        .iter()
                        .position(|g| g.name.as_deref() == Some(*name))
                        .map(|p| p as u32)
                });
                if let Some(lane) = first_result {
                    abi.returns.insert(lane);
                } else {
                    return Err(unsupported(
                        "declared a result the recovery found nowhere".into(),
                    ));
                }
            }
            if !abi.returns.is_empty() {
                let first = *abi.returns.iter().next().unwrap();
                match bits {
                    8 => {
                        abi.explicit_narrow_rets.insert(first, 8);
                    }
                    16 => {
                        abi.explicit_narrow_rets.insert(first, 16);
                    }
                    32 | 64 => {
                        abi.explicit_narrow_rets.remove(&first);
                    }
                    _ => return Err(unsupported(format!("bad integer result width {bits}"))),
                }
                if *signed {
                    abi.explicit_signed_rets.insert(first);
                } else {
                    abi.explicit_signed_rets.remove(&first);
                }
                abi.explicit_bool_rets.remove(&first);
                abi.explicit_ptr_rets.remove(&first);
            }
            abi.explicit_return_spelling = parsed.ret.spelling();
        }
        CType::Bool => {
            if abi.returns.is_empty() && abi.fp_returns.is_empty() {
                let first_result = spec.unknown_call.results.first().and_then(|name| {
                    info.globals
                        .iter()
                        .position(|g| g.name.as_deref() == Some(*name))
                        .map(|p| p as u32)
                });
                if let Some(lane) = first_result {
                    abi.returns.insert(lane);
                } else {
                    return Err(unsupported(
                        "declared a result the recovery found nowhere".into(),
                    ));
                }
            }
            if !abi.returns.is_empty() {
                let first = *abi.returns.iter().next().unwrap();
                abi.explicit_bool_rets.insert(first);
                abi.explicit_narrow_rets.remove(&first);
                abi.explicit_signed_rets.remove(&first);
                abi.explicit_ptr_rets.remove(&first);
            }
            abi.explicit_return_spelling = "_Bool".to_owned();
        }
        CType::Ptr {
            pointee_struct,
            spelling,
            ..
        } => {
            if abi.returns.is_empty() {
                let first_result = spec.unknown_call.results.first().and_then(|name| {
                    info.globals
                        .iter()
                        .position(|g| g.name.as_deref() == Some(*name))
                        .map(|p| p as u32)
                });
                if let Some(lane) = first_result {
                    abi.returns.insert(lane);
                } else {
                    return Err(unsupported(
                        "declared a pointer result the recovery found nowhere".into(),
                    ));
                }
            }
            let first = *abi.returns.iter().next().unwrap();
            abi.explicit_ptr_rets.insert(first);
            abi.explicit_narrow_rets.remove(&first);
            abi.explicit_signed_rets.remove(&first);
            abi.explicit_bool_rets.remove(&first);
            if let Some(name) = pointee_struct {
                abi.explicit_struct_rets.insert(first, name.clone());
            } else {
                abi.explicit_struct_rets.remove(&first);
            }
            abi.ret_class = None;
            abi.explicit_return_spelling = spelling.clone();
        }
        CType::Float32 => {
            if !abi.fp_returns.contains(&0) {
                abi.fp_returns.insert(0);
            }
            match abi.fp_ret_types.get(&0) {
                Some(LaneType::Float32) | None => {
                    abi.fp_ret_types.insert(0, LaneType::Float32);
                }
                Some(other) => {
                    return Err(unsupported(format!(
                        "float result conflicts with recovered {other:?} lane"
                    )));
                }
            }
            abi.explicit_return_spelling = "float".to_owned();
        }
        CType::Float64 => {
            if !abi.fp_returns.contains(&0) {
                abi.fp_returns.insert(0);
            }
            match abi.fp_ret_types.get(&0) {
                Some(LaneType::Float64) | None => {
                    abi.fp_ret_types.insert(0, LaneType::Float64);
                }
                Some(other) => {
                    return Err(unsupported(format!(
                        "double result conflicts with recovered {other:?} lane"
                    )));
                }
            }
            abi.explicit_return_spelling = "double".to_owned();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn structs() -> BTreeMap<String, biara_proto::annotations::StructAnnotation> {
        BTreeMap::new()
    }

    #[test]
    fn signedness_long_bool_and_double_map_faithfully() {
        // Signedness is preserved separately from transport: int16_t is
        // signed, uint16_t is not; the LLVM slot stays sign-agnostic.
        let parsed = parse_signature("uint64_t renamed(uint64_t x)", &structs()).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 64,
                signed: false
            }
        );
        assert_eq!(
            parsed.params,
            vec![CType::Int {
                bits: 64,
                signed: false
            }]
        );
        let parsed = parse_signature("uint8_t narrow8(uint8_t v)", &structs()).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 8,
                signed: false
            }
        );
        assert_eq!(
            parsed.params,
            vec![CType::Int {
                bits: 8,
                signed: false
            }]
        );
        let parsed = parse_signature("int16_t narrow16(int16_t v)", &structs()).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 16,
                signed: true
            }
        );
        assert_eq!(
            parsed.params,
            vec![CType::Int {
                bits: 16,
                signed: true
            }]
        );
        assert_eq!(parsed.ret.spelling(), "int16_t");
        // `double` parses (the old grammar silently dropped it from the
        // match); `bool` is a real boolean, never a 32-bit integer.
        let parsed = parse_signature("double mixed(uint64_t a, double b)", &structs()).unwrap();
        assert_eq!(parsed.ret, CType::Float64);
        assert_eq!(parsed.params[1], CType::Float64);
        let parsed = parse_signature("_Bool flag(_Bool v)", &structs()).unwrap();
        assert_eq!(parsed.ret, CType::Bool);
        assert_eq!(parsed.params, vec![CType::Bool]);
        assert_eq!(parsed.ret.spelling(), "_Bool");
        // Guest data model: `long` is 32 bits on LLP64, 64 on LP64.
        let parsed = parse_signature_impl("long f(long x)", &structs(), true).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 32,
                signed: false
            }
        );
        let parsed = parse_signature_impl("long f(long x)", &structs(), false).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 64,
                signed: false
            }
        );
        let parsed =
            parse_signature_impl("unsigned long f(unsigned long x)", &structs(), true).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 32,
                signed: false
            }
        );
    }

    #[test]
    fn signature_head_with_scalar_return_is_not_a_pointer() {
        // Regression: the old head split counted whitespace as stars, so
        // `uint64_t renamed(...)` parsed as a pointer return.
        let parsed = parse_signature("uint64_t renamed(uint64_t x)", &structs()).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 64,
                signed: false
            }
        );
        assert_eq!(
            parsed.params,
            vec![CType::Int {
                bits: 64,
                signed: false
            }]
        );
        let parsed = parse_signature("uint8_t narrow8(uint8_t v)", &structs()).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 8,
                signed: false
            }
        );
        assert_eq!(
            parsed.params,
            vec![CType::Int {
                bits: 8,
                signed: false
            }]
        );
        let parsed = parse_signature("int16_t narrow16(int16_t v)", &structs()).unwrap();
        assert_eq!(
            parsed.ret,
            CType::Int {
                bits: 16,
                signed: true
            }
        );
        assert_eq!(
            parsed.params,
            vec![CType::Int {
                bits: 16,
                signed: true
            }]
        );
    }

    #[test]
    fn signature_pointer_star_binds_to_return() {
        let parsed = parse_signature(
            "struct Header *inspect(struct Header *h)",
            &BTreeMap::from([(
                "Header".to_owned(),
                biara_proto::annotations::StructAnnotation { fields: Vec::new() },
            )]),
        )
        .unwrap();
        assert!(matches!(
            parsed.ret,
            CType::Ptr {
                depth: 1,
                pointee_struct: Some(_),
                ..
            }
        ));
        assert_eq!(parsed.ret.spelling(), "struct Header *");
        // `()` is not a parameter list: callers must spell `(void)`.
        assert!(parse_signature("void f()", &structs()).is_err());
        assert!(parse_signature("void f(void)", &structs()).is_ok());
        // `void` parameters and 128-bit scalars are loud errors.
        assert!(parse_signature("int f(void x)", &structs()).is_err());
        assert!(parse_signature("biara_u128 f(biara_u128 x)", &structs()).is_err());
        // Function pointers are unsupported, never silently a pointer.
        assert!(parse_signature("int f(int (*cb)(int))", &structs()).is_err());
    }

    #[test]
    fn substitute_rejects_hostile_tokens() {
        use biara_proto::tokens::{SymbolRef, Token, substitute};
        let body = "ab cd";
        let good = vec![
            Token {
                start: 0,
                end: 2,
                kind: "identifier".into(),
                symbol: Some(SymbolRef::Function { address: 1 }),
            },
            Token {
                start: 2,
                end: 3,
                kind: "whitespace".into(),
                symbol: None,
            },
            Token {
                start: 3,
                end: 5,
                kind: "identifier".into(),
                symbol: None,
            },
        ];
        let renames = BTreeMap::from([(SymbolRef::Function { address: 1 }, "z".to_owned())]);
        assert_eq!(substitute(body, &good, &renames).unwrap(), "z cd");
        // Overlap, out-of-range, and character splits are errors.
        let overlap = vec![
            Token {
                start: 0,
                end: 2,
                kind: "identifier".into(),
                symbol: None,
            },
            Token {
                start: 1,
                end: 2,
                kind: "identifier".into(),
                symbol: None,
            },
        ];
        assert!(substitute(body, &overlap, &renames).is_err());
        let oob = vec![Token {
            start: 0,
            end: 9,
            kind: "identifier".into(),
            symbol: None,
        }];
        assert!(substitute(body, &oob, &renames).is_err());
        let body = "aé";
        let split = vec![Token {
            start: 0,
            end: 2,
            kind: "identifier".into(),
            symbol: None,
        }];
        assert!(substitute(body, &split, &BTreeMap::new()).is_err());
    }
}
