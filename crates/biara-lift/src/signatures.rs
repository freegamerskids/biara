//! Owned typed function summaries over the ABI-form LLVM module.
//!
//! A [`FuncSig`] is the reusable typed spelling of one lifted function's
//! ABI-form signature: one [`AbiTy`] per LLVM parameter in order, and an
//! [`AbiResult`] for the return. Types come from the LLVM IR itself
//! (float/double/vector/pointer/integer parameter and return types the ABI
//! form already lowered). Nothing is guessed from bitcasts: the ABI form
//! only lowers a slot to float/vector on established lane evidence, so the
//! IR spelling summarizes directly here.
//!
//! Pointer-carrying values stay integer/pointer at the ABI boundary (never
//! an fp bitcast), so layout recovery's `isIntegerTy(64)`/`isPointerTy`
//! roots keep working. Layout ids are layout-analysis `SharedLayout`
//! indices assigned there; this module only references them. Unknown and
//! conflicting representations stay explicit.
//!
//! [`summarize`] reads one transformed module plus its layout facts and
//! returns one owned [`FuncSig`] per `!biara.entry`-carrying function, in
//! deterministic module order. Results are owned serde data: no LLVM
//! references escape.

use inkwell::{
    module::Module,
    types::{AnyType, AnyTypeEnum},
    values::AsValueRef,
};

unsafe extern "C" {
    fn biara_layouts_entry(function: *mut std::ffi::c_void, entry: *mut u64) -> std::ffi::c_int;
    fn biara_layouts_u32_metadata(
        function: *mut std::ffi::c_void,
        key: *const std::ffi::c_char,
        index: u32,
        value: *mut u32,
    ) -> std::ffi::c_int;
}

/// How a typed summary result travels back to the caller.
///
/// Describes executable ABI transport, not an asserted source aggregate.
/// Tuple members are recovered result slots; a memory result has a
/// caller-provided address. Distinct from `biara_cfg::ReturnClass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RetClass {
    /// One scalar result value.
    Direct,
    /// A small aggregate returned as a two-element struct value.
    Pair,
    /// More than two recovered result slots, without inventing a source type.
    Registers,
    /// A larger aggregate through a caller-provided pointer parameter.
    Memory,
}

/// One ABI parameter or return-slot type.
///
/// Selected from evidence only: the LLVM IR type at that position, refined
/// by per-lane float/vector facts where established. Integer-carried
/// bit patterns stay [`AbiTy::RawWord`]; disagreements stay
/// [`AbiTy::Conflict`]. Pointer slots may reference a layout analysis
/// `SharedLayout` id (assigned there, only referenced here).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AbiTy {
    /// 32-bit integer slot (raw words, addresses as integers).
    I32,
    /// 64-bit integer slot (raw words, addresses as integers).
    I64,
    /// `float`: established by `Float32` lane evidence on an `f32` IR value.
    F32,
    /// `double`: established by `Float64` lane evidence on an `f64` IR value.
    F64,
    /// 128-bit vector: established by `Vector128` lane evidence on a
    /// 128-bit vector IR value (`<4 x float>` lowering).
    Vec128,
    /// Pointer-carrying slot. The layout id is a [`LayoutFacts`]
    /// `SharedLayout` index when layout analysis bound one, else `None`
    /// (an unbound pointer, still spelled as a pointer).
    Ptr {
        /// Layout analysis `SharedLayout` id, when bound.
        layout: Option<u32>,
    },
    /// Hidden-`sret` pointer parameter (a [`RetClass::Memory`] result's
    /// address slot): a pointer, never a value read.
    HiddenSret,
    /// Integer-carried value with no established float/vector/pointer type:
    /// the executable raw-word signature. Bit-pattern float traffic without
    /// lane evidence stays here, never guessed into `F32`/`F64`.
    RawWord,
    /// Conflicting evidence (float on one path, raw bits or another width
    /// on another): consumers must keep the raw word, never pick a side.
    Conflict,
}

/// A typed ABI result, preserving every recovered result slot.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AbiResult {
    /// `void`.
    Void,
    /// One result slot.
    One(AbiTy),
    /// A small aggregate across two result slots (both typed).
    Pair(AbiTy, AbiTy),
    /// More than two result slots in executable LLVM aggregate order.
    Slots(Vec<AbiTy>),
}

/// Owned typed summary of one ABI-form function.
///
/// `params` follows the LLVM parameter order (including any hidden-`sret`
/// pointer and stack slots): position `i` describes LLVM parameter `i`.
/// `function` is the guest entry address (`!biara.entry`); `name` is the
/// LLVM function name. `conflicts` names parameter positions kept raw by
/// conflicting evidence. Pointer slots reference layout ids owned by the
/// layout analysis.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuncSig {
    /// Guest entry address.
    pub function: u64,
    /// LLVM function name.
    pub name: String,
    /// One type per LLVM parameter, in order.
    pub params: Vec<AbiTy>,
    /// Typed result.
    pub result: AbiResult,
    /// How the result travels.
    pub ret_class: RetClass,
    /// Parameter positions kept raw by conflicting evidence.
    pub conflicts: Vec<u32>,
}

/// Summarize every `!biara.entry`-carrying function of `module`.
///
/// `layouts` supplies argument binding order and `SharedLayout` ids for
/// pointer-carrying slots; LLVM IR types supply the executable spelling.
/// Returns one [`FuncSig`] per entry function in deterministic module
/// order. Functions without entries (dispatchers, imports, helpers) are
/// skipped. Never guesses: unestablished slots become [`AbiTy::RawWord`],
/// disagreements become [`AbiTy::Conflict`].
pub fn summarize(
    module: &Module<'_>,
    layouts: &crate::layouts::LayoutFacts,
) -> Result<Vec<FuncSig>, crate::Error> {
    let mut out = Vec::new();
    for f in module.get_functions() {
        if f.count_basic_blocks() == 0 {
            continue;
        }
        let mut entry = 0;
        if unsafe { biara_layouts_entry(f.as_value_ref().cast(), &mut entry) } == 0 {
            continue;
        };
        let params: Vec<AbiTy> = f
            .get_params()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                evidence_ty(
                    param_ty(p.get_type().as_any_type_enum(), entry, i as u32, layouts),
                    abi_metadata(f, c"biara.abi.args", i as u32),
                )
            })
            .collect();
        let conflicts: Vec<u32> = params
            .iter()
            .enumerate()
            .filter(|(_, t)| matches!(t, AbiTy::Conflict))
            .map(|(i, _)| i as u32)
            .collect();
        let (mut result, mut ret_class) = f
            .get_type()
            .get_return_type()
            .map_or((AbiResult::Void, RetClass::Direct), result_ty);
        let result_slot = |ty, i| evidence_ty(ty, abi_metadata(f, c"biara.abi.rets", i));
        result = match result {
            AbiResult::Void => AbiResult::Void,
            AbiResult::One(ty) => AbiResult::One(result_slot(ty, 0)),
            AbiResult::Pair(a, b) => AbiResult::Pair(result_slot(a, 0), result_slot(b, 1)),
            AbiResult::Slots(slots) => AbiResult::Slots(
                slots
                    .into_iter()
                    .enumerate()
                    .map(|(i, ty)| result_slot(ty, i as u32))
                    .collect(),
            ),
        };
        if abi_metadata(f, c"biara.abi.ret_class", 0) == Some(2) {
            ret_class = RetClass::Memory;
        }
        if matches!(result, AbiResult::One(AbiTy::I64 | AbiTy::Ptr { .. }))
            && let Some(layout) = layouts
                .returns
                .iter()
                .find(|r| r.function == entry)
                .and_then(|r| r.layout)
        {
            result = AbiResult::One(AbiTy::Ptr {
                layout: Some(layout),
            });
        }
        out.push(FuncSig {
            function: entry,
            name: f.get_name().to_string_lossy().into_owned(),
            params,
            result,
            ret_class,
            conflicts,
        });
    }
    Ok(out)
}
fn abi_metadata(
    function: inkwell::values::FunctionValue<'_>,
    key: &std::ffi::CStr,
    index: u32,
) -> Option<u32> {
    let mut value = 0;
    (unsafe {
        biara_layouts_u32_metadata(
            function.as_value_ref().cast(),
            key.as_ptr(),
            index,
            &mut value,
        )
    } != 0)
        .then_some(value)
}

// These kinds describe transport evidence; no numeric cast changes the value.
fn evidence_ty(ty: AbiTy, kind: Option<u32>) -> AbiTy {
    match kind {
        Some(6) => AbiTy::HiddenSret,
        Some(7) => AbiTy::RawWord,
        Some(8) => AbiTy::Conflict,
        _ => ty,
    }
}

/// ABI type of LLVM parameter `i` of `entry`: the IR type spelled directly,
/// refined by layout bindings (pointer slots).
///
/// The IR is authoritative for the executable spelling: `float`/`double`/
/// vector/pointer/integer map to their [`AbiTy`]. The ABI form only lowers
/// a slot to float/vector when lane evidence established it, so valid
/// typed IR summarizes directly (no guessing, and no downgrade of real
/// float IR either way). Integer/pointer values carrying layout-bound
/// pointers become [`AbiTy::Ptr`]; layout ids come from `layouts`
/// argument bindings.
fn param_ty(
    ty: AnyTypeEnum<'_>,
    entry: u64,
    i: u32,
    layouts: &crate::layouts::LayoutFacts,
) -> AbiTy {
    let layout = layout_of(layouts, entry, i);
    match ty {
        // Both `float` and `double` are `FloatType` in LLVM inkwell; the
        // bit width selects the spelling. Valid typed IR is authoritative
        // here: summarize it directly (no lane-guessing downgrade of real
        // float IR to `RawWord`, and no bitcast guessing either way).
        AnyTypeEnum::FloatType(t) => match t.get_bit_width() {
            32 => AbiTy::F32,
            64 => AbiTy::F64,
            _ => AbiTy::RawWord,
        },
        AnyTypeEnum::VectorType(v) => {
            // `<4 x float>` is the vector128 lowering; other widths stay
            // raw words rather than guessed vectors.
            if v.get_size() == 4
                && matches!(v.get_element_type(), inkwell::types::BasicTypeEnum::FloatType(f) if f.get_bit_width() == 32)
            {
                AbiTy::Vec128
            } else {
                AbiTy::RawWord
            }
        }
        AnyTypeEnum::PointerType(_) => AbiTy::Ptr { layout },
        AnyTypeEnum::IntType(t) => match t.get_bit_width() {
            32 => AbiTy::I32,
            64 => {
                if layout.is_some() {
                    AbiTy::Ptr { layout }
                } else {
                    AbiTy::I64
                }
            }
            _ => AbiTy::RawWord,
        },
        _ => AbiTy::RawWord,
    }
}

/// Preserve the executable result type, including all register-tuple fields.
fn result_ty(ty: inkwell::types::BasicTypeEnum<'_>) -> (AbiResult, RetClass) {
    if let inkwell::types::BasicTypeEnum::StructType(s) = ty {
        let field = |i| {
            s.get_field_type_at_index(i)
                .map_or(AbiTy::RawWord, |ty| field_ty(ty.as_any_type_enum()))
        };
        return if s.count_fields() == 2 {
            (AbiResult::Pair(field(0), field(1)), RetClass::Pair)
        } else {
            (
                AbiResult::Slots((0..s.count_fields()).map(field).collect()),
                RetClass::Registers,
            )
        };
    }
    (
        AbiResult::One(field_ty(ty.as_any_type_enum())),
        RetClass::Direct,
    )
}

/// One aggregate field's type: integers stay raw words here (pair members
/// are register facts, not lane-typed floats); pointers keep pointer form.
fn field_ty(ty: AnyTypeEnum<'_>) -> AbiTy {
    match ty {
        AnyTypeEnum::IntType(t) if t.get_bit_width() == 64 => AbiTy::I64,
        AnyTypeEnum::IntType(t) if t.get_bit_width() == 32 => AbiTy::I32,
        AnyTypeEnum::PointerType(_) => AbiTy::Ptr { layout: None },
        AnyTypeEnum::FloatType(t) if t.get_bit_width() == 32 => AbiTy::F32,
        AnyTypeEnum::FloatType(t) if t.get_bit_width() == 64 => AbiTy::F64,
        AnyTypeEnum::VectorType(v)
            if v.get_size() == 4
                && matches!(v.get_element_type(), inkwell::types::BasicTypeEnum::FloatType(f) if f.get_bit_width() == 32) =>
        {
            AbiTy::Vec128
        }
        _ => AbiTy::RawWord,
    }
}

/// Layout-bound `SharedLayout` id for argument `i` of `entry`, if the
/// layout analysis bound that argument to a layout.
fn layout_of(layouts: &crate::layouts::LayoutFacts, entry: u64, i: u32) -> Option<u32> {
    layouts
        .args
        .iter()
        .find(|a| a.function == entry && a.arg == i)
        .and_then(|a| a.layout)
}
