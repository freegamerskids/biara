//! Reusable interprocedural layout facts, extracted from the C renderer.
//!
//! The native analysis (`cpp/layouts.h`, `cpp/layouts.cpp`, formerly the
//! renderer-local `Types` in `cpp/cgen.cpp`) runs once per transformed
//! module and is cached in `TransformedC` ahead of the LLVM module. The C
//! renderer consumes that same cached analysis; it establishes no second
//! type convention. [`TransformedC::layout_facts`](crate::TransformedC::layout_facts)
//! returns these owned facts, and `--emit types` serializes them.
//!
//! What the facts mean (consumers rely on this; keep it):
//! - Observed access shapes only. [`SharedLayout::size`] is the accessed
//!   extent (last field end), never a declared object bound: audit object
//!   bounds must not consume it.
//! - Pointer classes deliberately do not meet across calls. Cross-call
//!   propagation is directional and context-sensitive (offset-aware
//!   actual-to-formal constraints for arguments, returns, and pointer
//!   fields, bounded fixpoint), so a generic callee called with unrelated
//!   objects keeps separate layouts while one object observed through two
//!   callees accumulates combined reusable fields under one shared struct.
//! - Overlapping incompatible accesses are explicit [`LayoutConflict`]
//!   facts; the renderer leaves those to casts, never asserted types.
//! - [`FactStatus`] and [`LayoutLimits`] report every materially dropped
//!   fact (field-offset cap, unsupported/nonconstant address relationships,
//!   overflowing offset translation, fixpoint truncation): a `Complete`
//!   status is never claimed when evidence was discarded.
//! - Layout ids are 0-based indices into [`LayoutFacts::layouts`], assigned
//!   in deterministic emission order (by struct name). Attaching debug
//!   names renames display fields only; ids, sizes, offsets, and bindings
//!   never move. `ArgLayout.arg` is the LLVM parameter index (position `i`
//!   describes LLVM parameter `i`, including any hidden-sret pointer and
//!   stack slots); `function` is the guest entry address.
//!
//! `Handle` is a private RAII wrapper around the opaque native analysis:
//! build once per module (CPU offsets arrive env-relative; the margin is
//! added here, matching the renderer's `MARGIN`), apply debug metadata,
//! export facts, expose the raw pointer for the cached emitter. The native
//! side holds LLVM references, so the parent stores the `Handle` ahead of
//! the module and drops it first. Facts are small owned serde data:
//! layouts, bindings, conflicts, status, limits — no per-instruction data.

use std::{
    ffi::{CString, c_char, c_void},
    os::raw::c_int,
};

use inkwell::module::Module;

use crate::decompile::CField;

/// One observed field of a shared layout: `bytes` accessed at `off`, what
/// it points to, and its display name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayoutField {
    pub off: i64,
    pub bytes: u32,
    pub pointee: Option<u32>,
    pub name: String,
}

/// One reusable inferred layout: fields at the offsets accessed, widest
/// access wins, plus the guest entries whose evidence converged here.
/// `size` is the accessed extent, not a declared object bound.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SharedLayout {
    pub id: u32,
    pub name: String,
    pub size: u64,
    pub scalar: bool,
    pub fields: Vec<LayoutField>,
    pub functions: Vec<u64>,
}

/// An embedded struct inside a frame layout.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Embedded {
    pub off: i64,
    pub layout: u32,
}

/// One frame (stack alloca or CPU-state global) layout: scalar fields plus
/// structs embedded where a callee layout was placed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FrameLayout {
    pub function: u64,
    pub name: String,
    pub layout: String,
    pub size: u64,
    pub fields: Vec<LayoutField>,
    pub embedded: Vec<Embedded>,
}

/// Argument binding: LLVM parameter `arg` of guest entry `function` carries
/// the bound layout (`None`: no layout established), observed at `offset`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArgLayout {
    pub function: u64,
    pub arg: u32,
    pub layout: Option<u32>,
    pub offset: i64,
}

/// Return binding: every return path of guest entry `function` aliases this
/// layout (`None`: absent or incompatible layout evidence across paths).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReturnLayout {
    pub function: u64,
    pub layout: Option<u32>,
}

/// Overlapping incompatible accesses at one offset of one layout: the
/// observed widths that could not both be asserted. The renderer uses
/// casts there.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayoutConflict {
    pub layout: Option<u32>,
    pub off: i64,
    pub widths: Vec<u32>,
    pub detail: String,
}

/// Bounded-analysis status: `Complete` only when no evidence was dropped;
/// otherwise how many propagation rounds ran against their cap.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactStatus {
    Complete,
    Truncated { iterations: u32, cap: u32 },
}

/// What the bounded analysis dropped instead of asserting.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayoutLimits {
    pub iterations: u32,
    pub iteration_cap: u32,
    pub max_field_offset: i64,
    pub capped_offsets: u32,
    pub unsupported_bases: u32,
    pub overflowed_offsets: u32,
}

/// Owned reusable layout evidence for one transformed module.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LayoutFacts {
    pub status: FactStatus,
    pub layouts: Vec<SharedLayout>,
    pub frames: Vec<FrameLayout>,
    pub args: Vec<ArgLayout>,
    pub returns: Vec<ReturnLayout>,
    pub conflicts: Vec<LayoutConflict>,
    pub limits: LayoutLimits,
}

/// Analyze an ABI-form module and return module-independent layout evidence.
/// CPU fields use env-relative offsets; `margin` locates env within CPU state.
/// For repeated export/render operations, use [`crate::TransformedC`] instead,
/// which retains one cached analysis.
pub fn analyze_layouts(
    module: &Module<'_>,
    cpu: &[(i64, u32, String)],
    margin: u64,
) -> Result<LayoutFacts, crate::Error> {
    Handle::build(module, cpu, margin)?.facts()
}

unsafe extern "C" {
    fn biara_layouts_build(module: *mut c_void, cpu: *const CField, ncpu: usize) -> *mut c_void;
    fn biara_layouts_apply_debug(layouts: *mut c_void, module: *mut c_void) -> c_int;
    fn biara_layouts_json(layouts: *const c_void, write: JsonWrite, ctx: *mut c_void) -> c_int;
    fn biara_layouts_free(layouts: *mut c_void);
}

type JsonWrite = unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> c_int;

struct JsonState<'a> {
    out: &'a mut Vec<u8>,
    err: bool,
}

unsafe extern "C" fn json_cb(ctx: *mut c_void, p: *const c_char, n: usize) -> c_int {
    let state = unsafe { &mut *(ctx as *mut JsonState) };
    if state.err {
        return 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n) };
    // Never unwind across FFI: byte copies do not panic, but be explicit.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.out.extend_from_slice(bytes);
    }));
    if r.is_err() {
        state.err = true;
        return 1;
    }
    0
}

/// RAII owner of one cached native layout analysis.
///
/// Build once per transformed module; the parent stores this ahead of the
/// LLVM module so the native analysis (which holds LLVM references) drops
/// while the module stays alive. `facts` re-exports the JSON the native
/// side emits, parsed into owned [`LayoutFacts`].
pub(crate) struct Handle {
    raw: std::ptr::NonNull<c_void>,
}

impl Handle {
    /// Build and cache the layout analysis for `module`. `cpu` carries
    /// env-relative `(offset, bytes, name)` descriptors; `margin` (the
    /// renderer's `MARGIN`) is added here so native offsets match emission.
    pub(crate) fn build(
        module: &Module<'_>,
        cpu: &[(i64, u32, String)],
        margin: u64,
    ) -> Result<Self, crate::Error> {
        let cpu_names: Vec<CString> = cpu
            .iter()
            .map(|(_, _, n)| {
                CString::new(n.as_str())
                    .map_err(|_| crate::Error::Llvm("CPU field name contains NUL".into()))
            })
            .collect::<Result<_, _>>()?;
        let fields: Vec<CField> = cpu
            .iter()
            .zip(&cpu_names)
            .map(|((off, bytes, _), n)| CField {
                off: margin as i64 + off,
                bytes: *bytes,
                name: n.as_ptr(),
            })
            .collect();
        // `as_mut_ptr` borrows, not consumes: the module outlives the
        // handle by construction (parent field order).
        let raw = unsafe {
            biara_layouts_build(module.as_mut_ptr().cast(), fields.as_ptr(), fields.len())
        };
        let raw = std::ptr::NonNull::new(raw)
            .ok_or_else(|| crate::Error::Llvm("layout analysis failed".into()))?;
        Ok(Handle { raw })
    }

    /// Re-run DWARF display renames after debug metadata changed. Only
    /// display names move; ids, sizes, offsets, and bindings are stable.
    pub(crate) fn apply_debug(&mut self, module: &Module<'_>) -> Result<(), crate::Error> {
        let failed =
            unsafe { biara_layouts_apply_debug(self.raw.as_ptr(), module.as_mut_ptr().cast()) };
        if failed != 0 {
            return Err(crate::Error::Llvm("layout debug refresh failed".into()));
        }
        Ok(())
    }

    /// Export owned facts: layouts, frames, bindings, conflicts, status,
    /// and limits. Small by construction (no per-instruction data).
    pub(crate) fn facts(&self) -> Result<LayoutFacts, crate::Error> {
        let mut out = Vec::new();
        let mut state = JsonState {
            out: &mut out,
            err: false,
        };
        let failed = unsafe {
            biara_layouts_json(
                self.raw.as_ptr(),
                json_cb,
                &mut state as *mut JsonState as *mut c_void,
            )
        };
        if failed != 0 || state.err {
            return Err(crate::Error::Llvm("layout facts failed".into()));
        }
        serde_json::from_slice(&out).map_err(|e| crate::Error::Llvm(format!("layout facts: {e}")))
    }

    /// Raw handle for the cached renderer (`biara_emit_c_cached`).
    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.raw.as_ptr()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { biara_layouts_free(self.raw.as_ptr()) };
    }
}
