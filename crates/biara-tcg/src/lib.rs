//! Safe access to libtcg: QEMU's TCG frontend built as `libtcg-<arch>.so`
//! (see `libtcg/libtcg.h` and `scripts/build-libtcg.sh`).

mod codec;
mod ir;

pub use codec::IrCodec;

pub use ir::*;

use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char},
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, LazyLock},
};

use parking_lot::Mutex;

use libtcg_sys as sys;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Path {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("loading {path}: {source}")]
    Load {
        path: PathBuf,
        source: libloading::Error,
    },
    #[error("{path}: libtcg API version {found}, expected {expected}")]
    ApiVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("{path}: already loaded with CPU model {loaded:?}")]
    CpuModel { path: PathBuf, loaded: String },
    #[error("{0}: libtcg_context_create failed")]
    Context(PathBuf),
    #[error("{0}: no program-counter global")]
    NoPcGlobal(PathBuf),
    #[error("no libtcg for {0}: set BIARA_LIBTCG_DIR or build it with scripts/build-libtcg.sh")]
    NotFound(String),
    #[error("translating {pc:#x}: instruction fetch left the code buffer")]
    Fetch { pc: u64 },
    #[error("translating {pc:#x}: pc outside the code buffer or bad max_insns")]
    Args { pc: u64 },
    #[error("translating {pc:#x}: libtcg_translate returned {code}")]
    Translate { pc: u64, code: i32 },
    #[error("libtcg: unknown TCGType {0}")]
    UnknownType(u8),
    #[error("libtcg: unknown TCGTempKind {0}")]
    UnknownTempKind(u8),
    #[error("libtcg: unknown helper typecode {0}")]
    UnknownHelperType(u32),
    #[error("translating {pc:#x}: corrupt TCG block ({detail})")]
    Corrupt { pc: u64, detail: String },
    #[error("analysis backend: {0}")]
    Backend(String),
    #[error("TCG snapshot: {0}")]
    Codec(String),
}

/// Translation context facts shared by every block.
#[derive(Clone, Debug)]
pub struct ContextInfo {
    pub arch: String,
    pub cpu_model: String,
    pub guest_bits: u32,
    /// Globals, indexed by `TempId`; every block's temps start with these
    /// (shared by pointer: `Block.temps` borrows this prefix, it does not
    /// copy it per block).
    pub globals: Arc<[Temp]>,
    /// The guest program counter global.
    pub pc_global: TempId,
    /// The fixed `env` temp (`CPUArchState *`).
    pub env_global: TempId,
    pub insn_start_words: u32,
    /// sizeof(CPUArchState); `env`-relative offsets index into it.
    pub env_size: usize,
}

impl ContextInfo {
    pub fn pc(&self) -> &Temp {
        &self.globals[self.pc_global as usize]
    }
}

/// A translation request borrows immutable guest bytes for one bounded batch.
pub struct TranslationRequest<'a> {
    pub code: &'a [u8],
    pub code_base: u64,
    pub pc: u64,
    pub max_insns: u32,
}

/// Recovery depends on translation, not the lifetime of one QEMU context.
pub trait Translator {
    fn info(&self) -> &ContextInfo;
    fn translate(
        &mut self,
        code: &[u8],
        code_base: u64,
        pc: u64,
        max_insns: u32,
    ) -> Result<Block, Error>;
    fn prefetch(&mut self, _requests: &[TranslationRequest<'_>]) -> Result<(), Error> {
        Ok(())
    }
}

impl Translator for Libtcg {
    fn info(&self) -> &ContextInfo {
        self.info()
    }
    fn translate(
        &mut self,
        code: &[u8],
        code_base: u64,
        pc: u64,
        max_insns: u32,
    ) -> Result<Block, Error> {
        self.translate(code, code_base, pc, max_insns)
    }
}

/// One loaded libtcg and its (process-unique) QEMU context.
pub struct Libtcg {
    lib: sys::LibTcg,
    ctx: *mut sys::LibTcgContext,
    info: ContextInfo,
    defs: Arc<OpDefs>,
}

// QEMU's translator state is process-global; `load` hands out the one
// instance per library behind a Mutex, and `translate` re-registers the
// calling thread with TCG on every call.
unsafe impl Send for Libtcg {}

/// One instance per library path: QEMU allows a single context per process.
static LOADED: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<Libtcg>>>>> =
    LazyLock::new(Default::default);

impl Libtcg {
    /// `$BIARA_LIBTCG_DIR/libtcg-<arch>.so`, if present.
    pub fn find(arch: &str) -> Result<PathBuf, Error> {
        std::env::var_os("BIARA_LIBTCG_DIR")
            .map(|d| Path::new(&d).join(format!("libtcg-{arch}.so")))
            .filter(|p| p.is_file())
            .ok_or_else(|| Error::NotFound(arch.to_owned()))
    }

    /// Load the library at `path` (once per process) and create its QEMU
    /// context with `cpu_model` (default "max").
    pub fn load(path: &Path, cpu_model: Option<&str>) -> Result<Arc<Mutex<Libtcg>>, Error> {
        let path = path.canonicalize().map_err(|source| Error::Path {
            path: path.to_owned(),
            source,
        })?;
        let mut loaded = LOADED.lock();
        if let Some(lib) = loaded.get(&path) {
            let have = lib.lock().info.cpu_model.clone();
            return match cpu_model {
                Some(m) if m != have => Err(Error::CpuModel { path, loaded: have }),
                _ => Ok(lib.clone()),
            };
        }
        let lib = Arc::new(Mutex::new(Self::open(&path, cpu_model)?));
        loaded.insert(path, lib.clone());
        Ok(lib)
    }

    fn open(path: &Path, cpu_model: Option<&str>) -> Result<Self, Error> {
        let lib = unsafe { sys::LibTcg::new(path) }.map_err(|source| Error::Load {
            path: path.to_owned(),
            source,
        })?;
        let found = unsafe { lib.libtcg_api_version() };
        if found != sys::LIBTCG_API_VERSION {
            return Err(Error::ApiVersion {
                path: path.to_owned(),
                found,
                expected: sys::LIBTCG_API_VERSION,
            });
        }

        let model = cpu_model.map(|m| CString::new(m).expect("CPU model contains NUL"));
        let ctx = unsafe {
            lib.libtcg_context_create(model.as_ref().map_or(ptr::null(), |m| m.as_ptr()))
        };
        if ctx.is_null() {
            return Err(Error::Context(path.to_owned()));
        }

        let raw = unsafe { &*lib.libtcg_context_info(ctx) };
        let raws = unsafe { slice(raw.globals, raw.nb_globals as usize) };
        let mut globals_vec = Vec::with_capacity(raws.len());
        for t in raws {
            globals_vec.push(convert_temp(t, u64::MAX)?);
        }
        let globals: Arc<[Temp]> = globals_vec.into();
        let raw_info = raw;
        if raw_info.pc_global < 0 {
            return Err(Error::NoPcGlobal(path.to_owned()));
        }
        let info = ContextInfo {
            arch: unsafe { cstr(raw_info.arch) }.unwrap_or_default(),
            cpu_model: unsafe { cstr(raw_info.cpu_model) }.unwrap_or_default(),
            guest_bits: raw_info.guest_bits,
            globals,
            pc_global: raw_info.pc_global as TempId,
            env_global: raw_info.env_global as TempId,
            insn_start_words: raw_info.insn_start_words,
            env_size: raw_info.env_size,
        };

        let mut n = 0;
        let defs = unsafe { slice(lib.libtcg_op_defs(&mut n), n) };
        let names: Vec<Box<str>> = defs
            .iter()
            .map(|d| unsafe { cstr(d.name) }.unwrap_or_default().into_boxed_str())
            .collect();
        let defs = Arc::new(OpDefs {
            opcodes: names.iter().map(|n| Opcode::from_name(n)).collect(),
            flags: defs.iter().map(|d| d.flags).collect(),
            arities: defs
                .iter()
                .map(|d| (d.nb_oargs, d.nb_iargs, d.nb_cargs))
                .collect(),
            names,
        });

        Ok(Self {
            lib,
            ctx,
            info,
            defs,
        })
    }

    pub fn info(&self) -> &ContextInfo {
        &self.info
    }
    pub fn codec(&self) -> IrCodec {
        IrCodec::new(
            self.defs.clone(),
            self.info.globals.clone(),
            self.lib.libtcg_api_version as usize,
        )
    }

    /// The guest CPU state (`CPUArchState`) helpers operate on. Valid for
    /// `info().env_size` bytes for the life of the process.
    pub fn env(&mut self) -> *mut u8 {
        unsafe { self.lib.libtcg_env(self.ctx) }.cast()
    }

    /// Translate the block at `pc`. `code` holds guest bytes for
    /// `[code_base, code_base + code.len())`; `max_insns` 0 means no limit
    /// beyond QEMU's (512).
    pub fn translate(
        &mut self,
        code: &[u8],
        code_base: u64,
        pc: u64,
        max_insns: u32,
    ) -> Result<Block, Error> {
        let mut out = ptr::null_mut();
        let rc = unsafe {
            self.lib.libtcg_translate(
                self.ctx,
                code.as_ptr(),
                code.len(),
                code_base,
                pc,
                max_insns,
                &mut out,
            )
        };
        if rc != sys::LIBTCG_OK as i32 {
            return Err(match rc {
                sys::LIBTCG_ERR_FETCH => Error::Fetch { pc },
                sys::LIBTCG_ERR_ARGS => Error::Args { pc },
                code => Error::Translate { pc, code },
            });
        }
        let block = unsafe { self.convert(&*out, pc) }?;
        unsafe { self.lib.libtcg_tb_free(out) };
        Ok(block)
    }

    unsafe fn convert(&self, tb: &sys::LibTcgTranslationBlock, pc: u64) -> Result<Block, Error> {
        let corrupt = |detail: &str| Error::Corrupt {
            pc,
            detail: detail.to_owned(),
        };
        // Native boundary: libtcg hands raw C array lengths. All slicing
        // below re-checks them before indexing; a hostile/truncated block
        // becomes `Corrupt`, never UB.
        let (nb_ops, nb_args, nb_temps, nb_helpers) =
            (tb.nb_ops, tb.nb_args, tb.nb_temps, tb.nb_helpers);
        if nb_ops > 1 << 20 || nb_args > 1 << 24 || nb_temps > 1 << 20 || nb_helpers > 1 << 16 {
            return Err(corrupt("absurd translation-block counts"));
        }
        let ops = unsafe { slice(tb.ops, nb_ops) };
        let args = unsafe { slice(tb.args, nb_args) };
        let temps = unsafe { slice(tb.temps, nb_temps) };
        let helpers = unsafe { slice(tb.helpers, nb_helpers) };
        // Every TB's `[0, nb_globals)` temps must be the context's globals
        // (libtcg.c exports `s->temps` whose first `nb_globals` entries are
        // the globals snapshotted into `ContextInfo`). Verify every field,
        // including `value` (zero for non-constants) and the interned name,
        // and keep only the block-local tail. A TB that ever disagrees keeps
        // its own exact prefix rather than silently borrowing the wrong one.
        let nb_globals = self.info.globals.len();
        let prefix_ok = temps.len() >= nb_globals
            && temps[..nb_globals]
                .iter()
                .zip(self.info.globals.iter())
                .all(|(t, g)| temp_matches(t, g).unwrap_or(false));
        let mut b = if prefix_ok {
            BlockBuilder::new(
                tb.pc,
                tb.size,
                tb.icount,
                tb.nb_labels,
                self.defs.clone(),
                self.info.globals.clone(),
            )
        } else {
            let mut prefix = Vec::with_capacity(nb_globals.min(temps.len()));
            for t in temps.iter().take(nb_globals.min(temps.len())) {
                prefix.push(convert_temp(t, pc)?);
            }
            BlockBuilder::new(
                tb.pc,
                tb.size,
                tb.icount,
                tb.nb_labels,
                self.defs.clone(),
                prefix.into(),
            )
        };
        let (temp_arg_count, const_arg_count) = ops.iter().fold((0usize, 0usize), |(t, c), op| {
            (
                t + op.nb_oargs as usize + op.nb_iargs as usize,
                c + op.nb_cargs as usize,
            )
        });
        b.reserve(
            ops.len(),
            temp_arg_count,
            const_arg_count,
            temps.len(),
            helpers.len(),
        );
        for t in temps.iter().skip(b.nb_globals()) {
            b.temp(convert_temp(t, pc)?);
        }
        for h in helpers {
            b.helper(Helper {
                name: unsafe { cstr(h.name) }.unwrap_or_default(),
                addr: h.func as usize,
                flags: h.flags,
                typemask: h.typemask,
            });
        }
        for op in ops {
            let opc = op.opc as usize;
            if opc >= self.defs.names.len() {
                return Err(corrupt("opcode out of range"));
            }
            // Native arity: `libtcg_op_defs()` fixes every non-call opcode's
            // operand counts. A hostile/truncated TB that disagrees becomes
            // `Corrupt` here, before any temp/const slice is formed.
            if self.defs.opcodes[opc] != crate::Opcode::Call
                && self
                    .defs
                    .arities
                    .get(opc)
                    .is_some_and(|&(o, i, c)| {
                        o != op.nb_oargs || i != op.nb_iargs || c != op.nb_cargs
                    })
            {
                return Err(corrupt("opcode arity mismatch"));
            }
            let start = op.args as usize;
            let need = op.nb_oargs as usize + op.nb_iargs as usize + op.nb_cargs as usize;
            let end = start
                .checked_add(need)
                .ok_or_else(|| corrupt("op arg range overflow"))?;
            if end > args.len() {
                return Err(corrupt("op args out of range"));
            }
            let a = &args[start..end];
            let (outs, rest) = a.split_at(op.nb_oargs as usize);
            let (ins, rest) = rest.split_at(op.nb_iargs as usize);
            let consts = &rest[..op.nb_cargs as usize];
            // Native boundary: temp ids arrive as raw u64 from C. Reject ids
            // beyond the block's temp table here (u32 range + table length),
            // so no out-of-range id ever enters the IR.
            let ntemps = temps.len() as u64;
            if outs
                .iter()
                .chain(ins)
                .any(|&t| t >= ntemps || t > u64::from(u32::MAX))
            {
                return Err(corrupt("temp id out of range"));
            }
            // The type tag is validated so no unknown enum ever enters the IR.
            b.op(
                opc as u32,
                Type::from_raw(op.type_)?,
                op.vece,
                outs,
                ins,
                consts,
            );
        }
        Ok(b.finish())
    }
}

fn convert_temp(t: &sys::LibTcgTemp, pc: u64) -> Result<Temp, Error> {
    let bad = |e: Error| Error::Corrupt {
        pc,
        detail: e.to_string(),
    };
    Ok(Temp {
        kind: TempKind::from_raw(t.kind).map_err(bad)?,
        ty: Type::from_raw(t.type_).map_err(bad)?,
        base_type: Type::from_raw(t.base_type).map_err(bad)?,
        subindex: t.subindex,
        mem_base: (t.mem_base >= 0).then_some(t.mem_base as TempId),
        mem_offset: t.mem_offset,
        value: t.val,
        name: unsafe { cstr(t.name) }.map(Arc::from),
    })
}
/// Whether raw TB temp `t` is exactly the context descriptor `g`: every
/// field, including `value` (globals are never constants, so this is the
/// exported zero) and the name bytes. No field is discarded unchecked; the
/// shared prefix is only borrowed when all of them agree. Compares the raw
/// C name without allocating (names are ASCII identifiers).
fn temp_matches(t: &sys::LibTcgTemp, g: &Temp) -> Result<bool, Error> {
    Ok(TempKind::from_raw(t.kind)? == g.kind
        && Type::from_raw(t.type_)? == g.ty
        && Type::from_raw(t.base_type)? == g.base_type
        && t.subindex == g.subindex
        && (t.mem_base >= 0).then_some(t.mem_base as TempId) == g.mem_base
        && t.mem_offset == g.mem_offset
        && t.val == g.value
        && name_matches(t.name, g.name.as_deref()))
}

fn name_matches(raw: *const c_char, want: Option<&str>) -> bool {
    if raw.is_null() {
        return want.is_none();
    }
    let Some(want) = want else {
        return false;
    };
    unsafe { CStr::from_ptr(raw) }.to_bytes() == want.as_bytes()
}

unsafe fn slice<'a, T>(p: *const T, n: usize) -> &'a [T] {
    if n == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}
