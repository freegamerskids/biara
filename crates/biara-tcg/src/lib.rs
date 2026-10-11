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
        let globals: Arc<[Temp]> = unsafe { slice(raw.globals, raw.nb_globals as usize) }
            .iter()
            .map(convert_temp)
            .collect();
        if raw.pc_global < 0 {
            return Err(Error::NoPcGlobal(path.to_owned()));
        }
        let info = ContextInfo {
            arch: unsafe { cstr(raw.arch) }.unwrap_or_default(),
            cpu_model: unsafe { cstr(raw.cpu_model) }.unwrap_or_default(),
            guest_bits: raw.guest_bits,
            globals,
            pc_global: raw.pc_global as TempId,
            env_global: raw.env_global as TempId,
            insn_start_words: raw.insn_start_words,
            env_size: raw.env_size,
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
        let block = unsafe { self.convert(&*out) };
        unsafe { self.lib.libtcg_tb_free(out) };
        Ok(block)
    }

    unsafe fn convert(&self, tb: &sys::LibTcgTranslationBlock) -> Block {
        let ops = unsafe { slice(tb.ops, tb.nb_ops) };
        let args = unsafe { slice(tb.args, tb.nb_args) };
        let temps = unsafe { slice(tb.temps, tb.nb_temps) };
        let helpers = unsafe { slice(tb.helpers, tb.nb_helpers) };

        // Every TB's `[0, nb_globals)` temps must be the context's globals
        // (libtcg.c exports `s->temps` whose first `nb_globals` entries are
        // the globals snapshotted into `ContextInfo`). Verify every field,
        // including `value` (zero for non-constants) and the interned name,
        // and keep only the block-local tail. A TB that ever disagrees keeps
        // its own exact prefix rather than silently borrowing the wrong one.
        let nb_globals = self.info.globals.len();
        let mut b = if temps.len() >= nb_globals
            && temps[..nb_globals]
                .iter()
                .zip(self.info.globals.iter())
                .all(|(t, g)| temp_matches(t, g))
        {
            BlockBuilder::new(
                tb.pc,
                tb.size,
                tb.icount,
                tb.nb_labels,
                self.defs.clone(),
                self.info.globals.clone(),
            )
        } else {
            let prefix: Arc<[Temp]> = temps
                .iter()
                .take(nb_globals.min(temps.len()))
                .map(convert_temp)
                .collect();
            BlockBuilder::new(
                tb.pc,
                tb.size,
                tb.icount,
                tb.nb_labels,
                self.defs.clone(),
                prefix,
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
            b.temp(convert_temp(t));
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
            let a = &args[op.args as usize..];
            let (outs, rest) = a.split_at(op.nb_oargs as usize);
            let (ins, rest) = rest.split_at(op.nb_iargs as usize);
            let consts = &rest[..op.nb_cargs as usize];
            b.op(op.opc, Type::from_raw(op.type_), op.vece, outs, ins, consts);
        }
        b.finish()
    }
}

fn convert_temp(t: &sys::LibTcgTemp) -> Temp {
    Temp {
        kind: TempKind::from_raw(t.kind),
        ty: Type::from_raw(t.type_),
        base_type: Type::from_raw(t.base_type),
        subindex: t.subindex,
        mem_base: (t.mem_base >= 0).then_some(t.mem_base as TempId),
        mem_offset: t.mem_offset,
        value: t.val,
        name: unsafe { cstr(t.name) }.map(Arc::from),
    }
}

/// Whether raw TB temp `t` is exactly the context descriptor `g`: every
/// field, including `value` (globals are never constants, so this is the
/// exported zero) and the name bytes. No field is discarded unchecked; the
/// shared prefix is only borrowed when all of them agree. Compares the raw
/// C name without allocating (names are ASCII identifiers).
fn temp_matches(t: &sys::LibTcgTemp, g: &Temp) -> bool {
    TempKind::from_raw(t.kind) == g.kind
        && Type::from_raw(t.type_) == g.ty
        && Type::from_raw(t.base_type) == g.base_type
        && t.subindex == g.subindex
        && (t.mem_base >= 0).then_some(t.mem_base as TempId) == g.mem_base
        && t.mem_offset == g.mem_offset
        && t.val == g.value
        && name_matches(t.name, g.name.as_deref())
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
