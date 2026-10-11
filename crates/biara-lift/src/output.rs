//! Portable streaming LLVM IR output.
//!
//! [`print_module`] prints a module exactly as `Module::print_to_string`
//! does, but in chunks: LLVM's `raw_ostream` forwards each buffer to the
//! given writer instead of first building one whole-module string (native
//! side in `cpp/output.cpp`). Stdout stays portable (no `/dev/stdout`) and
//! the peak holds one LLVM buffer rather than the whole textual module.

use std::{
    ffi::{c_int, c_void},
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};

use inkwell::module::Module;

/// `biara_write_fn` in `cpp/output.cpp`: 0 on success, nonzero on error.
type WriteFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;

unsafe extern "C" {
    /// Print `module` through `write`, chunk by chunk; 0 on success, or 1
    /// after the first writer error (later chunks dropped, buffer flushed).
    fn biara_print_module(module: *mut c_void, write: WriteFn, ctx: *mut c_void) -> c_int;
}

/// The writer behind the callback context: the first error sticks, and the
/// native stream stops calling back after it (see `cpp/output.cpp`).
struct Sink<'w> {
    out: &'w mut dyn io::Write,
    err: Option<io::Error>,
}

/// Forward one LLVM chunk; never unwinds across the C boundary (a panicking
/// writer becomes an error, like a failed write).
unsafe extern "C" fn write_cb(ctx: *mut c_void, data: *const u8, len: usize) -> c_int {
    let sink = unsafe { &mut *(ctx as *mut Sink<'_>) };
    if sink.err.is_some() {
        return 1;
    }
    if len == 0 {
        return 0;
    }
    let wrote = catch_unwind(AssertUnwindSafe(|| {
        let bytes = unsafe { slice::from_raw_parts(data, len) };
        sink.out.write_all(bytes)
    }));
    match wrote {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            sink.err = Some(e);
            1
        }
        Err(_) => {
            sink.err = Some(io::Error::other("LLVM IR writer panicked"));
            1
        }
    }
}

/// Print `module` as LLVM IR to `out`, chunk by chunk, without building the
/// whole text in memory.
///
/// The bytes are identical to `module.print_to_string().to_bytes()`.
///
/// On success every byte reached `out`: the LLVM buffer is flushed before
/// the native call returns, and `out` itself is flushed before returning
/// `Ok`. On failure the returned error is the writer's own, unchanged (a
/// panicking writer becomes an `ErrorKind::Other` error): chunks before the
/// failed one were fully written, the failed chunk may be partial, and
/// nothing after it was attempted.
pub fn print_module(module: &Module<'_>, out: &mut dyn io::Write) -> io::Result<()> {
    let mut sink = Sink { out, err: None };
    let rc = unsafe {
        biara_print_module(
            module.as_mut_ptr().cast(),
            write_cb,
            (&mut sink as *mut Sink<'_>).cast(),
        )
    };
    if rc == 0 {
        return match catch_unwind(AssertUnwindSafe(|| sink.out.flush())) {
            Ok(result) => result,
            Err(_) => Err(io::Error::other("LLVM IR writer panicked")),
        };
    }
    Err(sink
        .err
        .take()
        .unwrap_or_else(|| io::Error::other("LLVM IR writer failed")))
}
