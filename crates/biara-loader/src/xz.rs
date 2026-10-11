//! Streaming XZ decompression through liblzma (`lzma_stream_decoder`).
//!
//! Only what `.gnu_debugdata` needs: a single concatenated stream decoded
//! into a caller-bounded buffer. Errors are opaque (`false`); callers fall
//! back to no symbols rather than failing the whole load.

use std::ffi::c_void;

#[repr(C)]
struct Stream {
    next_in: *const u8,
    avail_in: usize,
    total_in: u64,
    next_out: *mut u8,
    avail_out: usize,
    total_out: u64,
    allocator: *const c_void,
    internal: *mut c_void,
    reserved: [*const c_void; 4],
    // Opaque internals follow; `lzma_stream_decoder` sizes the allocation
    // from this prefix, so the struct must be at least this large.
    opaque: [u64; 128],
}

unsafe extern "C" {
    fn lzma_stream_decoder(stream: *mut Stream, memlimit: u64, flags: u32) -> u32;
    fn lzma_code(stream: *mut Stream, action: u32) -> u32;
    fn lzma_end(stream: *mut Stream);
}

const RET_OK: u32 = 0;
const RET_STREAM_END: u32 = 1;
const ACTION_RUN: u32 = 0;
const ACTION_FINISH: u32 = 3;

/// Decode all of `input` (one XZ stream), appending at most `limit` bytes to
/// `out`. False on corrupt input, truncation, or over the limit.
pub fn decode(input: &[u8], out: &mut Vec<u8>, limit: usize) -> bool {
    if input.is_empty() {
        return false;
    }
    // SAFETY: zeroed `Stream` is a valid initializer for the decoder; all
    // pointers handed to it point at live buffers, and `lzma_end` runs
    // before any of them is freed or moved.
    unsafe {
        let mut stream: Stream = std::mem::zeroed();
        if lzma_stream_decoder(&mut stream, u64::MAX, 0) != RET_OK {
            return false;
        }
        let base = out.len();
        let mut chunk = [0u8; 65536];
        let mut input = input;
        let ok = loop {
            if input.is_empty() && stream.avail_in == 0 {
                break false;
            }
            if stream.avail_in == 0 {
                stream.next_in = input.as_ptr();
                stream.avail_in = input.len();
            }
            stream.next_out = chunk.as_mut_ptr();
            stream.avail_out = chunk.len();
            let action = if input.is_empty() || out.len() - base >= limit {
                ACTION_FINISH
            } else {
                ACTION_RUN
            };
            let in_before = stream.total_in;
            let ret = lzma_code(&mut stream, action);
            let produced = chunk.len() - stream.avail_out;
            input = &input[(stream.total_in - in_before) as usize..];
            if out.len() - base + produced > limit {
                break false;
            }
            out.extend_from_slice(&chunk[..produced]);
            match ret {
                RET_STREAM_END => break true,
                RET_OK => {
                    if stream.avail_in == 0 && input.is_empty() {
                        break false;
                    }
                }
                _ => break false,
            }
        };
        lzma_end(&mut stream);
        ok
    }
}
