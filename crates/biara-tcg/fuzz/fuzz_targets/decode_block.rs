#![no_main]
use libfuzzer_sys::fuzz_target;

// Real TCG snapshot decoder on arbitrary bytes: no live QEMU needed.
// A decode-only codec (empty opcode table) validates every bound;
// malformed input must return Err, never panic or OOM.
fuzz_target!(|data: &[u8]| {
    let codec = biara_tcg::IrCodec::decode_only();
    let _ = codec.decode(data);
});
