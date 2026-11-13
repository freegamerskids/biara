//! Native guest-byte translation on arbitrary bytes: the real libtcg path
//! (§3.7), not just the portable snapshot decoder. Each input picks an arch,
//! a pc and a bounded guest window; translation errors (fetch/args/corrupt)
//! are all total `Err`, never panics or UB. Snapshot round-trips of accepted
//! blocks exercise the real-opcode decoder (`IrCodec` from the live context)
//! on attacker-influenced IR.
//!
//! Requires `BIARA_LIBTCG_DIR` with both frontend libraries. Missing setup is
//! a harness failure, never a green run that skips native translation.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, LazyLock};

static LIBRARIES: LazyLock<[Arc<parking_lot::Mutex<biara_tcg::Libtcg>>; 2]> =
    LazyLock::new(|| {
        ["x86_64", "aarch64"].map(|arch| {
            let path = biara_tcg::Libtcg::find(arch)
                .expect("native fuzzing requires both libraries in BIARA_LIBTCG_DIR");
            biara_tcg::Libtcg::load(&path, None).expect("native frontend initialization failed")
        })
    });

fuzz_target!(|data: &[u8]| {
    let libraries = &*LIBRARIES;
    if data.len() < 4 {
        return;
    }
    let lib = &libraries[(data[0] & 1) as usize];
    // Bounded guest window: at most 64 bytes, base near the pc so fetches
    // stay in-bounds or fail as total `Fetch` errors.
    let len = (data[1] as usize).min(64).min(data.len() - 3);
    let pc = 0x400_000u64.wrapping_add(u64::from(data[2]));
    let bytes = &data[3..3 + len];
    let mut lib = lib.lock();
    let codec = lib.codec();
    match lib.translate(bytes, pc, pc, 0) {
        Ok(block) => {
            // Accepted IR must round-trip through the real-opcode codec:
            // encode then decode with live defs validates arity and helper
            // indices on attacker-influenced (but well-formed) blocks.
            let mut wire = codec.encode(&block).expect("native block must encode");
            let decoded = codec.decode(&wire).expect("native snapshot must decode");
            assert_eq!(codec.encode(&decoded).expect("decoded block must encode"), wire);
            // Mutate a real snapshot so valid opcode/helper tables are used
            // when checking hostile counts, references, and argument shapes.
            let at = data[2] as usize % wire.len();
            wire[at] ^= data[1];
            if let Ok(decoded) = codec.decode(&wire) {
                let _ = format!("{decoded}");
            }
            let _ = format!("{block}");
        }
        Err(_) => {}
    }
});
