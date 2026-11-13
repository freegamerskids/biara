//! Real loader entry point on arbitrary bytes: must return Ok or Err,
//! never panic. Covers ELF/PE/Mach-O dispatch, unwind/function-list
//! recovery and debugdata handling without any live QEMU.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let bytes = data.to_vec();
    if let Ok(image) = biara_loader::Image::parse(bytes) {
        // Exercise derived views on accepted images; all are total.
        let _ = image.function_starts();
        let _ = image.function_extents();
        let _ = image.indirect_entries();
        let mut buf = [0u8; 8];
        for seg in &image.segments {
            let _ = image.read(seg.addr, &mut buf);
            let _ = image.read_const(seg.addr, &mut buf);
            let _ = image.code_at(seg.addr);
            // One segment exercises the accessors; the views above
            // already covered the whole image.
            break;
        }
    }
});
