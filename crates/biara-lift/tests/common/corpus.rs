//! The C test corpus (tests/aarch64/corpus.c): its Rust reference
//! semantics, inputs, and building and mapping it.

use std::{collections::BTreeSet, path::PathBuf, process::Command};

use biara_loader::Image;

use super::{linker, tmp};

pub type Ref = fn(u64, u64) -> u64;

// ---- reference semantics (keep in sync with corpus.c) ----------------------

pub fn t_arith(a: u64, b: u64) -> u64 {
    a.wrapping_mul(3)
        .wrapping_add(b >> 2)
        .wrapping_sub(a ^ b)
        .wrapping_add(((a as i64) >> 7) as u64)
}

pub fn t_loop(a: u64, b: u64) -> u64 {
    let mut s = 0u64;
    for i in 0..(b & 63) {
        s = s.wrapping_add(i.wrapping_mul(a) ^ (s >> 3));
    }
    s
}

pub fn t_cond(a: u64, b: u64) -> u64 {
    let mut r = 0u64;
    if (a as i64) < (b as i64) {
        r |= 1;
    }
    if a < b {
        r |= 2;
    }
    if a == b {
        r |= 4;
    }
    if (a as i32) > (b as i32) {
        r |= 8;
    }
    if (a as u32) >= (b as u32) {
        r |= 16;
    }
    r.wrapping_add(a.abs_diff(b))
}

pub fn t_muldiv(a: u64, b: u64) -> u64 {
    let p = ((a as u128 * b as u128) >> 64) as u64;
    let q = (((a as i64 as i128) * (b as i64 as i128)) >> 64) as u64;
    let d = b | 1;
    let (sa, mut sd) = (a as i64, (b | 1) as i64);
    if sd == -1 {
        sd = 3;
    }
    p ^ q
        ^ (a / d)
        ^ (a % d)
        ^ (sa / sd) as u64
        ^ (sa % sd) as u64
        ^ u64::from(a as u32 / (b as u32 | 1))
}

pub fn t_bits(a: u64, b: u64) -> u64 {
    let n = (b & 63) as u32;
    let counts = u64::from(a.leading_zeros())
        + 100 * u64::from(b.trailing_zeros())
        + 10000 * u64::from((a ^ b).count_ones());
    counts ^ a.swap_bytes() ^ a.rotate_left(n) ^ b.reverse_bits()
}

pub fn t_flags(a: u64, b: u64) -> u64 {
    let (s, o1) = (a as i64).overflowing_add(b as i64);
    let (d, o2) = a.overflowing_sub(b);
    let r = u64::from(o1) | u64::from(o2) << 1;
    let x = ((a as u128) << 64 | b as u128).wrapping_add((b as u128) << 64 | a as u128);
    r ^ s as u64 ^ (d << 2) ^ (x >> 64) as u64 ^ x as u64
}

pub fn t_switch(a: u64, b: u64) -> u64 {
    match a & 15 {
        0 => b.wrapping_add(11),
        1 => b.wrapping_mul(23),
        2 => b.wrapping_sub(37),
        3 => b ^ 0x55,
        4 => b << 3,
        5 => b >> 5,
        6 => b.wrapping_neg(),
        7 => b | 0x100,
        8 => b & 0xff,
        9 => !b,
        10 => b.wrapping_mul(b),
        _ => a,
    }
}

pub fn t_byteswitch(a: u64, b: u64) -> u64 {
    match a as u8 {
        0 => b.wrapping_add(3),
        1 => b.wrapping_mul(5),
        2 => b.wrapping_sub(7),
        3 => b ^ 0x99,
        4 => b << 2,
        5 => b >> 3,
        7 => b.wrapping_mul(b),
        8 => !b,
        9 => b.wrapping_add(0x1234),
        10 => b.wrapping_mul(9),
        11 => b | 0xf0,
        13 => b & 0x0f,
        _ => a,
    }
}

pub fn t_merged(a: u64, b: u64) -> u64 {
    match a as u8 {
        0 => b.wrapping_add(1),
        1 => b.wrapping_sub(1),
        2 => b ^ 7,
        3 => b << 1,
        _ => b,
    }
}

fn fib(n: u64) -> u64 {
    if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
}

pub fn t_calls(a: u64, b: u64) -> u64 {
    let args = [
        a,
        b,
        a ^ b,
        a.wrapping_add(b),
        a.wrapping_mul(b),
        a.wrapping_sub(b),
        b.wrapping_sub(a),
        a | b,
        a & b,
        !a,
    ];
    let many = args
        .iter()
        .zip(1u64..)
        .fold(0u64, |s, (&x, k)| s.wrapping_add(x.wrapping_mul(k)));
    many.wrapping_add(fib(b & 15))
}

pub fn t_memory(a: u64, b: u64) -> u64 {
    let buf: Vec<u64> = (0..16u64)
        .map(|i| a.wrapping_mul(i).wrapping_add(b))
        .collect();
    (0..16u64).fold(0, |s, i| {
        s ^ buf[(i.wrapping_mul(7).wrapping_add(b) & 15) as usize] << (i & 7)
    })
}

pub fn t_narrow(a: u64, b: u64) -> u64 {
    let mut q = a.to_le_bytes();
    q[(b & 7) as usize] = b as u8;
    let half = |i: usize| u16::from_le_bytes([q[2 * i], q[2 * i + 1]]);
    let word = |i: usize| u32::from_le_bytes(q[4 * i..4 * i + 4].try_into().unwrap());
    (q[1] as i8 as i64 as u64)
        .wrapping_add(u64::from(half(2)))
        .wrapping_add(half(3) as i16 as i64 as u64)
        .wrapping_add(u64::from(word(0)))
        .wrapping_add(word(1) as i32 as i64 as u64)
        .wrapping_add(u64::from_le_bytes(q))
}

pub fn t_float(a: u64, b: u64) -> u64 {
    let (x, y) = (a as i64 as f64, (b | 1) as f64);
    let r = (x * x + y).sqrt() / y + x * 0.5;
    let f = (a as u32) as f32 * 1.5 - (b as u32) as f32;
    (r as i64 as u64) ^ (f as i64 as u64)
}

pub fn t_w32(a: u64, b: u64) -> u64 {
    let (x, y) = (a as u32, b as u32);
    let n = y & 31;
    let r = x
        .wrapping_mul(7)
        .wrapping_add(y >> 3)
        .wrapping_sub(x ^ y)
        .rotate_left(n);
    (r as i32 as i64 as u64).wrapping_add(((x as i32) >> n) as i64 as u64)
}

pub fn t_atomic(_: u64, b: u64) -> u64 {
    // old = a; the add leaves a + b, which the CAS swaps for a ^ b.
    b ^ 1
}

pub fn t_tail(a: u64, b: u64) -> u64 {
    t_arith(b, a.wrapping_add(1))
}

pub fn t_tramp(a: u64, b: u64) -> u64 {
    t_arith(b, a).wrapping_add(1)
}

pub fn t_structs(a: u64, b: u64) -> u64 {
    let walk = (a ^ b)
        .wrapping_mul(7)
        .wrapping_add(b.wrapping_mul(5))
        .wrapping_add(a.wrapping_mul(3));
    let k = a.wrapping_add(b);
    let (x, y) = (k as u32, (k as u32).wrapping_mul(2));
    walk.wrapping_add(u64::from(x))
        .wrapping_add(u64::from(y))
        .wrapping_add(k << 33)
}

/// Every corpus function and its reference (`t_merged` is AArch64 assembly).
pub const FUNCTIONS: &[(&str, Ref)] = &[
    ("t_arith", t_arith),
    ("t_loop", t_loop),
    ("t_cond", t_cond),
    ("t_muldiv", t_muldiv),
    ("t_bits", t_bits),
    ("t_flags", t_flags),
    ("t_switch", t_switch),
    ("t_byteswitch", t_byteswitch),
    ("t_merged", t_merged),
    ("t_calls", t_calls),
    ("t_memory", t_memory),
    ("t_narrow", t_narrow),
    ("t_float", t_float),
    ("t_w32", t_w32),
    ("t_atomic", t_atomic),
    ("t_tail", t_tail),
    ("t_structs", t_structs),
    ("t_tramp", t_tramp),
];

/// Map the image's segments at their addresses (read-write: lifted code
/// reads tables and writes data through host pointers; `exec` also lets
/// the host run them).
pub fn map(image: &Image, exec: bool) {
    const PAGE: u64 = 4096;
    let mut mapped = BTreeSet::new();
    for seg in &image.segments {
        let (start, end) = (
            seg.addr & !(PAGE - 1),
            (seg.addr + seg.size).next_multiple_of(PAGE),
        );
        for page in (start..end).step_by(PAGE as usize) {
            if mapped.insert(page) {
                let p = unsafe {
                    libc::mmap(
                        page as *mut libc::c_void,
                        PAGE as usize,
                        libc::PROT_READ | libc::PROT_WRITE | if exec { libc::PROT_EXEC } else { 0 },
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    )
                };
                assert_eq!(p as u64, page, "mapping {page:#x}");
            }
        }
        let mem = unsafe { std::slice::from_raw_parts_mut(seg.addr as *mut u8, seg.size as usize) };
        assert!(image.read(seg.addr, mem));
    }
}

pub fn inputs() -> Vec<(u64, u64)> {
    let edges = [
        0,
        1,
        2,
        7,
        10,
        15,
        31,
        63,
        64,
        0xff,
        0x8000_0000,
        u32::MAX as u64,
        i64::MAX as u64,
        i64::MIN as u64,
        u64::MAX,
    ];
    let mut v: Vec<(u64, u64)> = edges
        .iter()
        .flat_map(|&a| edges.iter().map(move |&b| (a, b)))
        .collect();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..64 {
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        v.push((next(), next()));
    }
    v
}

/// tests/aarch64/corpus.c built for `target` at `-O{opt}`, linked at `base`.
pub fn build(target: &str, opt: u8, base: u64) -> Image {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/aarch64/corpus.c");
    let out = tmp().join(format!("corpus-{target}-O{opt}"));
    let mut cmd = Command::new(env!("BIARA_CLANG"));
    cmd.args([&format!("--target={target}"), &format!("-O{opt}")])
        .args(["-ffreestanding", "-fno-math-errno", "-ffp-contract=off"])
        .args(["-nostdlib", "-static", "-fno-pie"])
        .arg(format!("--ld-path={}", linker().display()))
        .args([
            "-Wl,--entry=t_arith",
            &format!("-Wl,--image-base={base:#x}"),
        ]);
    if target.starts_with("aarch64") {
        cmd.arg("-mno-outline-atomics");
    } else {
        // Linked far above 2 GiB.
        cmd.arg("-mcmodel=large");
    }
    let status = cmd.arg("-o").arg(&out).arg(&src).status().unwrap();
    assert!(
        status.success(),
        "building the corpus for {target} at -O{opt}"
    );
    Image::load(&out).unwrap()
}
