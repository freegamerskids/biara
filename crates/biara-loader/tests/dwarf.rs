//! Compile real debug metadata at both optimization levels and architectures.
//! Native execution independently measures offsets from the entry stack pointer.
//! Debug entry registers and declared type spellings are precise facts: only
//! direct entry-covering register locations qualify, and unsupported shapes
//! stay explicit rather than guessed.

use biara_loader::Image;
use object::{Object, ObjectSection};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

fn linker(dir: &Path) -> PathBuf {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let root = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim()).join("lib/rustlib");
    let lld = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path().join("bin/rust-lld"))
        .find(|p| p.exists())
        .expect("Rust toolchain lld");
    let link = dir.join("ld.lld");
    std::os::unix::fs::symlink(lld, &link).unwrap();
    link
}

const SOURCE: &str = r#"
unsigned long entry, results[6], index;
typedef char Row[5];
typedef struct { char prefix[8]; long words[3]; } Payload;
__attribute__((noinline)) void sink(void *p, unsigned long n) {
    results[index++] = (unsigned long)p - entry;
    results[index++] = n;
}
__attribute__((noinline, used)) long scalar(long x) { return x + 1; }
__attribute__((noinline)) void body(void) {
    volatile Payload local;
    volatile Row grid[3];
    sink((void *)&local, sizeof(local));
    sink((void *)&grid, sizeof(grid));
    { volatile char inner[7]; sink((void *)&inner, sizeof(inner)); }
}
"#;

const X86_START: &str = r#"
.text
.globl _start
_start:
    mov %rsp, %rax
    sub $8, %rax
    mov %rax, entry(%rip)
    call body
    mov $1, %eax
    mov $1, %edi
    lea results(%rip), %rsi
    mov $48, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall
.section .note.GNU-stack,"",@progbits
"#;

const ARM_START: &str = r#"
.text
.globl _start
_start:
    mov x9, sp
    adrp x10, entry
    str x9, [x10, :lo12:entry]
    bl body
    mov x0, #1
    adrp x1, results
    add x1, x1, :lo12:results
    mov x2, #48
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #93
    svc #0
.section .note.GNU-stack,"",@progbits
"#;

fn build(arch: &str, opt: u8, frame_pointer: bool, debug: bool) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("dwarf-{arch}-{opt}-{frame_pointer}-{debug}"));
    // Each configuration is built once by this test module.
    std::fs::create_dir_all(&dir).unwrap();
    let link = if dir.join("ld.lld").exists() {
        dir.join("ld.lld")
    } else {
        linker(&dir)
    };
    std::fs::write(dir.join("body.c"), SOURCE).unwrap();
    std::fs::write(
        dir.join("start.S"),
        if arch == "x86_64" {
            X86_START
        } else {
            ARM_START
        },
    )
    .unwrap();
    let binary = dir.join("image");
    let output = Command::new(env!("BIARA_CLANG"))
        .arg(format!("--target={arch}-linux-gnu"))
        .arg(format!("-O{opt}"))
        .arg(if debug { "-g" } else { "-g0" })
        .arg(if frame_pointer {
            "-fno-omit-frame-pointer"
        } else {
            "-fomit-frame-pointer"
        })
        .args([
            "-ffreestanding",
            "-nostdlib",
            "-static",
            "-fno-pie",
            "-fno-stack-protector",
            "-funwind-tables",
            "-fuse-ld=lld",
        ])
        .arg(format!("--ld-path={}", link.display()))
        .arg(dir.join("body.c"))
        .arg(dir.join("start.S"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "clang: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

#[test]
fn optimized_and_unoptimized_declared_objects() {
    for arch in ["x86_64", "aarch64"] {
        let mut verified = BTreeSet::new();
        for opt in [0, 2] {
            for frame_pointer in [false, true] {
                let path = build(arch, opt, frame_pointer, true);
                let image = Image::load(&path).unwrap();
                assert!(image.debug_status.present);
                assert!(
                    image.debug_status.errors.is_empty(),
                    "{arch} O{opt}: {:?}",
                    image.debug_status
                );
                let function = image.symbol("body").unwrap().addr;
                // Declared spellings are evidence, not layout: exact array
                // bounds, aggregate members, and typedef names survive; bit
                // shapes or unknown compositions would be explicit `None`.
                let expected = [
                    ("local", 32u64, "Payload"),
                    ("grid", 15u64, "Row[3]"),
                    ("inner", 7u64, "char[7]"),
                ];
                for (name, size, spelling) in expected {
                    let objects: Vec<_> = image
                        .stack_objects
                        .iter()
                        .filter(|o| o.function == function && o.name == name)
                        .collect();
                    if objects.is_empty() {
                        // SP-relative locations cannot be converted when the
                        // CFA is FP-based without a current-SP relation.
                        assert!(
                            image.debug_status.unsupported_locations > 0,
                            "{arch} O{opt} fp={frame_pointer}: missing {name} without an unknown-location fact"
                        );
                        continue;
                    }
                    verified.insert(name);
                    for object in objects {
                        assert_eq!(object.size, size, "whole declaration, not first field");
                        assert!(object.range.start < object.range.end);
                        // Type spellings never change offsets: the same object
                        // carries the same declared description everywhere.
                        assert_eq!(
                            object.type_name.as_deref(),
                            Some(spelling),
                            "{arch} O{opt} fp={frame_pointer}: {name} declared type"
                        );
                        assert_eq!(
                            image
                                .stack_object(
                                    function,
                                    object.range.start,
                                    object.offset + size as i64 - 1
                                )
                                .unwrap()
                                .name,
                            name
                        );
                        assert!(
                            image
                                .stack_object(function, object.range.end, object.offset)
                                .is_none_or(|o| o.range.start >= object.range.end)
                        );
                    }
                }
                if opt == 0 {
                    let scalar = image.symbol("scalar").unwrap().addr;
                    assert!(
                        !image.debug_names.iter().any(|n| n.function == scalar),
                        "a spilled parameter is not an entry-register binding"
                    );
                }
                if arch == "x86_64" {
                    let result = Command::new(&path).output().unwrap();
                    assert!(result.status.success());
                    assert_eq!(result.stdout.len(), 48);
                    for (i, (name, size, _)) in expected.into_iter().enumerate() {
                        let offset = i64::from_le_bytes(
                            result.stdout[i * 16..i * 16 + 8].try_into().unwrap(),
                        );
                        let measured_size = u64::from_le_bytes(
                            result.stdout[i * 16 + 8..i * 16 + 16].try_into().unwrap(),
                        );
                        assert_eq!(measured_size, size);
                        if !image
                            .stack_objects
                            .iter()
                            .any(|o| o.function == function && o.name == name)
                        {
                            continue;
                        }
                        assert!(
                            image.stack_objects.iter().any(|o| o.function == function
                                && o.name == name
                                && o.offset == offset
                                && o.size == size),
                            "O{opt} fp={frame_pointer}: {name} measured entry-SP offset {offset}"
                        );
                    }
                }
            }
        }
        assert_eq!(
            verified,
            BTreeSet::from(["local", "grid", "inner"]),
            "{arch}: supported declarations across configurations"
        );
    }
}

#[test]
fn stripped_missing_and_malformed_debug_remain_unknown() {
    let stripped = Image::load(&build("x86_64", 1, false, false)).unwrap();
    assert!(!stripped.debug_status.present);
    assert!(stripped.stack_objects.is_empty());
    assert!(stripped.debug_names.is_empty());
    assert!(
        stripped
            .stack_object(stripped.symbol("body").unwrap().addr, stripped.entry, -32)
            .is_none()
    );

    let path = build("x86_64", 1, true, true);
    let mut bytes = std::fs::read(&path).unwrap();
    let (offset, length) = {
        let file = object::File::parse(&*bytes).unwrap();
        file.section_by_name(".debug_info")
            .unwrap()
            .file_range()
            .unwrap()
    };
    bytes[offset as usize..(offset + length) as usize].fill(0xff);
    let bad = Image::parse(bytes).unwrap();
    assert!(bad.debug_status.present);
    assert!(!bad.debug_status.errors.is_empty());
    assert!(bad.stack_objects.is_empty());
    assert!(bad.debug_names.is_empty());
}

#[test]
fn debug_names_cover_entry_registers_and_compressed_parity() {
    // This optimized leaf retains its original argument in the entry register.
    let path = build("x86_64", 1, false, true);
    let image = Image::load(&path).unwrap();
    assert!(image.debug_status.present);
    assert!(
        image.debug_status.errors.is_empty(),
        "{:?}",
        image.debug_status
    );
    let function = image.symbol("scalar").unwrap().addr;
    let names: Vec<_> = image
        .debug_names
        .iter()
        .filter(|n| n.function == function)
        .collect();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].name, "x");
    assert_eq!(names[0].type_name.as_deref(), Some("long"));
    assert_eq!(names[0].register, 5); // DWARF x86-64 RDI, not the guest address.
    // Compressed sections preserve names, types, and stack objects exactly.
    let compressed = path.with_extension("names-compressed");
    let output = Command::new("objcopy")
        .arg("--compress-debug-sections=zlib")
        .arg(&path)
        .arg(&compressed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let again = Image::load(&compressed).unwrap();
    assert_eq!(
        again
            .debug_names
            .iter()
            .map(|n| (
                n.function,
                n.register,
                n.name.as_str(),
                n.type_name.as_deref()
            ))
            .collect::<Vec<_>>(),
        image
            .debug_names
            .iter()
            .map(|n| (
                n.function,
                n.register,
                n.name.as_str(),
                n.type_name.as_deref()
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        again
            .stack_objects
            .iter()
            .map(|o| (
                o.function,
                o.range.clone(),
                o.name.as_str(),
                o.offset,
                o.size,
                o.type_name.as_deref()
            ))
            .collect::<Vec<_>>(),
        image
            .stack_objects
            .iter()
            .map(|o| (
                o.function,
                o.range.clone(),
                o.name.as_str(),
                o.offset,
                o.size,
                o.type_name.as_deref()
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn compressed_debug_sections_preserve_bounds() {
    let path = build("x86_64", 3, true, true);
    let original = Image::load(&path).unwrap();
    let compressed = path.with_extension("compressed");
    let output = Command::new("objcopy")
        .arg("--compress-debug-sections=zlib")
        .arg(&path)
        .arg(&compressed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let image = Image::load(&compressed).unwrap();
    assert!(image.debug_status.errors.is_empty());
    assert_eq!(
        image
            .stack_objects
            .iter()
            .map(|o| (
                o.function,
                o.range.clone(),
                o.name.as_str(),
                o.offset,
                o.size,
                o.type_name.as_deref()
            ))
            .collect::<Vec<_>>(),
        original
            .stack_objects
            .iter()
            .map(|o| (
                o.function,
                o.range.clone(),
                o.name.as_str(),
                o.offset,
                o.size,
                o.type_name.as_deref()
            ))
            .collect::<Vec<_>>()
    );
    // Conflicting declarations never pick the smallest overlapping extent.
    let mut image = image;
    let object = image
        .stack_objects
        .iter()
        .find(|o| o.name == "local")
        .unwrap()
        .clone();
    let mut conflicting = object.clone();
    conflicting.name = "unrelated".into();
    conflicting.size = 8;
    image.stack_objects.push(conflicting);
    assert!(
        image
            .stack_object(object.function, object.range.start, object.offset)
            .is_none()
    );
}
