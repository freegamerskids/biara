//! PE discovery distinguishes executable exports, forwarded/data exports and TLS.
use biara_loader::Image;

fn word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn dword(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn qword(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn dll() -> Vec<u8> {
    dll_with_magic(0x20b)
}

/// Entryless PE with code exports and a TLS callback.
fn dll_with_magic(magic: u16) -> Vec<u8> {
    // `.rdata` is 0x400 bytes (RVA 0x2000..0x2400, file 0x400..0x800) so a
    // 148-byte load config body plus its GFIDs table fit file-backed past
    // the export names/TLS slots.
    let mut bytes = vec![0; 0x800];
    word(&mut bytes, 0, 0x5a4d);
    dword(&mut bytes, 0x3c, 0x80);
    dword(&mut bytes, 0x80, 0x4550);
    word(
        &mut bytes,
        0x84,
        if magic == 0x20b { 0x8664 } else { 0x14c },
    );
    word(&mut bytes, 0x86, 2);
    let optional_size = if magic == 0x20b { 240 } else { 224 };
    word(&mut bytes, 0x94, optional_size);
    word(&mut bytes, 0x96, 0x2022);
    let opt = 0x98;
    word(&mut bytes, opt, magic);
    dword(&mut bytes, opt + 4, 0x200);
    dword(&mut bytes, opt + 8, 0x200);
    if magic == 0x20b {
        qword(&mut bytes, opt + 24, 0x180000000);
    } else {
        dword(&mut bytes, opt + 28, 0x400000);
    }
    dword(&mut bytes, opt + 32, 0x1000);
    dword(&mut bytes, opt + 36, 0x200);
    dword(&mut bytes, opt + 56, 0x3000);
    dword(&mut bytes, opt + 60, 0x200);
    // Data directories start at opt+112 for PE32+, opt+96 for PE32.
    let dirs = opt + if magic == 0x20b { 112 } else { 96 };
    dword(&mut bytes, dirs - 4, 16);
    dword(&mut bytes, dirs, 0x2000);
    dword(&mut bytes, dirs + 4, 0x100);
    dword(&mut bytes, dirs + 9 * 8, 0x2100);
    dword(&mut bytes, dirs + 9 * 8 + 4, 40);
    let text = opt + usize::from(optional_size);
    bytes[text..text + 5].copy_from_slice(b".text");
    dword(&mut bytes, text + 8, 0x80);
    dword(&mut bytes, text + 12, 0x1000);
    dword(&mut bytes, text + 16, 0x200);
    dword(&mut bytes, text + 20, 0x200);
    dword(&mut bytes, text + 36, 0x60000020);
    let data = text + 40;
    bytes[data..data + 6].copy_from_slice(b".rdata");
    dword(&mut bytes, data + 8, 0x400);
    dword(&mut bytes, data + 12, 0x2000);
    dword(&mut bytes, data + 16, 0x400);
    dword(&mut bytes, data + 20, 0x400);
    dword(&mut bytes, data + 36, 0x40000040);
    for offset in [0x200, 0x210, 0x220] {
        bytes[offset..offset + 4].copy_from_slice(&[0x48, 0x89, 0xc8, 0xc3]);
    }
    dword(&mut bytes, 0x400 + 16, 1);
    dword(&mut bytes, 0x400 + 20, 4);
    dword(&mut bytes, 0x400 + 24, 2);
    dword(&mut bytes, 0x400 + 28, 0x2028);
    dword(&mut bytes, 0x400 + 32, 0x2038);
    dword(&mut bytes, 0x400 + 36, 0x2040);
    dword(&mut bytes, 0x428, 0x1000);
    dword(&mut bytes, 0x42c, 0x2180);
    dword(&mut bytes, 0x430, 0x1010);
    dword(&mut bytes, 0x434, 0x2060);
    dword(&mut bytes, 0x438, 0x2044);
    dword(&mut bytes, 0x43c, 0x204c);
    word(&mut bytes, 0x440, 0);
    word(&mut bytes, 0x442, 3);
    bytes[0x444..0x44c].copy_from_slice(b"visible\0");
    bytes[0x44c..0x456].copy_from_slice(b"forwarded\0");
    bytes[0x460..0x46b].copy_from_slice(b"other.call\0");
    let base = base_of(&bytes);
    if magic == 0x20b {
        qword(&mut bytes, 0x518, base + 0x2140);
        qword(&mut bytes, 0x540, base + 0x1020);
    } else {
        dword(&mut bytes, 0x50c, (base + 0x2140) as u32);
        dword(&mut bytes, 0x540, (base + 0x1020) as u32);
    }
    bytes
}

fn base_of(bytes: &[u8]) -> u64 {
    let opt = 0x98;
    if u16::from_le_bytes([bytes[opt], bytes[opt + 1]]) == 0x20b {
        u64::from_le_bytes(bytes[opt + 24..opt + 32].try_into().unwrap())
    } else {
        u64::from(u32::from_le_bytes(
            bytes[opt + 28..opt + 32].try_into().unwrap(),
        ))
    }
}

const GUARD_DIRECTORY: usize = 0x600;

fn guard_layout(magic: u16) -> (usize, usize, usize, usize, usize) {
    if magic == 0x20b {
        (0x98 + 112, 128, 136, 144, 148)
    } else {
        (0x98 + 96, 80, 84, 88, 92)
    }
}

/// GFIDs are the only source of entries: remove the exports and TLS directory.
fn guarded(magic: u16, stride: usize, entries: &[(u32, u8)]) -> Vec<u8> {
    let mut bytes = dll_with_magic(magic);
    let base = base_of(&bytes);
    let (dirs, table, count, flags, prefix) = guard_layout(magic);
    for index in [0, 9] {
        dword(&mut bytes, dirs + index * 8, 0);
        dword(&mut bytes, dirs + index * 8 + 4, 0);
    }
    dword(&mut bytes, dirs + 10 * 8, 0x2200);
    dword(&mut bytes, dirs + 10 * 8 + 4, prefix as u32);
    dword(&mut bytes, GUARD_DIRECTORY, prefix as u32);
    dword(
        &mut bytes,
        GUARD_DIRECTORY + flags,
        0x400 | (((stride - 4) as u32) << 28),
    );
    let table_file = GUARD_DIRECTORY + prefix;
    let table_va = base + 0x2000 + (table_file - 0x400) as u64;
    if magic == 0x20b {
        qword(&mut bytes, GUARD_DIRECTORY + table, table_va);
        qword(&mut bytes, GUARD_DIRECTORY + count, entries.len() as u64);
    } else {
        dword(&mut bytes, GUARD_DIRECTORY + table, table_va as u32);
        dword(&mut bytes, GUARD_DIRECTORY + count, entries.len() as u32);
    }
    for (i, &(rva, metadata)) in entries.iter().enumerate() {
        let offset = table_file + i * stride;
        dword(&mut bytes, offset, rva);
        if stride > 4 {
            bytes[offset + 4] = metadata;
        }
    }
    bytes
}

#[test]
fn entryless_dll_discovers_named_ordinal_exports_and_tls_callbacks() {
    let image = Image::parse(dll()).unwrap();
    assert_eq!(image.symbol("visible").unwrap().addr, 0x180001000);
    assert_eq!(image.symbol("ordinal_3").unwrap().addr, 0x180001010);
    assert!(image.symbol("ordinal_2").is_none());
    assert!(image.symbol("forwarded").is_none());
    assert_eq!(
        image.function_starts().into_iter().collect::<Vec<_>>(),
        [0x180001000, 0x180001010, 0x180001020]
    );
    assert!(image.indirect_entries().contains(&0x180001020));
}

#[test]
fn invalid_tls_table_does_not_add_unmapped_callback_entries() {
    let mut bytes = dll();
    qword(&mut bytes, 0x518, u64::MAX);
    let image = Image::parse(bytes).unwrap();
    assert_eq!(
        image.function_starts().into_iter().collect::<Vec<_>>(),
        [0x180001000, 0x180001010]
    );
}

#[test]
fn guard_tables_find_functions_without_entry_exports_tls_or_unwind() {
    for magic in [0x10b, 0x20b] {
        let bytes = guarded(magic, 4, &[(0x1000, 0), (0x1010, 0)]);
        let base = base_of(&bytes);
        let image = Image::parse(bytes).unwrap();
        assert_eq!(
            image.function_starts().into_iter().collect::<Vec<_>>(),
            [base + 0x1000, base + 0x1010]
        );
        assert_eq!(image.indirect_entries(), image.function_starts());
        assert!(image.function_extents().is_empty());
    }
}

#[test]
fn older_guard_directory_revision_needs_only_its_declared_prefix() {
    for magic in [0x10b, 0x20b] {
        let mut bytes = guarded(magic, 4, &[(0x1000, 0), (0x1010, 0)]);
        let base = base_of(&bytes);
        let (dirs, table, _, _, prefix) = guard_layout(magic);
        // Put the minimal directory and two RVAs at the end of the raw
        // section. Requiring the full current SDK structure loses these.
        let destination = bytes.len() - prefix - 8;
        bytes.copy_within(GUARD_DIRECTORY..GUARD_DIRECTORY + prefix + 8, destination);
        dword(
            &mut bytes,
            dirs + 10 * 8,
            (0x2000 + destination - 0x400) as u32,
        );
        let table_va = base + 0x23f8;
        if magic == 0x20b {
            qword(&mut bytes, destination + table, table_va);
        } else {
            dword(&mut bytes, destination + table, table_va as u32);
        }
        let image = Image::parse(bytes).unwrap();
        assert_eq!(
            image.function_starts().into_iter().collect::<Vec<_>>(),
            [base + 0x1000, base + 0x1010]
        );
    }
}

#[test]
fn stride_and_suppression_metadata_do_not_erase_function_roots() {
    let mut bytes = guarded(
        0x20b,
        19,
        &[(0x1000, 1), (0x1010, 2), (0x1010, 2), (0x1020, 0)],
    );
    let (_, _, _, _, prefix) = guard_layout(0x20b);
    // Extra metadata must not be interpreted as more RVA entries.
    bytes[GUARD_DIRECTORY + prefix + 3 * 19 + 5..GUARD_DIRECTORY + prefix + 4 * 19].fill(0xff);
    let image = Image::parse(bytes).unwrap();
    assert_eq!(
        image.function_starts().into_iter().collect::<Vec<_>>(),
        [0x180001000, 0x180001010, 0x180001020]
    );
    assert_eq!(
        image.indirect_entries().into_iter().collect::<Vec<_>>(),
        [0x180001000, 0x180001010, 0x180001020]
    );
}

#[test]
fn guard_entries_exclude_non_code_zero_and_out_of_map_addresses() {
    let bytes = guarded(0x20b, 5, &[(0x2000, 0), (0, 0), (0x1000, 0), (u32::MAX, 0)]);
    let image = Image::parse(bytes).unwrap();
    assert_eq!(
        image.function_starts().into_iter().collect::<Vec<_>>(),
        [0x180001000]
    );
}

#[test]
fn invalid_guard_directories_do_not_promote_targets() {
    for magic in [0x10b, 0x20b] {
        let valid = guarded(magic, 4, &[(0x1000, 0)]);
        let (dirs, table, count, flags, prefix) = guard_layout(magic);
        for fault in [
            "absent flag",
            "short directory",
            "short structure",
            "huge count",
            "unmapped table",
            "truncated entry",
            "unbacked directory",
        ] {
            let mut bytes = valid.clone();
            match fault {
                "absent flag" => dword(&mut bytes, GUARD_DIRECTORY + flags, 0),
                "short directory" => dword(&mut bytes, dirs + 10 * 8 + 4, (prefix - 1) as u32),
                "short structure" => dword(&mut bytes, GUARD_DIRECTORY, (prefix - 1) as u32),
                "huge count" if magic == 0x20b => {
                    qword(&mut bytes, GUARD_DIRECTORY + count, u64::MAX)
                }
                "huge count" => dword(&mut bytes, GUARD_DIRECTORY + count, u32::MAX),
                "unmapped table" | "truncated entry" => {
                    let address = base_of(&bytes)
                        + if fault == "unmapped table" {
                            0x9000
                        } else {
                            0x23fd
                        };
                    if magic == 0x20b {
                        qword(&mut bytes, GUARD_DIRECTORY + table, address);
                    } else {
                        dword(&mut bytes, GUARD_DIRECTORY + table, address as u32);
                    }
                }
                "unbacked directory" => bytes.truncate(GUARD_DIRECTORY + prefix - 1),
                _ => unreachable!(),
            }
            let image = Image::parse(bytes).unwrap();
            assert!(image.function_starts().is_empty(), "{magic:x}: {fault}");
            assert!(image.indirect_entries().is_empty(), "{magic:x}: {fault}");
        }
    }
}
