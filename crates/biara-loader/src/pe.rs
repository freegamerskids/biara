//! PE: imports (and delay-load imports), `.pdata` unwind entries, TLS
//! callbacks, Guard CF function tables, and relocated code pointers.
//!
//! RVAs become addresses by adding the image base (`optional_header`'s
//! `image_base`); `object`'s section addresses already include it.
//! Guard CF parsing accepts PE32/PE32+ revisions through GuardFlags, honours
//! the metadata stride, and requires the complete table to be file-backed.
//! Suppression metadata never erases functions; runtime CFG permissions are
//! not inferred by static recovery.
//!
//! IAT slots (written by the loader) are import slots, so `read_const`
//! refuses them; the import name follows the callee's base name.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use object::{
    Architecture, LittleEndian as LE, Object,
    pe::{
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_TLS,
        IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK,
        IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
        ImageLoadConfigDirectory32, ImageLoadConfigDirectory64,
    },
    read::pe::{ImageNtHeaders, ImageOptionalHeader, Import, ImportTable, PeFile},
};

use crate::{Memory, Parts, Pointers};

pub(crate) fn parts<Pe>(file: &PeFile<'_, Pe>, mem: &Memory) -> Parts
where
    Pe: ImageNtHeaders,
{
    let opt = file.nt_headers().optional_header();
    let base = opt.image_base();
    let entry = base.wrapping_add(opt.address_of_entry_point().into());
    let mut imports = BTreeMap::new();
    let mut symbolic = BTreeSet::new();
    if let Ok(Some(table)) = file.import_table() {
        collect::<Pe>(&table, base, &mut imports, &mut symbolic);
    }
    if let Ok(Some(table)) = file.delay_load_import_table() {
        collect_delay(&table, base, &mut imports, &mut symbolic);
    }
    let (relocated, pointers) = relocations(file, mem);
    let mut values: Vec<u64> = pointers.into_iter().collect();
    values.extend(relocated.values().copied());
    // `object` gives the IAT's file bytes, not its bound contents: with no
    // addresses, skip the IAT scan and only list named imports.
    Parts {
        os: "windows",
        entry,
        main: None,
        imports,
        data: BTreeMap::new(),
        function_ranges: pdata(file, mem),
        guard_functions: guard_functions(file, mem),
        init_fini: tls_callbacks(file, mem),
        pointers: Pointers::Listed(values),
        relocated,
        symbolic,
        read_only: Vec::new(),
    }
}

/// TLS callback slots contain virtual addresses, unlike the directory RVA.
/// Stop at the terminator or mapped-data boundary; corrupt metadata is optional.
fn tls_callbacks<Pe>(file: &PeFile<'_, Pe>, mem: &Memory) -> Vec<u64>
where
    Pe: ImageNtHeaders,
{
    let Some(dir) = file.data_directories().get(IMAGE_DIRECTORY_ENTRY_TLS) else {
        return Vec::new();
    };
    let callbacks_offset = 3 * mem.word;
    if (dir.size.get(LE) as usize) < callbacks_offset + mem.word {
        return Vec::new();
    }
    let base = file.nt_headers().optional_header().image_base();
    let Some(slot) = base
        .checked_add(u64::from(dir.virtual_address.get(LE)))
        .and_then(|address| address.checked_add(callbacks_offset as u64))
    else {
        return Vec::new();
    };
    let Some(mut table) = mem.word_at(slot) else {
        return Vec::new();
    };
    let mut callbacks = Vec::new();
    // A malicious unterminated table must not scan the whole image.
    for _ in 0..4096 {
        match mem.word_at(table) {
            Some(0) | None => break,
            Some(address) => callbacks.push(address),
        }
        let Some(next) = table.checked_add(mem.word as u64) else {
            break;
        };
        table = next;
    }
    callbacks
}

/// One import table's IAT slots: `first_thunk + i * word`.
fn collect<Pe>(
    table: &ImportTable,
    base: u64,
    imports: &mut BTreeMap<u64, String>,
    symbolic: &mut BTreeSet<u64>,
) where
    Pe: ImageNtHeaders,
{
    let Ok(mut descriptors) = table.descriptors() else {
        return;
    };
    let word = size_of::<Pe::ImageThunkData>() as u64;
    while let Ok(Some(d)) = descriptors.next() {
        let lookup = d.original_first_thunk.get(LE);
        let iat = u64::from(d.first_thunk.get(LE));
        let lookup = if lookup != 0 {
            lookup
        } else {
            d.first_thunk.get(LE)
        };
        let Ok(mut thunks) = table.thunks(lookup) else {
            continue;
        };
        let mut i = 0u64;
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            let slot = base.wrapping_add(iat).wrapping_add(i * word);
            match table.import::<Pe>(thunk) {
                Ok(Import::Name(_, name)) => {
                    if let Ok(name) = core::str::from_utf8(name)
                        && !name.is_empty()
                    {
                        imports.insert(slot, name.to_owned());
                    }
                    symbolic.insert(slot);
                }
                _ => {
                    // Ordinals have no name to match rules against.
                    symbolic.insert(slot);
                }
            }
            i += 1;
        }
    }
}

fn collect_delay(
    table: &object::read::pe::DelayLoadImportTable,
    base: u64,
    imports: &mut BTreeMap<u64, String>,
    symbolic: &mut BTreeSet<u64>,
) {
    let Ok(mut descriptors) = table.descriptors() else {
        return;
    };
    while let Ok(Some(d)) = descriptors.next() {
        let iat = d.import_address_table_rva.get(LE);
        let lookup = d.import_name_table_rva.get(LE);
        let lookup = if lookup != 0 { lookup } else { iat };
        let Ok(mut thunks) = table.thunks(lookup) else {
            continue;
        };
        // Delay-load thunks are 32-bit RVAs even in PE32+: parse with the
        // 32-bit headers.
        let mut i = 0u64;
        while let Ok(Some(thunk)) = thunks.next::<object::pe::ImageNtHeaders32>() {
            let slot = base.wrapping_add(iat as u64).wrapping_add(i * 4);
            match table.import::<object::pe::ImageNtHeaders32>(thunk) {
                Ok(Import::Name(_, name)) => {
                    if let Ok(name) = core::str::from_utf8(name)
                        && !name.is_empty()
                    {
                        imports.insert(slot, name.to_owned());
                    }
                    symbolic.insert(slot);
                }
                _ => {
                    symbolic.insert(slot);
                }
            }
            i += 1;
        }
    }
}

/// `.pdata` entries as `[begin, end)`: x64 `ImageRuntimeFunctionEntry`
/// triples; ARM64 8-byte records, or 12 bytes when the flag selects full
/// unwind data (flag 2, a fragment, only bounds the range).
fn pdata<Pe>(file: &PeFile<'_, Pe>, _mem: &Memory) -> Vec<Range<u64>>
where
    Pe: ImageNtHeaders,
{
    let Some(dir) = file.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Vec::new();
    };
    let size = dir.size.get(LE) as usize;
    let Some((file_off, _)) = file
        .section_table()
        .pe_file_range_at(dir.virtual_address.get(LE))
    else {
        return Vec::new();
    };
    let data = &file.data()[file_off as usize..][..size.min(1 << 20)];
    let mut out = Vec::new();
    let base = file.nt_headers().optional_header().image_base();
    // x64 uses 12-byte entries; ARM64 8 bytes unless flag 0 selects 12.
    // Decide by architecture.
    let is_arm64 = file.architecture() == Architecture::Aarch64;
    if is_arm64 {
        let mut i = 0;
        while i + 8 <= data.len() {
            let begin = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
            let xd = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
            let (len, stride) = match xd & 3 {
                1 => (u64::from((xd >> 2) & 0x7ff) * 4, 8),
                2 => (0, 8), // fragment: end unknown, keep the start
                _ => (u64::from(xd >> 14) * 8, 12),
            };
            let start = base.wrapping_add(begin as u64);
            out.push(start..start + len.max(4));
            i += stride;
        }
    } else {
        let mut i = 0;
        while i + 12 <= data.len() {
            let begin = u32::from_le_bytes(data[i..i + 4].try_into().unwrap_or([0; 4]));
            let end = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
            if begin == 0 && end == 0 {
                break;
            }
            out.push(base.wrapping_add(begin as u64)..base.wrapping_add(end as u64));
            i += 12;
        }
    }
    out
}

/// DIR64 (or HIGHLOW) base relocations: `(slot, value at the link address)`.
fn relocations<Pe>(file: &PeFile<'_, Pe>, mem: &Memory) -> (BTreeMap<u64, u64>, BTreeSet<u64>)
where
    Pe: ImageNtHeaders,
{
    let mut relocated = BTreeMap::new();
    let mut pointers = BTreeSet::new();
    let Ok(Some(blocks)) = file
        .data_directories()
        .relocation_blocks(file.data(), &file.section_table())
    else {
        return (relocated, pointers);
    };
    let want = if mem.word == 8 {
        IMAGE_REL_BASED_DIR64
    } else {
        IMAGE_REL_BASED_HIGHLOW
    };
    let base = file.nt_headers().optional_header().image_base();
    for block in blocks.flat_map(|b| b.ok()) {
        for r in block {
            if r.typ != want {
                continue;
            }
            let slot = base.wrapping_add(r.virtual_address as u64);
            if let Some(v) = mem.word_at(slot) {
                relocated.insert(slot, v);
                pointers.insert(v);
            }
        }
    }
    let _ = IMAGE_DIRECTORY_ENTRY_BASERELOC;
    (relocated, pointers)
}
/// Function starts from a complete, file-backed GFIDs table and a
/// size-validated load-configuration prefix. Entry metadata controls runtime
/// call eligibility, not the existence of these function starts.
fn guard_functions<Pe>(file: &PeFile<'_, Pe>, mem: &Memory) -> BTreeSet<u64>
where
    Pe: ImageNtHeaders,
{
    let empty = BTreeSet::new;
    let Some(dir) = file.data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) else {
        return empty();
    };
    let dir_rva = dir.virtual_address.get(LE);
    let dir_size = u64::from(dir.size.get(LE));
    if dir_rva == 0 || dir_size == 0 {
        return empty();
    }
    let base = file.nt_headers().optional_header().image_base();
    let Some(bytes) = file.section_table().pe_data_at(file.data(), dir_rva) else {
        return empty();
    };
    let (table_offset, count_offset, flags_offset) = if mem.word == 8 {
        (
            std::mem::offset_of!(ImageLoadConfigDirectory64, guard_cf_function_table),
            std::mem::offset_of!(ImageLoadConfigDirectory64, guard_cf_function_count),
            std::mem::offset_of!(ImageLoadConfigDirectory64, guard_flags),
        )
    } else {
        (
            std::mem::offset_of!(ImageLoadConfigDirectory32, guard_cf_function_table),
            std::mem::offset_of!(ImageLoadConfigDirectory32, guard_cf_function_count),
            std::mem::offset_of!(ImageLoadConfigDirectory32, guard_flags),
        )
    };
    // Older revisions need only the fields through GuardFlags, not the
    // complete current SDK structure. Both advertised sizes must cover them.
    let prefix = flags_offset + size_of::<u32>();
    let Some(load) = bytes.get(..prefix) else {
        return empty();
    };
    if dir_size < prefix as u64 || u64::from(u32_at(load, 0)) < prefix as u64 {
        return empty();
    }
    // The table address is a VA; the count is pointer-sized.
    let (table_va, count) = if mem.word == 8 {
        (u64_at(load, table_offset), u64_at(load, count_offset))
    } else {
        (
            u64::from(u32_at(load, table_offset)),
            u64::from(u32_at(load, count_offset)),
        )
    };
    let guard_flags = u32_at(load, flags_offset);
    if guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT.0 == 0 {
        return empty();
    }
    if count == 0 || table_va == 0 {
        return empty();
    }
    let stride = stride_of(guard_flags);
    let Some(table_size) = count.checked_mul(stride as u64) else {
        return empty();
    };
    // Mapped-file bounds: the whole table must be file-backed bytes of one
    // mapped segment. Truncated, out-of-map, and huge-count tables drop out
    // here without touching the count-sized allocation they ask for.
    let Some(table) = mem.slice(table_va, table_size) else {
        return empty();
    };
    let mut functions = BTreeSet::new();
    for entry in table.chunks_exact(stride) {
        let rva = u32_at(entry, 0);
        if rva == 0 {
            continue;
        }
        let Some(addr) = base.checked_add(u64::from(rva)) else {
            continue;
        };
        if !mem.is_exec(addr) {
            continue;
        }
        functions.insert(addr);
    }
    functions
}

/// Unaligned little-endian loads at `off` (the caller bounds `load`).
fn u32_at(load: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(load[off..off + 4].try_into().unwrap())
}

fn u64_at(load: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(load[off..off + 8].try_into().unwrap())
}

/// Entry stride from the `GuardFlags` high nibble: 4-byte RVA plus `n`
/// extra metadata bytes.
fn stride_of(guard_flags: u32) -> usize {
    4 + ((guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
        >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) as usize
}
