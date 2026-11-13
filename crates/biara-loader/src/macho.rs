//! Mach-O: entry point and `main` from `LC_MAIN`, imports from indirect
//! symbol tables and chained-fixup binds, function starts from
//! `LC_FUNCTION_STARTS`, code pointers from chained-fixup rebases,
//! `__DATA_CONST` as read-only-after-relocation.
//!
//! The `object` crate's `entry()` misreads `LC_MAIN` (its `entryoff` is a
//! file offset, not an address); the load commands are read directly.
//!
//! Symbol-table names lose the leading underscore C names get, here and in
//! `lib.rs`; import names (from the indirect table / binds) are stripped
//! the same way so rules match `printf`, not `_printf`.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use object::{
    LittleEndian as LE, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    macho::{self, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_INFO_ONLY, LC_FUNCTION_STARTS, LC_MAIN},
    read::{
        ReadRef,
        macho::{DyldChainedImport, Fixup, MachOFile64, Section},
    },
};

use crate::{Memory, Parts, Pointers};

pub(crate) fn c_name(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

pub(crate) fn parts(
    file: &MachOFile64<object::Endianness>,
    mem: &Memory,
    code: &[Range<u64>],
) -> Result<Parts, crate::Error> {
    let endian = file.endian();
    let data = file.data();
    let mut commands = file.macho_load_commands().map_err(crate::Error::Parse)?;
    let (mut entry_off, main): (Option<u64>, Option<u64>) = (None, None);
    let (mut fixups_cmd, mut dyld_info, mut starts_cmd) = (None, None, None);
    let (mut dysymtab, mut text_addr) = (None, None);
    while let Ok(Some(command)) = commands.next() {
        if command.cmd() == LC_MAIN
            && let Ok(Some(ep)) = command.entry_point()
        {
            entry_off = Some(ep.entryoff.get(endian));
        }
        if command.cmd() == LC_DYLD_CHAINED_FIXUPS
            && let Ok(Some(cmd)) = command.dyld_chained_fixups()
        {
            fixups_cmd = Some(*cmd);
        }
        if command.cmd() == LC_DYLD_INFO_ONLY {
            dyld_info = Some(());
        }
        if command.cmd() == LC_FUNCTION_STARTS {
            starts_cmd = Some(command);
        }
        if dysymtab.is_none()
            && let Ok(Some(d)) = command.dysymtab()
        {
            dysymtab = Some(*d);
        }
        if text_addr.is_none()
            && let Ok(Some((seg, _))) = command.segment_64()
        {
            use object::read::macho::Segment as _;
            if seg.name() == b"__TEXT" {
                text_addr = Some(seg.vmaddr(endian));
            }
        }
    }
    // `LC_MAIN`'s offset is into the file: the address of its segment.
    let text: u64 = text_addr.unwrap_or(0);
    let entry = match entry_off {
        Some(off) => file_offset_addr(file, off).unwrap_or(text.wrapping_add(off)),
        None => file.entry(),
    };
    let _ = (main, mem, code);
    let main = (entry != 0).then_some(entry);
    // Indirect symbol table: (slot address, symbol index) for pointer
    // sections (stubs are code; their functions are seeded below).
    let mut indirect: BTreeMap<u64, u32> = BTreeMap::new();
    if let Some(dy) = dysymtab {
        let table: &[object::U32<LE, macho::IndirectSymbol>] = data
            .read_slice_at::<object::U32<LE, macho::IndirectSymbol>>(
                dy.indirectsymoff.get(endian).into(),
                dy.nindirectsyms.get(endian) as usize,
            )
            .unwrap_or(&[]);
        for section in file.sections() {
            let raw = section.macho_section();
            let ty = raw.section_type(endian);
            let ptr = matches!(
                ty,
                macho::S_NON_LAZY_SYMBOL_POINTERS
                    | macho::S_LAZY_SYMBOL_POINTERS
                    | macho::S_LAZY_DYLIB_SYMBOL_POINTERS
                    | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
            );
            if !ptr {
                continue;
            }
            let stride = mem.word as u64;
            let first = raw.reserved1(endian) as usize;
            let count = section.size() / stride;
            for i in 0..count {
                let Some(sym) = table.get(first + i as usize) else {
                    break;
                };
                if let Some(index) = sym.get(LE).index() {
                    indirect.insert(section.address().wrapping_add(i * stride), index);
                }
            }
        }
    }
    // Symbol names by index, for imports.
    let names: BTreeMap<u32, String> = file
        .symbols()
        .enumerate()
        .filter_map(|(i, s)| {
            let name = core::str::from_utf8(s.name_bytes().ok()?).ok()?;
            (!name.is_empty()).then(|| (i as u32, c_name(name).to_owned()))
        })
        .collect();
    let mut imports = BTreeMap::new();
    let mut symbolic = BTreeSet::new();
    // Stub addresses are code (their functions forward to the import);
    // pointer slots are the imports.
    let mut stubs = BTreeSet::new();
    for section in file.sections() {
        let ty = section.macho_section().section_type(endian);
        if ty != macho::S_SYMBOL_STUBS {
            continue;
        }
        let stride = section.macho_section().reserved2(endian) as u64;
        if stride == 0 {
            continue;
        }
        for i in 0..section.size() / stride {
            stubs.insert(section.address().wrapping_add(i * stride));
        }
    }
    for (&slot, &index) in &indirect {
        if let Some(name) = names.get(&index) {
            imports.insert(slot, name.clone());
        }
        symbolic.insert(slot);
    }
    let mut relocated = BTreeMap::new();
    let mut values = BTreeSet::new();
    let mut bound: BTreeMap<u32, String> = BTreeMap::new();
    if let Some(cmd) = fixups_cmd {
        let fixups = cmd
            .chained_fixups(endian, data)
            .map_err(crate::Error::Parse)?;
        for i in fixups.imports(endian).map_err(crate::Error::Parse)? {
            let Ok(i) = i else { continue };
            let DyldChainedImport { name, .. } = i;
            if let Ok(name) = core::str::from_utf8(name) {
                bound.insert(bound.len() as u32, c_name(name).to_owned());
            }
        }
        let segs: Vec<(u64, &[u8])> = file
            .segments()
            .filter_map(|s| {
                let (off, len) = s.file_range();
                // Hostile file ranges must not panic the loader: skip ranges
                // that are not file-backed instead of slicing blindly.
                let off: usize = off.try_into().ok()?;
                let len: usize = len.try_into().ok()?;
                Some((s.address(), data.get(off..)?.get(..len)?))
            })
            .collect();
        for seg in fixups.segments(endian).map_err(crate::Error::Parse)? {
            let Ok(seg) = seg else { continue };
            let Some(&(addr, bytes)) = segs.get(seg.index() as usize) else {
                continue;
            };
            for item in seg.fixups(endian, text, bytes) {
                let Ok((off, fix)) = item else { continue };
                let slot = addr.wrapping_add(off);
                match fix {
                    Fixup::Rebase(r) => {
                        let v = text.wrapping_add(r.target_offset);
                        relocated.insert(slot, v);
                        values.insert(v);
                    }
                    Fixup::Bind(b) => {
                        symbolic.insert(slot);
                        if let Some(name) = bound.get(&b.ordinal) {
                            imports.insert(slot, name.clone());
                        }
                    }
                    _ => {
                        symbolic.insert(slot);
                    }
                }
            }
        }
    } else {
        // Classic (non-chained) fixups need no walking: unlike chained
        // fixups, classic stores already hold link-address values, so the
        // word scan below sees the same pointers, and the indirect table
        // above already names every import slot (weak and lazy binds
        // included: they occupy GOT slots with indirect entries).
        let _ = &dyld_info;
    }
    // Function starts: each up to the next start (or the code's end).
    let mut starts = Vec::new();
    if let Some(cmd) = starts_cmd
        && let Ok(variant) = cmd.variant()
        && let object::read::macho::LoadCommandVariant::LinkeditData(linkedit) = variant
        && let Ok(iter) = linkedit.function_starts(endian, data, text)
    {
        for s in iter {
            let Ok(a) = s else { break };
            starts.push(a);
        }
    }
    starts.sort_unstable();
    starts.dedup();
    let ends: Vec<u64> = code.iter().map(|r| r.end).collect();
    let function_ranges: Vec<Range<u64>> = starts
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            let next = starts
                .get(i + 1)
                .copied()
                .unwrap_or_else(|| ends.iter().copied().find(|&e| e > s).unwrap_or(s.saturating_add(4)));
            s..next.max(s.saturating_add(4))
        })
        .collect();
    // `__DATA_CONST` is written by fixups, then made read-only.
    let read_only: Vec<Range<u64>> = file
        .sections()
        .filter_map(|s| {
            (s.segment_name() == Ok(Some("__DATA")) && s.name() == Ok("__const"))
                .then(|| s.address()..s.address().saturating_add(s.size()))
        })
        .collect();
    let scan: Vec<Range<u64>> = file
        .sections()
        .filter(|s| {
            !matches!(s.kind(), object::SectionKind::Text)
                && s.segment_name().is_ok_and(|n| n != Some("__LINKEDIT"))
        })
        .map(|s| s.address()..s.address().saturating_add(s.size()))
        .collect();
    let mut listed: Vec<u64> = values.into_iter().collect();
    listed.extend(indirect.keys().filter_map(|s| mem.word_at(*s)));
    listed.extend(stubs.iter().copied());
    Ok(Parts {
        os: "darwin",
        entry,
        main,
        imports,
        data: BTreeMap::new(),
        function_ranges,
        guard_functions: BTreeSet::new(),
        init_fini: Vec::new(),
        pointers: if fixups_cmd.is_some() {
            Pointers::Listed(listed)
        } else {
            Pointers::Scan(scan)
        },
        relocated,
        symbolic,
        read_only,
    })
}

/// The address file offset `off` has.
fn file_offset_addr(file: &MachOFile64<object::Endianness>, off: u64) -> Option<u64> {
    file.segments().find_map(|s| {
        let (start, len) = s.file_range();
        (start <= off && off < start.saturating_add(len))
            .then(|| s.address().saturating_add(off - start))
    })
}
