//! ELF: imports and relative relocations from the dynamic relocations,
//! `.eh_frame` unwind entries, `DT_INIT`/`DT_FINI`, `PT_GNU_RELRO`.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use object::{
    Object, ObjectKind, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationFlags,
    RelocationTarget, SectionFlags,
    read::elf::{FileHeader, ProgramHeader},
};

use crate::{Memory, Parts, Pointers};

pub(crate) fn parts(file: &object::File, mem: &Memory) -> Parts {
    use object::Architecture as A;
    let arch = file.architecture();
    let is_copy = |f: RelocationFlags| match (arch, f) {
        (A::X86_64, RelocationFlags::Elf { r_type }) => r_type == object::elf::R_X86_64_COPY,
        (A::Aarch64, RelocationFlags::Elf { r_type }) => r_type == object::elf::R_AARCH64_COPY,
        _ => false,
    };
    let mut imports = BTreeMap::new();
    let mut data: BTreeMap<u64, (String, u64)> = BTreeMap::new();
    if let (Some(relocs), Some(dynsyms)) = (file.dynamic_relocations(), file.dynamic_symbol_table())
    {
        for (slot, reloc) in relocs {
            if let RelocationTarget::Symbol(i) = reloc.target()
                && let Ok(sym) = dynsyms.symbol_by_index(i)
                && let Ok(name) = sym.name()
                && !name.is_empty()
            {
                // Copied data (a `FILE *` like stdout): defined here, filled
                // by the dynamic linker; the C names it, linking the host's.
                if is_copy(reloc.flags()) {
                    data.insert(slot, (name.to_owned(), sym.size()));
                } else if !sym.is_definition() {
                    imports.insert(slot, name.to_owned());
                }
            }
        }
    }
    let (relocated, symbolic) = dynamic_relocations(file, mem);
    let pointers = match file.kind() {
        ObjectKind::Dynamic => Pointers::Listed(relocated.values().copied().collect()),
        ObjectKind::Executable => Pointers::Scan(
            mem.segments
                .iter()
                .map(|s| s.addr..s.addr + s.file.len() as u64)
                .collect(),
        ),
        _ => Pointers::Listed(Vec::new()),
    };
    Parts {
        os: "linux",
        entry: file.entry(),
        main: None,
        imports,
        data,
        function_ranges: unwind_ranges(file, mem),
        guard_functions: BTreeSet::new(),
        init_fini: init_fini(file, mem),
        pointers,
        relocated,
        symbolic,
        read_only: program_header(file, object::elf::PT_GNU_RELRO)
            .map(|(addr, size)| addr..addr + size)
            .into_iter()
            .collect(),
    }
}

/// Function ranges of the `.eh_frame` entries, found by section name or,
/// without a section table, through the `PT_GNU_EH_FRAME` header.
fn unwind_ranges(file: &object::File, mem: &Memory) -> Vec<Range<u64>> {
    let endian = if mem.little {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let (addr, data) = match file.section_by_name(".eh_frame") {
        Some(s) => match s.data() {
            Ok(d) => (s.address(), d),
            Err(_) => return Vec::new(),
        },
        None => {
            let Some((hdr, _)) = program_header(file, object::elf::PT_GNU_EH_FRAME) else {
                return Vec::new();
            };
            let Some(hdr_data) = mem.tail(hdr) else {
                return Vec::new();
            };
            let bases = gimli::BaseAddresses::default().set_eh_frame_hdr(hdr);
            let parsed = gimli::EhFrameHdr::new(hdr_data, endian).parse(&bases, mem.word as u8);
            let Ok(gimli::Pointer::Direct(addr)) = parsed.map(|p| p.eh_frame_ptr()) else {
                return Vec::new();
            };
            match mem.tail(addr) {
                Some(d) => (addr, d),
                None => return Vec::new(),
            }
        }
    };
    use gimli::UnwindSection;
    let mut eh = gimli::EhFrame::new(data, endian);
    eh.set_address_size(mem.word as u8);
    let bases = gimli::BaseAddresses::default().set_eh_frame(addr);
    let mut out = Vec::new();
    let mut entries = eh.entries(&bases);
    // A malformed entry ends the walk; what came before stands.
    while let Ok(Some(entry)) = entries.next() {
        if let gimli::CieOrFde::Fde(partial) = entry
            && let Ok(fde) = partial.parse(|s, b, o| s.cie_from_offset(b, o))
            && fde.len() > 0
        {
            out.push(fde.initial_address()..fde.initial_address() + fde.len());
        }
    }
    out
}

/// Address and memory size of the first ELF program header of type `ty`.
fn program_header(file: &object::File, ty: object::elf::ProgramType) -> Option<(u64, u64)> {
    fn find<Elf: FileHeader<Endian = object::Endianness>>(
        f: &object::read::elf::ElfFile<'_, Elf>,
        ty: object::elf::ProgramType,
    ) -> Option<(u64, u64)> {
        let endian = f.endian();
        f.elf_program_headers()
            .iter()
            .find(|ph| ph.p_type(endian) == ty)
            .map(|ph| (ph.p_vaddr(endian).into(), ph.p_memsz(endian).into()))
    }
    match file {
        object::File::Elf64(f) => find(f, ty),
        object::File::Elf32(f) => find(f, ty),
        _ => None,
    }
}

/// The `DT_INIT` and `DT_FINI` functions: run by the dynamic linker, and
/// named nowhere else.
fn init_fini(file: &object::File, mem: &Memory) -> Vec<u64> {
    let Some((addr, size)) = program_header(file, object::elf::PT_DYNAMIC) else {
        return Vec::new();
    };
    let w = mem.word as u64;
    let mut out = Vec::new();
    let tag = |t: object::elf::DynamicTag| Some(t.0 as u64);
    for a in (addr..addr.saturating_add(size)).step_by(2 * mem.word) {
        let t = mem.word_at(a);
        if t.is_none() || t == tag(object::elf::DT_NULL) {
            break;
        }
        if t == tag(object::elf::DT_INIT) || t == tag(object::elf::DT_FINI) {
            // Hostile `p_vaddr` near `u64::MAX` must not wrap the slot.
            out.extend(a.checked_add(w).and_then(|slot| mem.word_at(slot)));
        }
    }
    out
}

/// The dynamic relocations: words set to load base + constant (the
/// addresses a position-independent image stores; `R_*_RELATIVE` and packed
/// `SHT_RELR` relocations) with their value at the link address, and the
/// words set from symbols.
fn dynamic_relocations(file: &object::File, mem: &Memory) -> (BTreeMap<u64, u64>, BTreeSet<u64>) {
    use object::Architecture as A;
    let mut relocated = BTreeMap::new();
    let mut symbolic = BTreeSet::new();
    let relative = match file.architecture() {
        A::X86_64 => object::elf::R_X86_64_RELATIVE,
        A::Aarch64 => object::elf::R_AARCH64_RELATIVE,
        _ => return (relocated, symbolic),
    };
    for (slot, r) in file.dynamic_relocations().into_iter().flatten() {
        if r.flags() != (RelocationFlags::Elf { r_type: relative }) {
            symbolic.insert(slot);
        } else if r.has_implicit_addend() {
            relocated.extend(mem.word_at(slot).map(|v| (slot, v)));
        } else {
            relocated.insert(slot, r.addend() as u64);
        }
    }
    // RELR: an address word, then bitmaps of which of the following words
    // are relocated too; the addends are in place.
    for s in file.sections() {
        let SectionFlags::Elf { sh_type, .. } = s.flags() else {
            continue;
        };
        if sh_type != object::elf::SHT_RELR {
            continue;
        }
        let Ok(data) = s.data() else { continue };
        let w = mem.word as u64;
        let mut next = 0;
        for chunk in data.chunks_exact(mem.word) {
            let entry = mem.decode(chunk);
            if entry & 1 == 0 {
                relocated.extend(mem.word_at(entry).map(|v| (entry, v)));
                next = entry.saturating_add(w);
            } else {
                let bits = w * 8 - 1;
                for i in 0..bits {
                    // `i * w` is bounded (`i < bits <= 63`, `w <= 8`), but a
                    // hostile base `next` could wrap: skip that slot.
                    if entry >> (i + 1) & 1 != 0
                        && let Some(slot) = next.checked_add(i * w)
                    {
                        relocated.extend(mem.word_at(slot).map(|v| (slot, v)));
                    }
                }
                next = next.saturating_add(bits * w);
            }
        }
    }
    (relocated, symbolic)
}
