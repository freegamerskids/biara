//! guest architecture and operating system, entry point, mapped segments,
//! symbols, imports, and what locates functions without symbols (unwind
//! information, function lists, code pointers stored in data). The
//! format-specific parts are in `elf`, `pe` and `macho`.
//! PC validity ranges, plus function-entry formal-parameter registers
//! (`debug_names`) and declared type spellings (`StackObject::type_name`).
//! Unsupported locations remain unknown, never inferred from a function's
//! frame size; ambiguous register/name evidence is dropped, never forced.

mod dwarf;
mod elf;
mod macho;
mod pe;
mod xz;

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Deref, Range},
    path::Path,
};

use object::{
    BinaryFormat, Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionKind, SegmentFlags,
    SymbolKind,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] object::Error),
    #[error("unsupported architecture {0:?}")]
    Arch(object::Architecture),
    #[error("unsupported format {0:?}")]
    Format(BinaryFormat),
    #[error("malformed image: {0}")]
    Malformed(&'static str),
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub addr: u64,
    /// Mapped size; bytes past the file data read as zero.
    pub size: u64,
    pub exec: bool,
    pub write: bool,
    file: Range<usize>,
}

impl Segment {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr - self.addr < self.size
    }
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub is_function: bool,
}

/// A whole declared variable, not a struct member or an inferred frame slot.
/// `type_name` is the declared type spelling or a conservative description
/// (arrays with known bounds, aggregates with members, function pointers);
/// `None` means the type was missing, unsupported, recursive, or too large.
/// It never changes offsets: evidence for naming only.
#[derive(Clone, Debug, serde::Serialize)]
pub struct StackObject {
    pub function: u64,
    /// PCs at which both the lexical scope and location description apply.
    pub range: Range<u64>,
    pub name: String,
    /// Byte offset from the stack pointer on entry to `function`.
    pub offset: i64,
    pub size: u64,
    pub type_name: Option<String>,
}

/// A formal parameter's register at function entry, from DWARF.
/// `register` is the DWARF register number, not an architecture name; the
/// parent maps it architecturally. Only a direct single `DW_OP_regN`
/// location whose range covers the function entry qualifies; `DW_OP_entry_value`
/// and other compositions are rejected unless proven to be the entry register.
/// Names may be inherited from declarations, never locations. Ambiguous
/// names/registers within a function are dropped. `type_name` mirrors
/// `StackObject::type_name`; `None` is explicit unknown.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DebugName {
    pub function: u64,
    pub register: u16,
    pub name: String,
    pub type_name: Option<String>,
}

/// Optional debug metadata never prevents loading an otherwise valid image.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DebugStatus {
    pub present: bool,
    /// Location descriptions that could not prove a contiguous stack object.
    pub unsupported_locations: u64,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub struct Image {
    /// QEMU target name of the guest architecture (`libtcg-<arch>.so`).
    pub arch: &'static str,
    /// The operating system the image is for, which fixes its calling
    /// conventions (`biara_cfg::spec`): `"linux"` (ELF), `"windows"` (PE),
    /// `"darwin"` (Mach-O).
    pub os: &'static str,
    pub entry: u64,
    /// `main`, when the loader calls it directly with `argc`, `argv` and
    /// `envp` (Mach-O `LC_MAIN`); then also the entry point.
    pub main: Option<u64>,
    pub segments: Vec<Segment>,
    /// Defined symbols from the static and dynamic tables, sorted by
    /// address. Mach-O names lose the leading underscore C names get.
    pub symbols: Vec<Symbol>,
    pub stack_objects: Vec<StackObject>,
    /// Formal parameters live in registers at function entry, by DWARF
    /// register number: precise facts only, never guesses.
    pub debug_names: Vec<DebugName>,
    pub debug_status: DebugStatus,
    /// Imported symbols by the address of the pointer the dynamic linker
    /// fills in (GOT or IAT slot): the target of `jmp *slot` / `call *slot`.
    pub imports: BTreeMap<u64, String>,
    /// Copied data by address: `R_*_COPY` (`FILE *` stdout), defined here
    /// and filled by the dynamic linker, with its size. The C names them,
    /// linking the host's.
    pub data: BTreeMap<u64, (String, u64)>,
    /// Address ranges holding code: the executable sections, or the
    /// executable segments when there is no section table.
    pub code: Vec<Range<u64>>,
    /// Function bodies the image lists apart from symbols, sorted by
    /// start: unwind entries (ELF `.eh_frame`, PE `.pdata`) or Mach-O's
    /// `LC_FUNCTION_STARTS` (each up to the next start). Present in most
    /// stripped binaries.
    pub function_ranges: Vec<Range<u64>>,
    /// Executable function starts listed by PE Guard CF metadata, as absolute
    /// addresses; empty for ELF/Mach-O. Suppression flags do not erase the
    /// functions or prove their calling context. No extents are inferred.
    pub guard_functions: BTreeSet<u64>,
    /// Functions the loader runs besides the entry point: `DT_INIT` and
    /// `DT_FINI`.
    pub init_fini: Vec<u64>,
    /// Addresses in `code` that data holds: targets of relocations (ELF
    /// relative, PE base, Mach-O chained rebase) where the image has them,
    /// otherwise pointer-sized words of mapped data. Function pointers, but
    /// also labels and coincidental integers.
    pub code_pointers: BTreeSet<u64>,
    /// Words the dynamic linker sets to load base + constant, by address:
    /// their value with the image at its link address.
    relocated: BTreeMap<u64, u64>,
    /// Words the dynamic linker sets from symbols (imports): unknown.
    symbolic: BTreeSet<u64>,
    /// Writable in the file, read-only once relocated (`PT_GNU_RELRO`,
    /// Mach-O `__DATA_CONST`).
    read_only: Vec<Range<u64>>,
    word: usize,
    little: bool,
    bytes: ImageBytes,
}

#[derive(Debug)]
enum ImageBytes {
    Owned(Vec<u8>),
    Mapped(memmap2::Mmap),
}

impl Deref for ImageBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(bytes) => bytes,
        }
    }
}

/// What a format's own structures tell (`elf::parts`, `pe::parts`,
/// `macho::parts`).
struct Parts {
    os: &'static str,
    entry: u64,
    main: Option<u64>,
    imports: BTreeMap<u64, String>,
    data: BTreeMap<u64, (String, u64)>,
    function_ranges: Vec<Range<u64>>,
    guard_functions: BTreeSet<u64>,
    init_fini: Vec<u64>,
    pointers: Pointers,
    relocated: BTreeMap<u64, u64>,
    symbolic: BTreeSet<u64>,
    read_only: Vec<Range<u64>>,
}

/// Where code pointers stored in data are.
enum Pointers {
    /// Known from relocations: their values.
    Listed(Vec<u64>),
    /// Unknown: every aligned word in these ranges (outside code and
    /// import slots) may be one.
    Scan(Vec<Range<u64>>),
}

impl Image {
    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::parse(std::fs::read(path)?)
    }

    /// Map an immutable image snapshot without copying its bytes per worker.
    ///
    /// # Safety
    /// The file must not be modified or truncated while this image exists.
    /// Analysis workers use content-addressed snapshots, not mutable originals.
    pub unsafe fn map(path: &Path) -> Result<Self, Error> {
        let file = std::fs::File::open(path)?;
        let bytes = unsafe { memmap2::MmapOptions::new().map(&file)? };
        Self::from_bytes(ImageBytes::Mapped(bytes))
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_bytes(ImageBytes::Owned(bytes))
    }

    fn from_bytes(bytes: ImageBytes) -> Result<Self, Error> {
        let file = object::File::parse(&*bytes)?;
        let arch = qemu_arch(file.architecture())?;
        let macho = file.format() == BinaryFormat::MachO;

        let segments: Vec<Segment> = file
            .segments()
            .filter(|s| s.size() > 0 && is_read(s.flags()))
            .map(|s| {
                let (off, len) = s.file_range();
                // A declared file range can point past the end of a truncated
                // or hostile input: only file-backed bytes are addressable.
                let file = if len == 0 {
                    0..0
                } else {
                    let end = off
                        .checked_add(len)
                        .filter(|&end| end <= bytes.len() as u64)
                        .ok_or(Error::Malformed("segment data outside file"))?;
                    off as usize..end as usize
                };
                s.address()
                    .checked_add(s.size())
                    .ok_or(Error::Malformed("segment address overflow"))?;
                Ok(Segment {
                    addr: s.address(),
                    size: s.size(),
                    exec: is_exec(s.flags()),
                    write: is_write(s.flags()),
                    file,
                })
            })
            .collect::<Result<_, Error>>()?;

        let mut symbols: Vec<Symbol> = file
            .symbols()
            .chain(file.dynamic_symbols())
            .filter(|s| s.is_definition() && s.address() != 0)
            .filter_map(|s| {
                let name = s.name().ok().filter(|n| !n.is_empty())?;
                let name = if macho { macho::c_name(name) } else { name };
                Some(Symbol {
                    name: name.to_owned(),
                    addr: s.address(),
                    size: s.size(),
                    is_function: s.kind() == SymbolKind::Text,
                })
            })
            .collect();
        symbols.extend(debugdata_symbols(&file));
        symbols.sort_by(|a, b| (a.addr, &a.name).cmp(&(b.addr, &b.name)));
        symbols.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);

        let mut code: Vec<Range<u64>> = file
            .sections()
            .filter(|s| s.kind() == SectionKind::Text && s.address() != 0 && s.size() > 0)
            .map(|s| {
                let end = s
                    .address()
                    .checked_add(s.size())
                    .ok_or(Error::Malformed("code section address overflow"))?;
                Ok(s.address()..end)
            })
            .collect::<Result<_, Error>>()?;
        if code.is_empty() {
            code = segments
                .iter()
                .filter(|s| s.exec)
                // Segments are built with checked bounds, so this cannot wrap.
                .map(|s| s.addr..s.addr.saturating_add(s.size))
                .collect();
        }
        code.sort_by_key(|r| r.start);

        let mem = Memory {
            segments: &segments,
            bytes: &bytes,
            word: if file.is_64() { 8 } else { 4 },
            little: file.is_little_endian(),
        };
        let parts = match &file {
            object::File::Elf32(_) | object::File::Elf64(_) => elf::parts(&file, &mem),
            object::File::Pe32(f) => pe::parts(f, &mem),
            object::File::Pe64(f) => pe::parts(f, &mem),
            object::File::MachO64(f) => macho::parts(f, &mem, &code)?,
            _ => return Err(Error::Format(file.format())),
        };
        if matches!(file.format(), BinaryFormat::Pe) {
            // Forwarders refer to another image; data exports are not entries.
            // Ordinal-only code exports still need an addressable identity.
            if let Ok(exports) = file.exports() {
                for export in exports.flatten() {
                    let object::ExportTarget::Address { address } = export.target() else {
                        continue;
                    };
                    if !code.iter().any(|range| range.contains(&address)) {
                        continue;
                    }
                    let name = match export.name() {
                        object::NameOrOrdinal::Name(name) => {
                            String::from_utf8_lossy(name).into_owned()
                        }
                        object::NameOrOrdinal::Ordinal(ordinal) => format!("ordinal_{ordinal}"),
                    };
                    if !name.is_empty() {
                        symbols.push(Symbol {
                            name,
                            addr: address,
                            size: 0,
                            is_function: true,
                        });
                    }
                }
            }
            symbols.sort_by(|a, b| (a.addr, &a.name).cmp(&(b.addr, &b.name)));
            symbols.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);
        }
        let mut function_ranges = parts.function_ranges;
        function_ranges.sort_by_key(|r| (r.start, r.end));
        let in_code = |a: u64| code.iter().any(|r| r.contains(&a));
        let code_pointers = match parts.pointers {
            Pointers::Listed(v) => v,
            Pointers::Scan(ranges) => data_words(&mem, &ranges, &|a| {
                in_code(a) || parts.symbolic.contains(&a)
            }),
        }
        .into_iter()
        .filter(|&a| in_code(a))
        .collect();
        let (word, little) = (mem.word, mem.little);
        let (debug, debug_status) = dwarf::read(&file);

        Ok(Self {
            arch,
            os: parts.os,
            entry: parts.entry,
            main: parts.main,
            segments,
            symbols,
            stack_objects: debug.stack_objects,
            debug_names: debug.names,
            debug_status,
            imports: parts.imports,
            data: parts.data,
            code,
            function_ranges,
            guard_functions: parts.guard_functions,
            init_fini: parts.init_fini,
            code_pointers,
            relocated: parts.relocated,
            symbolic: parts.symbolic,
            read_only: parts.read_only,
            word,
            little,
            bytes,
        })
    }

    /// The enclosing declared variable at this PC and entry-SP-relative
    /// address. Conflicting overlapping declarations are unknown; choosing
    /// the smallest overlap would incorrectly turn fields into whole objects.
    pub fn stack_object(
        &self,
        function: u64,
        pc: u64,
        entry_sp_offset: i64,
    ) -> Option<&StackObject> {
        let mut found: Option<&StackObject> = None;
        for object in &self.stack_objects {
            if object.function != function || !object.range.contains(&pc) {
                continue;
            }
            let displacement = i128::from(entry_sp_offset) - i128::from(object.offset);
            if displacement < 0 || displacement >= i128::from(object.size) {
                continue;
            }
            if let Some(previous) = found {
                if previous.offset != object.offset
                    || previous.size != object.size
                    || previous.name != object.name
                {
                    return None;
                }
            } else {
                found = Some(object);
            }
        }
        found
    }

    /// Whether `addr` lies in `code`.
    pub fn is_code(&self, addr: u64) -> bool {
        let i = self.code.partition_point(|r| r.start <= addr);
        i > 0 && self.code[i - 1].contains(&addr)
    }

    /// Where functions are known to start: the entry point, `DT_INIT` and
    /// `DT_FINI`, function symbols, `function_ranges`, and PE `guard_functions`.
    pub fn function_starts(&self) -> BTreeSet<u64> {
        let symbols = self.symbols.iter().filter(|s| s.is_function);
        // Shared libraries without an entry point have 0 there.
        std::iter::once(self.entry)
            .filter(|&e| self.is_code(e))
            .chain(self.init_fini.iter().copied())
            .chain(symbols.map(|s| s.addr))
            .chain(self.function_ranges.iter().map(|r| r.start))
            .chain(self.guard_functions.iter().copied())
            .collect()
    }

    /// Potential non-direct entries, not a runtime CFG permission set: the
    /// entry point, `DT_INIT`/`DT_FINI`, data code pointers and PE GFIDs.
    /// Keep suppressed GFIDs conservative: eligibility can change at runtime.
    /// Addresses taken by code are the CFG's to see; exports enter from peers.
    pub fn indirect_entries(&self) -> BTreeSet<u64> {
        std::iter::once(self.entry)
            .filter(|&e| self.is_code(e))
            .chain(self.init_fini.iter().copied())
            .chain(self.code_pointers.iter().copied())
            .chain(self.guard_functions.iter().copied())
            .collect()
    }

    /// Known function bodies: `function_ranges` and sized function
    /// symbols, sorted by start. An address strictly inside one is not a
    /// function entry.
    pub fn function_extents(&self) -> Vec<Range<u64>> {
        let symbols = self
            .symbols
            .iter()
            .filter(|s| s.is_function && s.size > 0)
            // Symbols report their own sizes; a hostile size near `u64::MAX`
            // must saturate into an end-clamped extent, never wrap.
            .map(|s| s.addr..s.addr.saturating_add(s.size));
        let mut v: Vec<Range<u64>> = self
            .function_ranges
            .iter()
            .cloned()
            .chain(symbols)
            .collect();
        v.sort_by_key(|r| (r.start, r.end));
        v.dedup();
        v
    }

    pub fn segment_at(&self, addr: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(addr))
    }

    /// File-backed bytes of `seg`, starting at `seg.addr`.
    pub fn data(&self, seg: &Segment) -> &[u8] {
        &self.bytes[seg.file.clone()]
    }

    /// For `addr` in `code`: the file-backed bytes of the executable segment
    /// containing it, and the address of their first byte.
    pub fn code_at(&self, addr: u64) -> Option<(&[u8], u64)> {
        if !self.is_code(addr) {
            return None;
        }
        let seg = self.segments.iter().find(|s| s.exec && s.contains(addr))?;
        Some((self.data(seg), seg.addr))
    }

    /// Copy memory at `addr` into `buf` as loaded at the link address:
    /// bytes past a segment's file data read as zero, relative relocations
    /// applied. False if any byte is unmapped.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        self.read_where(addr, buf, |_| true)
    }

    /// `read`, restricted to what the program cannot write and the dynamic
    /// linker fills in without symbols: what is read is what runs (jump
    /// tables, also relocated read-only-after-relocation ones; not imports'
    /// GOT or IAT entries).
    pub fn read_const(&self, addr: u64, buf: &mut [u8]) -> bool {
        let end = addr.saturating_add(buf.len() as u64);
        let read_only = self
            .read_only
            .iter()
            .any(|r| r.start <= addr && end <= r.end);
        let w = self.word as u64;
        if self
            .symbolic
            .range(addr.saturating_sub(w - 1)..end)
            .next()
            .is_some()
        {
            return false;
        }
        self.read_where(addr, buf, |s| !s.write || read_only)
    }

    fn read_where(&self, addr: u64, buf: &mut [u8], ok: impl Fn(&Segment) -> bool) -> bool {
        if !read_segments(&self.segments, &self.bytes, addr, buf, ok) {
            return false;
        }
        let w = self.word as u64;
        let end = addr.saturating_add(buf.len() as u64);
        for (&slot, &v) in self.relocated.range(addr.saturating_sub(w - 1)..end) {
            let bytes = if self.little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            };
            let bytes = if self.little {
                &bytes[..self.word]
            } else {
                &bytes[8 - self.word..]
            };
            for (i, &b) in bytes.iter().enumerate() {
                let a = slot + i as u64;
                if (addr..end).contains(&a) {
                    buf[(a - addr) as usize] = b;
                }
            }
        }
        true
    }

    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Function symbol starting exactly at `addr`.
    pub fn function_at(&self, addr: u64) -> Option<&Symbol> {
        let i = self.symbols.partition_point(|s| s.addr < addr);
        self.symbols[i..]
            .iter()
            .take_while(|s| s.addr == addr)
            .find(|s| s.is_function)
    }
}

fn read_segments(
    segments: &[Segment],
    bytes: &[u8],
    addr: u64,
    buf: &mut [u8],
    ok: impl Fn(&Segment) -> bool,
) -> bool {
    let Some(seg) = segments.iter().find(|s| s.contains(addr) && ok(s)) else {
        return false;
    };
    let off = addr - seg.addr;
    if buf.len() as u64 > seg.size - off {
        return false;
    }
    let data = bytes.get(seg.file.clone()).unwrap_or(&[]);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = data.get(off as usize + i).copied().unwrap_or(0);
    }
    true
}

/// Mapped memory while the image is being parsed.
struct Memory<'a> {
    segments: &'a [Segment],
    bytes: &'a [u8],
    /// Pointer size in bytes.
    word: usize,
    little: bool,
}

impl Memory<'_> {
    fn word_at(&self, addr: u64) -> Option<u64> {
        let mut buf = [0; 8];
        let buf = &mut buf[..self.word];
        read_segments(self.segments, self.bytes, addr, buf, |_| true).then(|| self.decode(buf))
    }

    fn decode(&self, b: &[u8]) -> u64 {
        let it = b.iter().map(|&x| u64::from(x));
        if self.little {
            it.rev().fold(0, |v, x| v << 8 | x)
        } else {
            it.fold(0, |v, x| v << 8 | x)
        }
    }

    /// File-backed bytes from `addr` to the end of its segment.
    fn tail(&self, addr: u64) -> Option<&[u8]> {
        let seg = self.segments.iter().find(|s| s.contains(addr))?;
        self.bytes[seg.file.clone()].get((addr - seg.addr) as usize..)
    }

    /// `len` file-backed bytes at `addr`, if one segment holds them all.
    /// Reads past a segment's file data are not zero-filled here: optional
    /// metadata must prove it is file-backed, not BSS-adjacent.
    fn slice(&self, addr: u64, len: u64) -> Option<&[u8]> {
        let len: usize = len.try_into().ok()?;
        let seg = self.segments.iter().find(|s| s.contains(addr))?;
        let off: usize = (addr - seg.addr).try_into().ok()?;
        let end = off.checked_add(len)?;
        if end as u64 > seg.size {
            return None;
        }
        self.bytes.get(seg.file.clone())?.get(off..end)
    }

    /// Whether `addr` is in an executable segment.
    fn is_exec(&self, addr: u64) -> bool {
        self.segments.iter().any(|s| s.exec && s.contains(addr))
    }
}

/// Aligned pointer-sized words of mapped data in `ranges`, except at
/// addresses `skip` rejects: where an image without pointer relocations
/// keeps its pointers.
fn data_words(mem: &Memory, ranges: &[Range<u64>], skip: &dyn Fn(u64) -> bool) -> Vec<u64> {
    let mut out = Vec::new();
    let w = mem.word as u64;
    for r in ranges {
        // Align without `next_multiple_of` (which wraps on overflow): a
        // hostile range near `u64::MAX` skips instead of panicking.
        let mut a = match r.start.checked_add(w - 1) {
            Some(x) => x / w * w,
            None => continue,
        };
        loop {
            let Some(next) = a.checked_add(w) else { break };
            if next > r.end {
                break;
            }
            if !skip(a)
                && let Some(v) = mem.word_at(a)
            {
                out.push(v);
            }
            a = next;
        }
    }
    out
}

/// Function symbols from Fedora-style `.gnu_debugdata` (an XZ-compressed
/// ELF carrying the stripped symtab): `mini_debuginfo`'s reason to exist.
/// Empty when absent, corrupt, or absurdly large; never fails the load.
fn debugdata_symbols(file: &object::File) -> Vec<Symbol> {
    use std::borrow::Cow;
    let Some(section) = file.section_by_name(".gnu_debugdata") else {
        return Vec::new();
    };
    // `object` hands XZ back untouched; anything else it already decoded.
    let data: Cow<'_, [u8]> = match section.uncompressed_data() {
        Ok(d) if d.len() != section.size() as usize => d,
        _ => {
            let Ok(raw) = section.data() else {
                return Vec::new();
            };
            let mut out = Vec::new();
            if !xz::decode(raw, &mut out, 64 << 20) {
                return Vec::new();
            }
            Cow::Owned(out)
        }
    };
    symbols_of(&data)
}

/// Function definitions of an in-memory ELF image.
fn symbols_of(bytes: &[u8]) -> Vec<Symbol> {
    let Ok(file) = object::File::parse(bytes) else {
        return Vec::new();
    };
    file.symbols()
        .chain(file.dynamic_symbols())
        .filter(|s| s.is_definition() && s.address() != 0)
        .filter_map(|s| {
            let name = s.name().ok().filter(|n| !n.is_empty())?;
            Some(Symbol {
                name: name.to_owned(),
                addr: s.address(),
                size: s.size(),
                is_function: s.kind() == SymbolKind::Text,
            })
        })
        .collect()
}

fn qemu_arch(a: object::Architecture) -> Result<&'static str, Error> {
    use object::Architecture as A;
    Ok(match a {
        A::X86_64 => "x86_64",
        A::I386 => "i386",
        A::Aarch64 => "aarch64",
        A::Arm => "arm",
        A::Riscv64 => "riscv64",
        A::Riscv32 => "riscv32",
        A::Mips => "mips",
        A::Mips64 => "mips64",
        A::PowerPc => "ppc",
        A::PowerPc64 => "ppc64",
        A::S390x => "s390x",
        A::LoongArch64 => "loongarch64",
        A::Sparc64 => "sparc64",
        other => return Err(Error::Arch(other)),
    })
}

/// Mapped at all: not Mach-O's `__PAGEZERO`, which only reserves the low
/// addresses.
fn is_read(flags: SegmentFlags) -> bool {
    match flags {
        SegmentFlags::MachO { initprot, .. } => initprot.0 != 0,
        _ => true,
    }
}

fn is_exec(flags: SegmentFlags) -> bool {
    match flags {
        SegmentFlags::Elf { p_flags, .. } => p_flags.0 & object::elf::PF_X.0 != 0,
        SegmentFlags::MachO { initprot, .. } => initprot.0 & object::macho::VM_PROT_EXECUTE.0 != 0,
        SegmentFlags::Coff { characteristics } => {
            characteristics.0 & object::pe::IMAGE_SCN_MEM_EXECUTE.0 != 0
        }
        _ => false,
    }
}

fn is_write(flags: SegmentFlags) -> bool {
    match flags {
        SegmentFlags::Elf { p_flags, .. } => p_flags.0 & object::elf::PF_W.0 != 0,
        SegmentFlags::MachO { initprot, .. } => initprot.0 & object::macho::VM_PROT_WRITE.0 != 0,
        SegmentFlags::Coff { characteristics } => {
            characteristics.0 & object::pe::IMAGE_SCN_MEM_WRITE.0 != 0
        }
        _ => true,
    }
}
