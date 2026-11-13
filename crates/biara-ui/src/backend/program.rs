//! The recovered program and the indexes every view queries.
//!
//! [`Program`] is immutable once recovery finishes and is shared by `Arc`, so the UI thread and
//! the decompiler thread read it without locks. [`Index`] holds what the views need that the
//! engine does not keep in one place: the function table with sizes, cross-references in both
//! directions, strings, and a name for every address that has one.

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
};

use biara_abi::FunctionAbi;
use biara_cfg::{Cfg, ExitKind};
use biara_loader::Image;
use biara_tcg::{Libtcg, Opcode, TempKind};
use parking_lot::Mutex;

use super::{
    demangle::{self, Demangled},
    disasm::Arch,
};

/// Everything recovery produced for one binary.
pub struct Program {
    pub path: PathBuf,
    pub arch: Arch,
    pub image: Arc<Image>,
    pub cfg: Arc<Cfg>,
    pub abis: Arc<BTreeMap<u64, FunctionAbi>>,
    pub index: Arc<Index>,
    pub listing: super::listing::Listing,
    pub(crate) lib: Arc<Mutex<Libtcg>>,
}

/// What a function table row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionKind {
    /// Code the binary defines.
    Normal,
    /// A PLT-style stub that forwards to an import.
    Stub,
}

/// One row of the function table.
#[derive(Clone, Debug)]
pub struct FunctionInfo {
    pub entry: u64,
    /// The name recovery could give it: a symbol, `import@plt`, or `sub_<addr>`.
    pub name: String,
    /// Bytes of code across its blocks.
    pub size: u64,
    pub blocks: u32,
    pub insns: u32,
    /// Distinct functions it calls.
    pub calls: u32,
    /// Call sites that reach it.
    pub callers: u32,
    pub returns: bool,
    pub kind: FunctionKind,
    /// Stack frame size in bytes, when the ABI analysis found one.
    pub frame: Option<u64>,
    /// Argument registers plus stack slots the ABI analysis found it reads.
    pub args: u32,
}

/// Why one address refers to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum XrefKind {
    Call,
    Jump,
    /// The instruction materialises the address (a pointer, `lea`, `adrp`).
    Data,
}

/// A reference from the instruction at `from` to `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Xref {
    pub from: u64,
    /// Entry of the function containing `from`, if any.
    pub function: u64,
    pub kind: XrefKind,
}

/// A string found in the image.
#[derive(Clone, Debug)]
pub struct StringEntry {
    pub addr: u64,
    /// Length in bytes in the image, terminator excluded.
    pub bytes: u32,
    pub wide: bool,
    pub text: String,
}

/// Longest string kept in full; longer ones are cut with an ellipsis for display.
const STRING_CAP: usize = 240;

/// A named import: the slot the dynamic linker fills and what it resolves to.
#[derive(Clone, Debug)]
pub struct ImportEntry {
    pub slot: u64,
    pub name: String,
    /// The readable form, if the name is mangled.
    pub demangled: Option<Demangled>,
}

/// The function table, cross-references and strings.
#[derive(Default)]
pub struct Index {
    /// Sorted by entry address.
    pub functions: Vec<FunctionInfo>,
    by_entry: HashMap<u64, usize>,
    /// Incoming references, keyed by target address, sorted by `from`.
    pub xrefs: BTreeMap<u64, Vec<Xref>>,
    pub strings: Vec<StringEntry>,
    pub imports: Vec<ImportEntry>,
    /// Names the binary itself gives addresses: symbols and `import@plt` stubs.
    names: HashMap<u64, String>,
    /// Readable forms of the mangled names in `names`.
    demangled: HashMap<u64, Demangled>,
    /// Block start -> entry of the function that owns it (lowest entry wins when shared).
    owners: HashMap<u64, u64>,
}

impl Index {
    /// The functions known before analysis: those named by symbols. Gives the UI something to
    /// list while recovery runs.
    pub fn preview(image: &Image) -> Index {
        let mut index = Index::default();
        for s in image.symbols.iter().filter(|s| s.is_function) {
            index.functions.push(FunctionInfo {
                entry: s.addr,
                name: s.name.clone(),
                size: s.size,
                blocks: 0,
                insns: 0,
                calls: 0,
                callers: 0,
                returns: true,
                kind: FunctionKind::Normal,
                frame: None,
                args: 0,
            });
        }
        index.functions.sort_by_key(|f| f.entry);
        index.functions.dedup_by_key(|f| f.entry);
        index.finish(image);
        index
    }

    /// Build the full index from a recovered program.
    pub fn build(image: &Image, cfg: &Cfg, abis: &BTreeMap<u64, FunctionAbi>) -> Index {
        let mut index = Index::default();
        for (&entry, f) in &cfg.functions {
            for &b in &f.blocks {
                index
                    .owners
                    .entry(b)
                    .and_modify(|o| *o = (*o).min(entry))
                    .or_insert(entry);
            }
        }
        let mut callers: HashMap<u64, u32> = HashMap::new();
        for block in cfg.blocks.values() {
            let site = block.insns.last().copied().unwrap_or(block.pc());
            let function = index.owners.get(&block.pc()).copied().unwrap_or(0);
            for exit in &block.exits {
                match exit.kind {
                    ExitKind::Call { target, .. } => {
                        index.add_xref(
                            target,
                            Xref {
                                from: site,
                                function,
                                kind: XrefKind::Call,
                            },
                        );
                        *callers.entry(target).or_default() += 1;
                    }
                    ExitKind::IndirectCall {
                        slot: Some(slot), ..
                    } => {
                        index.add_xref(
                            slot,
                            Xref {
                                from: site,
                                function,
                                kind: XrefKind::Call,
                            },
                        );
                    }
                    // A jump to another function's entry is a tail call; any other jump is
                    // control flow inside the function and a reference to a label. A jump to
                    // the next block is plain fallthrough and not worth a reference.
                    ExitKind::Jump(target) if target != block.end() => {
                        index.add_xref(
                            target,
                            Xref {
                                from: site,
                                function,
                                kind: XrefKind::Jump,
                            },
                        );
                    }
                    _ => {}
                }
            }
            index.scan_constants(image, block, function);
        }
        for xs in index.xrefs.values_mut() {
            xs.sort();
            xs.dedup();
        }
        for (&entry, f) in &cfg.functions {
            let blocks: Vec<_> = f.blocks.iter().filter_map(|b| cfg.blocks.get(b)).collect();
            let size = blocks.iter().map(|b| b.end() - b.pc()).sum();
            let insns = blocks.iter().map(|b| b.insns.len() as u32).sum();
            let stub = cfg.stub_import(entry);
            let abi = abis.get(&entry);
            let name = stub
                .map(|s| format!("{s}@plt"))
                .or_else(|| image.function_at(entry).map(|s| s.name.clone()))
                .unwrap_or_else(|| format!("sub_{entry:x}"));
            index.functions.push(FunctionInfo {
                entry,
                name,
                size,
                blocks: f.blocks.len() as u32,
                insns,
                calls: f.calls.len() as u32,
                callers: callers.get(&entry).copied().unwrap_or(0),
                returns: f.returns,
                kind: if stub.is_some() {
                    FunctionKind::Stub
                } else {
                    FunctionKind::Normal
                },
                frame: abi.map(|a| a.frame.size),
                args: abi.map_or(0, |a| {
                    (a.args.len() + a.stack_args.len() + a.fp_args.len()) as u32
                }),
            });
        }
        index.functions.sort_by_key(|f| f.entry);
        index.finish(image);
        index
    }

    fn add_xref(&mut self, to: u64, x: Xref) {
        self.xrefs.entry(to).or_default().push(x);
    }

    /// Record data references: constants an instruction materialises that point into the
    /// image. A TCG block carries the guest address of every `lea rip+x` / `adrp` as a
    /// constant operand, tagged with the instruction that uses it.
    fn scan_constants(&mut self, image: &Image, block: &biara_cfg::BasicBlock, function: u64) {
        let b = &block.block;
        let mut at = block.pc();
        for op in &b.ops {
            if op.opcode == Opcode::InsnStart {
                at = b.consts(op)[0];
                continue;
            }
            for &t in b.inputs(op) {
                let temp = b.temp(t);
                if temp.kind != TempKind::Const {
                    continue;
                }
                let value = temp.value as u64;
                if value < 0x1000 || image.segment_at(value).is_none() {
                    continue;
                }
                // The address of the next instruction (a pushed return address) and of the
                // block's own exit targets are control flow, not data.
                if value == b.end() || block.insns.contains(&value) {
                    continue;
                }
                if block
                    .exits
                    .iter()
                    .any(|e| exit_targets(e.kind).any(|t| t == value))
                {
                    continue;
                }
                self.add_xref(
                    value,
                    Xref {
                        from: at,
                        function,
                        kind: XrefKind::Data,
                    },
                );
            }
        }
    }

    fn finish(&mut self, image: &Image) {
        self.by_entry = self
            .functions
            .iter()
            .enumerate()
            .map(|(i, f)| (f.entry, i))
            .collect();
        for s in &image.symbols {
            if !s.name.is_empty() {
                self.names.entry(s.addr).or_insert_with(|| s.name.clone());
            }
        }
        for f in &self.functions {
            self.names.entry(f.entry).or_insert_with(|| f.name.clone());
        }
        self.imports = image
            .imports
            .iter()
            .map(|(&slot, name)| ImportEntry {
                slot,
                name: name.clone(),
                demangled: demangle::demangle(name),
            })
            .collect();
        for i in &self.imports {
            self.names
                .entry(i.slot)
                .or_insert_with(|| format!("{}@got", i.name));
        }
        self.demangled = self
            .names
            .iter()
            .filter_map(|(&addr, name)| Some((addr, demangle::demangle(name)?)))
            .collect();
        self.strings = find_strings(image);
    }

    /// The function table row for `entry`.
    pub fn function(&self, entry: u64) -> Option<&FunctionInfo> {
        self.by_entry.get(&entry).map(|&i| &self.functions[i])
    }

    /// Position of `entry` in [`Index::functions`].
    pub fn function_position(&self, entry: u64) -> Option<usize> {
        self.by_entry.get(&entry).copied()
    }

    /// The name the binary gives `addr`, if any.
    pub fn base_name(&self, addr: u64) -> Option<&str> {
        self.names.get(&addr).map(String::as_str)
    }

    /// The readable form of the mangled name at `addr`, if it has one.
    pub fn demangled(&self, addr: u64) -> Option<&Demangled> {
        self.demangled.get(&addr)
    }

    /// The function that owns the block starting at `block`.
    pub fn owner_of_block(&self, block: u64) -> Option<u64> {
        self.owners.get(&block).copied()
    }

    /// References to `addr`.
    pub fn xrefs_to(&self, addr: u64) -> &[Xref] {
        self.xrefs.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// The string whose text starts at `addr`.
    pub fn string_at(&self, addr: u64) -> Option<&StringEntry> {
        self.strings
            .binary_search_by_key(&addr, |s| s.addr)
            .ok()
            .map(|i| &self.strings[i])
    }
}

fn exit_targets(kind: ExitKind) -> impl Iterator<Item = u64> {
    let (a, b) = match kind {
        ExitKind::Jump(t) => (Some(t), None),
        ExitKind::Call { target, ret } => (Some(target), Some(ret)),
        ExitKind::IndirectCall { ret, .. } => (None, Some(ret)),
        ExitKind::Syscall { next } => (Some(next), None),
        ExitKind::Return | ExitKind::IndirectJump { .. } => (None, None),
    };
    a.into_iter().chain(b)
}

impl Program {
    /// The containing function's entry for an arbitrary code address.
    pub fn function_containing(&self, addr: u64) -> Option<u64> {
        let (_, block) = self.cfg.blocks.range(..=addr).next_back()?;
        (addr < block.end())
            .then(|| self.index.owner_of_block(block.pc()))
            .flatten()
    }

    /// Guest bytes at `range`, if mapped.
    pub fn bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0; len];
        self.image.read(addr, &mut buf).then_some(buf)
    }
}

// Strings --------------------------------------------------------------------------------

/// ASCII and UTF-16LE strings of at least four characters in the image's data segments.
fn find_strings(image: &Image) -> Vec<StringEntry> {
    const MIN: usize = 4;
    let mut out = Vec::new();
    for seg in image.segments.iter().filter(|s| !s.exec) {
        let bytes = image.data(seg);
        scan_ascii(bytes, seg.addr, MIN, &mut out);
        scan_utf16(bytes, seg.addr, MIN, &mut out);
        if out.len() > 2_000_000 {
            break;
        }
    }
    out.sort_by_key(|s| s.addr);
    out.dedup_by_key(|s| s.addr);
    out
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

fn scan_ascii(bytes: &[u8], base: u64, min: usize, out: &mut Vec<StringEntry>) {
    let mut i = 0;
    while i < bytes.len() {
        if !printable(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (printable(bytes[i]) || bytes[i] == b'\n' || bytes[i] == b'\r') {
            i += 1;
        }
        // A string ends at a NUL (or the segment's end); a run cut by any other byte is data.
        let terminated = i >= bytes.len() || bytes[i] == 0;
        if terminated && i - start >= min {
            out.push(entry(base + start as u64, &bytes[start..i], false));
        }
        i += 1;
    }
}

fn scan_utf16(bytes: &[u8], base: u64, min: usize, out: &mut Vec<StringEntry>) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        let start = i;
        let mut units = Vec::new();
        while i + 1 < bytes.len() && bytes[i + 1] == 0 && printable(bytes[i]) {
            units.push(bytes[i]);
            i += 2;
        }
        let terminated = i + 1 >= bytes.len() || (bytes[i] == 0 && bytes[i + 1] == 0);
        if terminated && units.len() >= min && (start == 0 || bytes[start - 1] == 0) {
            let mut e = entry(base + start as u64, &units, true);
            e.bytes = (units.len() * 2) as u32;
            out.push(e);
        }
        i = if i == start { i + 1 } else { i };
    }
}

fn entry(addr: u64, bytes: &[u8], wide: bool) -> StringEntry {
    let full = String::from_utf8_lossy(bytes);
    let mut text: String = full.chars().take(STRING_CAP).collect();
    if full.chars().count() > STRING_CAP {
        text.push('…');
    }
    StringEntry {
        addr,
        bytes: bytes.len() as u32,
        wide,
        text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_strings_need_a_terminator_and_minimum_length() {
        let mut out = Vec::new();
        scan_ascii(
            b"\0hello\0ab\0world!\0\x01\x02garbage\x01more\0",
            0x1000,
            4,
            &mut out,
        );
        let found: Vec<_> = out.iter().map(|s| (s.addr, s.text.as_str())).collect();
        // "ab" is too short; "garbage\x01more" is cut by a control byte, so only its NUL-run
        // tail "more" can qualify.
        assert_eq!(
            found,
            [(0x1001, "hello"), (0x100a, "world!"), (0x101b, "more")]
        );
    }

    #[test]
    fn utf16_strings_are_found_and_report_byte_length() {
        let mut bytes = vec![0u8, 0];
        for c in "wide!".bytes() {
            bytes.extend([c, 0]);
        }
        bytes.extend([0, 0, 0xff, 0xff]);
        let mut out = Vec::new();
        scan_utf16(&bytes, 0x2000, 4, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            (out[0].addr, out[0].text.as_str(), out[0].wide, out[0].bytes),
            (0x2002, "wide!", true, 10)
        );
    }

    #[test]
    fn long_strings_are_cut_for_display_but_keep_their_length() {
        let long = vec![b'a'; STRING_CAP + 50];
        let e = entry(0, &long, false);
        assert_eq!(e.bytes as usize, long.len());
        assert!(e.text.ends_with('…') && e.text.chars().count() == STRING_CAP + 1);
    }
}
