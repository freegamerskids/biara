//! The linear disassembly listing: every recovered instruction in address order, with function
//! headers, labels and unanalysed gaps between them.
//!
//! The model is a sorted list of 16-byte [`Head`]s, one per row. It holds no text: a view decodes
//! the bytes of the rows it draws, so a 400,000-row listing costs a few megabytes and builds in
//! milliseconds.

use biara_cfg::Cfg;
use biara_loader::Image;

use super::program::{Index, XrefKind};

/// What one row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadKind {
    /// Spacing before a function.
    Blank,
    /// A function's header: name, size, references.
    Func,
    /// A branch target inside a function.
    Label,
    Insn,
    /// Bytes between recovered blocks, up to 16 per row.
    Gap,
    /// A long stretch of unanalysed bytes shown as one row.
    Skip,
}

/// One row of the listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub addr: u64,
    /// Bytes covered: an instruction's length, a gap row's bytes. Zero for structural rows.
    pub len: u32,
    pub kind: HeadKind,
}

#[derive(Debug, Default)]
pub struct Listing {
    pub heads: Vec<Head>,
}

/// Gaps up to this size are listed byte by byte; larger ones collapse into a [`HeadKind::Skip`].
const GAP_LIMIT: u64 = 256;

impl Listing {
    /// Lay out every block of `cfg` in address order.
    pub fn build(image: &Image, cfg: &Cfg, index: &Index) -> Listing {
        let mut heads = Vec::with_capacity(cfg.blocks.values().map(|b| b.insns.len() + 2).sum());
        let mut prev_end = 0u64;
        for block in cfg.blocks.values() {
            let (start, end) = (block.pc(), block.end());
            // Blocks retranslated with a smaller budget can lie inside an earlier one.
            if start < prev_end {
                continue;
            }
            if prev_end != 0 && start > prev_end && same_segment(image, prev_end, start) {
                gap(&mut heads, prev_end, start);
            }
            if index.function(start).is_some() {
                heads.push(Head {
                    addr: start,
                    len: 0,
                    kind: HeadKind::Blank,
                });
                heads.push(Head {
                    addr: start,
                    len: 0,
                    kind: HeadKind::Func,
                });
            } else if index
                .xrefs_to(start)
                .iter()
                .any(|x| x.kind == XrefKind::Jump)
            {
                heads.push(Head {
                    addr: start,
                    len: 0,
                    kind: HeadKind::Label,
                });
            }
            for (i, &pc) in block.insns.iter().enumerate() {
                let next = block.insns.get(i + 1).copied().unwrap_or(end);
                heads.push(Head {
                    addr: pc,
                    len: (next - pc) as u32,
                    kind: HeadKind::Insn,
                });
            }
            prev_end = end;
        }
        Listing { heads }
    }

    /// The row to show when going to `addr`: a function's header for its entry, otherwise the
    /// instruction (or gap) containing it.
    pub fn row_of(&self, addr: u64) -> Option<usize> {
        if self.heads.is_empty() {
            return None;
        }
        let i = self.heads.partition_point(|h| h.addr < addr);
        match self.heads.get(i) {
            Some(h) if h.addr == addr => Some(if h.kind == HeadKind::Blank { i + 1 } else { i }),
            _ => {
                let i = i.checked_sub(1)?;
                // An address in the middle of an instruction belongs to that instruction;
                // past the end of the last row there is nothing to show.
                let h = self.heads[i];
                (addr < h.addr + u64::from(h.len).max(1)).then_some(i)
            }
        }
    }
}

fn same_segment(image: &Image, a: u64, b: u64) -> bool {
    match (image.segment_at(a.saturating_sub(1)), image.segment_at(b)) {
        (Some(x), Some(y)) => x.addr == y.addr,
        _ => false,
    }
}

fn gap(heads: &mut Vec<Head>, from: u64, to: u64) {
    if to - from > GAP_LIMIT {
        heads.push(Head {
            addr: from,
            len: (to - from).min(u64::from(u32::MAX)) as u32,
            kind: HeadKind::Skip,
        });
        return;
    }
    let mut at = from;
    while at < to {
        let len = (to - at).min(16);
        heads.push(Head {
            addr: at,
            len: len as u32,
            kind: HeadKind::Gap,
        });
        at += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(heads: &[(u64, u32, HeadKind)]) -> Listing {
        Listing {
            heads: heads
                .iter()
                .map(|&(addr, len, kind)| Head { addr, len, kind })
                .collect(),
        }
    }

    #[test]
    fn a_function_entry_goes_to_its_header_not_the_spacing_above_it() {
        use HeadKind::*;
        let l = listing(&[
            (0x100, 0, Blank),
            (0x100, 0, Func),
            (0x100, 4, Insn),
            (0x104, 2, Insn),
        ]);
        assert_eq!(l.row_of(0x100), Some(1), "the Func row");
        assert_eq!(l.heads[l.row_of(0x100).unwrap()].kind, Func);
    }

    #[test]
    fn an_address_inside_an_instruction_selects_that_instruction() {
        use HeadKind::*;
        let l = listing(&[(0x100, 5, Insn), (0x105, 3, Insn), (0x200, 1, Insn)]);
        assert_eq!(l.row_of(0x102), Some(0));
        assert_eq!(l.row_of(0x107), Some(1));
        // Between rows (an unanalysed hole) and past the end there is nothing to select.
        assert_eq!(l.row_of(0x150), None);
        assert_eq!(l.row_of(0x300), None);
        assert_eq!(l.row_of(0x10), None);
    }

    #[test]
    fn gaps_list_bytes_in_sixteens_and_long_gaps_collapse() {
        let mut heads = Vec::new();
        gap(&mut heads, 0x1000, 0x1025);
        let lens: Vec<_> = heads.iter().map(|h| (h.addr, h.len)).collect();
        assert_eq!(lens, [(0x1000, 16), (0x1010, 16), (0x1020, 5)]);
        let mut long = Vec::new();
        gap(&mut long, 0x2000, 0x2000 + GAP_LIMIT + 1);
        assert_eq!(
            long,
            [Head {
                addr: 0x2000,
                len: (GAP_LIMIT + 1) as u32,
                kind: HeadKind::Skip
            }]
        );
    }

    #[test]
    fn an_empty_listing_has_no_rows() {
        assert_eq!(Listing::default().row_of(0x100), None);
    }
}
