//! The hex view: the mapped image as 16-byte rows, with an ASCII column.
//!
//! It needs only the parsed image, so it works while analysis is still running.

use std::borrow::Cow;

use biara_loader::Image;
use rune::{El, GrowthSpec, ScrollSpec, Tx, col, row, text};

use super::{App, code::Line, theme::*};

const PER_ROW: u64 = 16;

/// Where each segment's rows start, so a row number maps to an address and back.
#[derive(Default)]
pub struct State {
    /// `(segment address, first row)`, one per segment in address order.
    starts: Vec<(u64, u64)>,
    total: u64,
    /// Bumped when the image changes.
    pub version: u64,
}

impl State {
    pub fn rebuild(&mut self, image: &Image) {
        let mut segs: Vec<_> = image.segments.iter().map(|s| (s.addr, s.size)).collect();
        segs.sort();
        let mut row = 0;
        self.starts = segs
            .iter()
            .map(|&(addr, size)| {
                let start = row;
                row += (addr % PER_ROW + size).div_ceil(PER_ROW);
                (addr, start)
            })
            .collect();
        self.total = row;
        self.version += 1;
    }

    pub fn rows(&self) -> usize {
        self.total as usize
    }

    /// The address at the start of row `i`.
    pub fn addr_of(&self, i: usize) -> u64 {
        let i = i as u64;
        let k = self
            .starts
            .partition_point(|&(_, first)| first <= i)
            .saturating_sub(1);
        let (addr, first) = self.starts[k];
        // Rows align to 16 bytes; the first row of a segment may start mid-row.
        (addr & !(PER_ROW - 1)) + (i - first) * PER_ROW
    }

    /// The row containing `addr`, if it is mapped.
    pub fn row_of(&self, addr: u64) -> Option<usize> {
        let k = self
            .starts
            .partition_point(|&(a, _)| (a & !(PER_ROW - 1)) <= addr)
            .checked_sub(1)?;
        let (seg, first) = self.starts[k];
        let row = first + (addr - (seg & !(PER_ROW - 1))) / PER_ROW;
        let end = self.starts.get(k + 1).map_or(self.total, |s| s.1);
        (row < end).then_some(row as usize)
    }
}

pub fn view(app: &App) -> El {
    let p = colors();
    if app.image.is_none() {
        return col()
            .w_full()
            .h_full()
            .center()
            .child(text("Nothing to show").font(UI).color(p.muted));
    }
    col()
        .w_full()
        .h_full()
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .scroll_margin(260.0)
        .child(
            col()
                .key("hex-rows")
                .w_full()
                .growth(GrowthSpec::default())
                .virtual_rows(
                    app.hex.rows(),
                    ROW_H,
                    |_: &App, i| Cow::Owned(format!("h{i}")),
                    build_row,
                )
                .virtual_rows_version((app.hex.version, app.hex.rows())),
        )
}

fn build_row(s: &App, i: usize) -> El {
    let p = colors();
    let image = s.image.as_ref().expect("hex rows need an image");
    let addr = s.hex.addr_of(i);
    let mut buf = [0u8; PER_ROW as usize];
    let mut have = [false; PER_ROW as usize];
    for (k, slot) in have.iter_mut().enumerate() {
        *slot = image.read(addr + k as u64, &mut buf[k..k + 1]);
    }
    let mut line = Line::new();
    line.push(&format!("{addr:012x}  "), p.addr);
    for k in 0..PER_ROW as usize {
        let here = addr + k as u64 == s.cur;
        let (txt, color) = if have[k] {
            (
                format!("{:02x}", buf[k]),
                if buf[k] == 0 {
                    p.faint
                } else if (0x20..0x7f).contains(&buf[k]) {
                    p.text
                } else {
                    p.muted
                },
            )
        } else {
            ("··".to_owned(), p.faint)
        };
        line.run(&txt, color, None, here.then_some(p.accent_soft));
        line.push(if k == 7 { "  " } else { " " }, p.text);
    }
    line.push(" ", p.text);
    for k in 0..PER_ROW as usize {
        let c = if have[k] && (0x20..0x7f).contains(&buf[k]) {
            buf[k] as char
        } else {
            '.'
        };
        line.run(
            &c.to_string(),
            if have[k] && c != '.' {
                p.string
            } else {
                p.faint
            },
            None,
            (addr + k as u64 == s.cur).then_some(p.accent_soft),
        );
    }
    row()
        .w_full()
        .h(ROW_H)
        .px(14.0)
        .items_center()
        .hover(p.hover)
        .on_press(move |s: &mut App| s.sync_cursor(addr))
        .child(line.build(CODE))
}

/// Scroll the hex view to the current address.
pub fn reveal(app: &App, tx: &mut Tx) {
    if let Some(row) = app.hex.row_of(app.cur) {
        tx.scroll_into_view(format!("h{row}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(segments: &[(u64, u64)]) -> State {
        let mut starts = Vec::new();
        let mut row = 0;
        for &(addr, size) in segments {
            starts.push((addr, row));
            row += (addr % PER_ROW + size).div_ceil(PER_ROW);
        }
        State {
            starts,
            total: row,
            version: 0,
        }
    }

    #[test]
    fn rows_map_to_addresses_and_back_across_segments() {
        // 0x1000..0x1040 is four rows; 0x2008..0x2028 starts mid-row and covers three.
        let s = state(&[(0x1000, 0x40), (0x2008, 0x20)]);
        assert_eq!(s.rows(), 4 + 3);
        assert_eq!((s.addr_of(0), s.addr_of(3)), (0x1000, 0x1030));
        assert_eq!((s.addr_of(4), s.addr_of(6)), (0x2000, 0x2020));
        for addr in [0x1000, 0x103f, 0x2008, 0x2027] {
            let row = s
                .row_of(addr)
                .unwrap_or_else(|| panic!("{addr:#x} unmapped"));
            assert!(
                s.addr_of(row) <= addr && addr < s.addr_of(row) + PER_ROW,
                "{addr:#x} row {row}"
            );
        }
        // The gap between segments and the space past the end are not rows.
        assert_eq!(s.row_of(0x1800), None);
        assert_eq!(s.row_of(0x3000), None);
        assert_eq!(s.row_of(0x10), None);
    }
}
