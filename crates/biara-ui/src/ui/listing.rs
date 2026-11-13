//! The disassembly listing: every recovered instruction in address order, as virtual rows.

use std::borrow::Cow;

use rune::{El, GrowthSpec, ScrollSpec, Tx, col, el, row, text};

use crate::backend::{HeadKind, Insn, XrefKind, disasm};

use super::{App, code::Line, theme::*};

/// Listing view state.
#[derive(Default)]
pub struct State {
    /// Bumped when the rows change.
    version: u64,
}

impl State {
    pub fn invalidate(&mut self) {
        self.version += 1;
    }
}

const ADDR_W: f32 = CHAR_W * 17.0;
const BYTES_W: f32 = CHAR_W * 25.0;

pub fn view(app: &App) -> El {
    let Some(program) = &app.program else {
        return el();
    };
    let count = program.listing.heads.len();
    col()
        .w_full()
        .h_full()
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .scroll_margin(260.0)
        .child(
            col()
                .key("listing-rows")
                .w_full()
                .growth(GrowthSpec::default())
                .virtual_rows(
                    count,
                    ROW_H,
                    |_: &App, i| Cow::Owned(format!("l{i}")),
                    build_row,
                )
                .virtual_rows_version((app.listing.version, count, app.display_version())),
        )
}

fn build_row(s: &App, i: usize) -> El {
    let p = colors();
    let program = s.program.as_ref().expect("listing rows need a program");
    let head = program.listing.heads[i];
    let here = s.cur >= head.addr && s.cur < head.addr + u64::from(head.len).max(1);
    let base = row().w_full().h(ROW_H).px(14.0).items_center();
    match head.kind {
        HeadKind::Blank => base,
        HeadKind::Func => {
            let info = s.index.function(head.addr);
            // A mangled name has room for its full signature here, and the linker's spelling
            // goes in the comment.
            let full = s.full_name_of(head.addr);
            let name = full.clone().unwrap_or_else(|| s.label(head.addr));
            let mut line = Line::new();
            line.push(&name, p.function);
            line.push(" ", p.text);
            if let Some(f) = info {
                line.push(
                    &format!("  {} bytes · {} blocks", f.size, f.blocks),
                    p.comment,
                );
                if f.callers > 0 {
                    line.push(&format!(" · {} callers", f.callers), p.comment);
                }
                if full.is_some() {
                    line.push(&format!(" · {}", f.name), p.comment);
                }
            }
            base.fill(if here { p.selected } else { p.raised })
                .child(line.build(CODE.mono()))
                .child(el().grow(1.0))
        }
        HeadKind::Label => {
            let mut line = Line::new();
            line.push(&format!("{}:", s.label(head.addr)), p.label);
            let from: Vec<String> = s
                .index
                .xrefs_to(head.addr)
                .iter()
                .filter(|x| x.kind == XrefKind::Jump)
                .take(4)
                .map(|x| format!("{:x}", x.from))
                .collect();
            if !from.is_empty() {
                line.push(&format!("   ; from {}", from.join(", ")), p.comment);
            }
            base.child(el().w(ADDR_W + BYTES_W)).child(line.build(CODE))
        }
        HeadKind::Insn => {
            let mut buf = vec![0u8; head.len as usize];
            let insn = if s
                .image
                .as_ref()
                .is_some_and(|img| img.read(head.addr, &mut buf))
            {
                s.arch.map(|a| disasm::decode(a, head.addr, &buf))
            } else {
                None
            };
            let hex = buf
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let mut r = base
                .fill(if here {
                    p.selected
                } else {
                    rune::Color::TRANSPARENT
                })
                .child(
                    text(format!("{:x}", head.addr))
                        .font(CODE)
                        .color(p.addr)
                        .w(ADDR_W),
                )
                .child(text(hex).font(CODE).color(p.bytes).w(BYTES_W));
            if let Some(insn) = insn {
                r = r.child(insn_line(s, &insn).build(CODE));
            }
            r
        }
        HeadKind::Gap => {
            let mut buf = vec![0u8; head.len as usize];
            let ok = s
                .image
                .as_ref()
                .is_some_and(|img| img.read(head.addr, &mut buf));
            let hex = if ok {
                buf.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                String::new()
            };
            base.child(
                text(format!("{:x}", head.addr))
                    .font(CODE)
                    .color(p.addr)
                    .w(ADDR_W),
            )
            .child(text(hex).font(CODE).color(p.bytes))
        }
        HeadKind::Skip => base
            .child(
                text(format!("{:x}", head.addr))
                    .font(CODE)
                    .color(p.addr)
                    .w(ADDR_W),
            )
            .child(
                text(format!("… {} bytes not analysed", head.len))
                    .font(CODE)
                    .color(p.comment),
            ),
    }
}

/// The text of one instruction: coloured runs, named targets that link, and a comment for
/// what a data reference points at.
pub fn insn_line(s: &App, insn: &Insn) -> Line {
    let p = colors();
    let mut line = Line::new();
    for span in &insn.spans {
        match (span.tok, span.target) {
            (crate::backend::Tok::Target, Some(t)) => {
                line.push_link(&s.label(t), p.target, format!("{t:x}"));
            }
            _ => {
                line.push(&span.text, tok_color(span.tok, insn.flow));
            }
        }
    }
    // What an address operand points at: a string, or a named place.
    let pointed = insn.data_ref.or_else(|| {
        insn.spans
            .iter()
            .filter(|sp| sp.tok == crate::backend::Tok::Number)
            .filter_map(|sp| {
                sp.text
                    .strip_prefix("0x")
                    .and_then(|h| u64::from_str_radix(h, 16).ok())
            })
            .find(|&v| {
                v >= 0x1000 && (s.index.string_at(v).is_some() || s.index.base_name(v).is_some())
            })
    });
    if let Some(addr) = pointed {
        let note = s
            .index
            .string_at(addr)
            .map(|st| format!("\"{}\"", st.text.replace('\n', "\\n")))
            .or_else(|| s.name_of(addr));
        if let Some(note) = note {
            line.push(&format!("   ; {note}"), p.comment);
        }
    }
    line
}

/// Scroll the listing to the current address.
pub fn reveal(app: &App, tx: &mut Tx) {
    let Some(program) = &app.program else { return };
    if let Some(row) = program.listing.row_of(app.cur) {
        tx.scroll_into_view(format!("l{row}"));
    }
}

/// The address of the next row in the direction of `delta` that is a different place from the
/// cursor: spacing rows, and the header or label that share an address with an instruction,
/// are passed over. `None` at either end.
pub fn step(app: &App, delta: isize) -> Option<u64> {
    use crate::backend::HeadKind;
    let heads = &app.program.as_ref()?.listing.heads;
    let mut row = app.program.as_ref()?.listing.row_of(app.cur)? as isize;
    loop {
        row += delta.signum();
        let head = heads.get(usize::try_from(row).ok()?)?;
        if head.kind != HeadKind::Blank && head.addr != app.cur {
            return Some(head.addr);
        }
    }
}
