//! The bottom panel: cross-references to what the cursor is on, and the output log.

use biara_loader::Image;
use rune::{Cursor, Drag, El, GrowthSpec, Phase, ScrollSpec, Tx, col, el, row, text};

use crate::backend::{XrefKind, disasm};

use super::{App, theme::*, widgets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomTab {
    Xrefs,
    Output,
}

const ROW: f32 = 22.0;

/// The address whose references the panel lists: the cursor if something refers to it,
/// otherwise the function it is in.
pub fn xref_target(app: &App) -> u64 {
    if !app.index.xrefs_to(app.cur).is_empty() {
        return app.cur;
    }
    app.function_of(app.cur).unwrap_or(app.cur)
}

pub fn panel(app: &App) -> El {
    let p = colors();
    let tabs = row()
        .w_full()
        .h(32.0)
        .px(6.0)
        .items_center()
        .child(widgets::tab(
            &format!(
                "Cross-references ({})",
                app.index.xrefs_to(xref_target(app)).len()
            ),
            app.bottom_tab == BottomTab::Xrefs,
            |s: &mut App, _| s.bottom_tab = BottomTab::Xrefs,
        ))
        .child(widgets::tab(
            "Output",
            app.bottom_tab == BottomTab::Output,
            |s: &mut App, _| s.bottom_tab = BottomTab::Output,
        ));
    let body = match app.bottom_tab {
        BottomTab::Xrefs => xrefs(app),
        BottomTab::Output => output(app),
    };
    col()
        .w_full()
        .h(app.bottom_h)
        .fill(p.panel)
        .child(grip())
        .child(tabs)
        .child(el().w_full().h(1.0).fill(p.line))
        .child(body)
}

/// The draggable top edge of the panel.
fn grip() -> El {
    let p = colors();
    el().w_full()
        .h(5.0)
        .fill(p.line)
        .hover(p.line_strong)
        .cursor(Cursor::ResizeRow)
        .on_drag(|s: &mut App, d: &mut Drag, _tx: &mut Tx| match d.phase {
            Phase::Down => d.data = s.bottom_h,
            _ => s.bottom_h = (d.data - d.dy).clamp(80.0, 520.0),
        })
}

fn xrefs(app: &App) -> El {
    let p = colors();
    let target = xref_target(app);
    let list = app.index.xrefs_to(target);
    if list.is_empty() {
        return col().w_full().grow(1.0).center().child(
            text(format!("No references to {}", app.label(target)))
                .font(UI)
                .color(p.faint),
        );
    }
    let rows: Vec<El> = list
        .iter()
        .take(500)
        .map(|x| xref_row(app, x.from, x.function, x.kind))
        .collect();
    col()
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .child(
            col()
                .key("xref-rows")
                .w_full()
                .growth(GrowthSpec::default())
                .children(rows),
        )
}

fn xref_row(app: &App, from: u64, function: u64, kind: XrefKind) -> El {
    let p = colors();
    let (word, color) = match kind {
        XrefKind::Call => ("call", p.mnemonic_call),
        XrefKind::Jump => ("jump", p.mnemonic_jump),
        XrefKind::Data => ("data", p.mnemonic),
    };
    let place = if function != 0 && function != from {
        format!("{}+{:#x}", app.label(function), from - function)
    } else {
        format!("{from:#x}")
    };
    let insn = insn_text(app, from);
    row()
        .key(format!("x{from:x}{word}"))
        .w_full()
        .h(ROW)
        .px(14.0)
        .gap(14.0)
        .items_center()
        .hover(p.hover)
        .on_press_tx(move |s: &mut App, tx| s.goto(from, tx))
        .child(text(word).font(SMALL_MEDIUM.mono()).color(color).w(36.0))
        .child(
            text(format!("{from:x}"))
                .font(CODE)
                .color(p.addr)
                .w(CHAR_W * 14.0),
        )
        .child(
            text(place)
                .font(CODE)
                .color(p.target)
                .w(CHAR_W * 34.0)
                .truncate(),
        )
        .child(
            text(insn)
                .font(CODE)
                .color(p.muted)
                .truncate()
                .grow(1.0)
                .min_w(0.0),
        )
}

/// The instruction at `addr`, as plain text.
fn insn_text(app: &App, addr: u64) -> String {
    let (Some(image), Some(arch)) = (&app.image, app.arch) else {
        return String::new();
    };
    read_insn(image, arch, addr)
        .map(|i| i.text())
        .unwrap_or_default()
}

fn read_insn(image: &Image, arch: disasm::Arch, addr: u64) -> Option<disasm::Insn> {
    let mut buf = [0u8; 15];
    let mut n = 0;
    while n < buf.len() && image.read(addr + n as u64, &mut buf[n..n + 1]) {
        n += 1;
    }
    (n > 0).then(|| disasm::decode(arch, addr, &buf[..n]))
}

fn output(app: &App) -> El {
    let p = colors();
    let rows: Vec<El> = app
        .log
        .iter()
        .enumerate()
        .map(|(i, l)| {
            row()
                .key(format!("o{i}"))
                .w_full()
                .h(ROW)
                .px(14.0)
                .items_center()
                .child(text(l.clone()).font(CODE).color(p.muted).truncate())
        })
        .collect();
    col()
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec { stick_bottom: true })
        .child(
            col()
                .key("output-rows")
                .w_full()
                .growth(GrowthSpec::default())
                .children(rows),
        )
}
