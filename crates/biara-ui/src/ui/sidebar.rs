//! The sidebar: functions, imports, strings and segments, each a filtered virtual list.

use std::borrow::Cow;

use rune::{El, GrowthSpec, ScrollSpec, Tx, col, el, row, text};
use rune_kit::TextInput;

use crate::backend::Index;

use super::{App, theme::*, widgets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideTab {
    Functions,
    Imports,
    Strings,
    Segments,
}

impl SideTab {
    const ALL: [SideTab; 4] = [
        SideTab::Functions,
        SideTab::Imports,
        SideTab::Strings,
        SideTab::Segments,
    ];

    fn label(self) -> &'static str {
        match self {
            SideTab::Functions => "Functions",
            SideTab::Imports => "Imports",
            SideTab::Strings => "Strings",
            SideTab::Segments => "Segments",
        }
    }
}

/// Row indexes that pass the filter, per list.
#[derive(Default)]
pub struct Lists {
    pub functions: Vec<u32>,
    pub imports: Vec<u32>,
    pub strings: Vec<u32>,
    /// Bumped whenever the rows change, so the virtual lists re-key.
    pub version: u64,
}

impl Lists {
    pub fn rebuild(&mut self, index: &Index, filter: &str) {
        let needle = filter.trim().to_lowercase();
        let hit = |hay: &str, addr: u64| {
            needle.is_empty()
                || hay.to_lowercase().contains(&needle)
                || format!("{addr:x}").contains(needle.trim_start_matches("0x"))
        };
        self.functions = (0..index.functions.len() as u32)
            .filter(|&i| {
                let f = &index.functions[i as usize];
                hit(&f.name, f.entry)
                    || index
                        .demangled(f.entry)
                        .is_some_and(|d| hit(&d.full, f.entry))
            })
            .collect();
        self.imports = (0..index.imports.len() as u32)
            .filter(|&i| {
                let imp = &index.imports[i as usize];
                hit(&imp.name, imp.slot)
                    || imp
                        .demangled
                        .as_ref()
                        .is_some_and(|d| hit(&d.full, imp.slot))
            })
            .collect();
        self.strings = (0..index.strings.len() as u32)
            .filter(|&i| {
                hit(
                    &index.strings[i as usize].text,
                    index.strings[i as usize].addr,
                )
            })
            .collect();
        self.version += 1;
    }
}

const ROW: f32 = 24.0;

pub fn panel(app: &App) -> El {
    let p = colors();
    let mut tabs = row().w_full().px(8.0).pt(6.0).gap(2.0);
    for t in SideTab::ALL {
        let active = app.side_tab == t;
        tabs = tabs.child(
            row()
                .h(26.0)
                .px(10.0)
                .radius(6.0)
                .items_center()
                .fill(if active {
                    p.selected
                } else {
                    rune::Color::TRANSPARENT
                })
                .hover(p.hover)
                .on_press(move |s: &mut App| s.side_tab = t)
                .child(
                    text(t.label())
                        .font(if active { UI_MEDIUM } else { UI })
                        .color(if active { p.text } else { p.muted }),
                ),
        );
    }
    let filter = col().w_full().px(8.0).py(8.0).child(
        TextInput::new(&app.filter)
            .placeholder(match app.side_tab {
                SideTab::Functions => "Filter functions",
                SideTab::Imports => "Filter imports",
                SideTab::Strings => "Filter strings",
                SideTab::Segments => "Filter",
            })
            .leading_icon(&widgets::SEARCH)
            .clear_button()
            .on_edit(|s: &mut App| &mut s.filter)
            .on_change(|s: &mut App, _tx: &mut Tx| {
                s.sidebar.rebuild(&s.index.clone(), &s.filter.text)
            })
            .build(kit()),
    );
    let list = match app.side_tab {
        SideTab::Functions => virtual_list(
            "fn",
            app.sidebar.functions.len(),
            app.sidebar.version,
            function_row,
        ),
        SideTab::Imports => virtual_list(
            "im",
            app.sidebar.imports.len(),
            app.sidebar.version,
            import_row,
        ),
        SideTab::Strings => virtual_list(
            "st",
            app.sidebar.strings.len(),
            app.sidebar.version,
            string_row,
        ),
        SideTab::Segments => virtual_list(
            "sg",
            app.image.as_ref().map_or(0, |i| i.segments.len()),
            0,
            segment_row,
        ),
    };
    col()
        .w(app.side_w)
        .h_full()
        .fill(p.panel)
        .child(tabs)
        .child(filter)
        .child(el().w_full().h(1.0).fill(p.line))
        .child(list)
        .child(footer(app))
}

fn footer(app: &App) -> El {
    let p = colors();
    let (shown, total) = match app.side_tab {
        SideTab::Functions => (app.sidebar.functions.len(), app.index.functions.len()),
        SideTab::Imports => (app.sidebar.imports.len(), app.index.imports.len()),
        SideTab::Strings => (app.sidebar.strings.len(), app.index.strings.len()),
        SideTab::Segments => {
            let n = app.image.as_ref().map_or(0, |i| i.segments.len());
            (n, n)
        }
    };
    col()
        .w_full()
        .child(el().w_full().h(1.0).fill(p.line))
        .child(
            row().w_full().h(24.0).px(12.0).items_center().child(
                text(if shown == total {
                    format!("{total}")
                } else {
                    format!("{shown} of {total}")
                })
                .font(SMALL)
                .color(p.faint),
            ),
        )
}

/// A scrolling list of `count` rows built by `build`.
fn virtual_list(
    prefix: &'static str,
    count: usize,
    version: u64,
    build: fn(&App, usize) -> El,
) -> El {
    col()
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .child(
            col()
                .key(format!("{prefix}-rows"))
                .w_full()
                .growth(GrowthSpec::default())
                .virtual_rows(
                    count,
                    ROW,
                    move |_: &App, i| Cow::Owned(format!("{prefix}{i}")),
                    build,
                )
                .virtual_rows_version((prefix, version, count)),
        )
}

fn function_row(s: &App, i: usize) -> El {
    let p = colors();
    let f = &s.index.functions[s.sidebar.functions[i] as usize];
    let entry = f.entry;
    let current = s.function_of(s.cur) == Some(entry);
    let name = s.display_of(entry).unwrap_or_else(|| f.name.clone());
    let stub = f.kind == crate::backend::FunctionKind::Stub;
    row()
        .w_full()
        .h(ROW)
        .px(12.0)
        .gap(8.0)
        .items_center()
        .fill(if current {
            p.selected
        } else {
            rune::Color::TRANSPARENT
        })
        .hover(p.hover)
        .on_press_tx(move |s: &mut App, tx| s.goto(entry, tx))
        .child(
            text(name)
                .font(CODE)
                .color(if stub { p.muted } else { p.text })
                .truncate()
                .grow(1.0)
                .min_w(0.0),
        )
        .child(
            text(format!("{:x}", f.entry))
                .font(SMALL.mono())
                .color(p.faint),
        )
}

fn import_row(s: &App, i: usize) -> El {
    let p = colors();
    let imp = &s.index.imports[s.sidebar.imports[i] as usize];
    let slot = imp.slot;
    row()
        .w_full()
        .h(ROW)
        .px(12.0)
        .gap(8.0)
        .items_center()
        .hover(p.hover)
        .on_press_tx(move |s: &mut App, tx| s.goto(slot, tx))
        .child(
            text(match &imp.demangled {
                Some(d) if s.demangle => d.short.clone(),
                _ => imp.name.clone(),
            })
            .font(CODE)
            .color(p.text)
            .truncate()
            .grow(1.0)
            .min_w(0.0),
        )
        .child(text(format!("{slot:x}")).font(SMALL.mono()).color(p.faint))
}

fn string_row(s: &App, i: usize) -> El {
    let p = colors();
    let st = &s.index.strings[s.sidebar.strings[i] as usize];
    let addr = st.addr;
    row()
        .w_full()
        .h(ROW)
        .px(12.0)
        .gap(8.0)
        .items_center()
        .hover(p.hover)
        .on_press_tx(move |s: &mut App, tx| s.goto(addr, tx))
        .child(text(format!("{addr:x}")).font(SMALL.mono()).color(p.faint))
        .child(
            text(st.text.replace(['\n', '\r', '\t'], " "))
                .font(CODE)
                .color(p.string)
                .truncate()
                .grow(1.0)
                .min_w(0.0),
        )
}

fn segment_row(s: &App, i: usize) -> El {
    let p = colors();
    let seg = &s.image.as_ref().expect("segments need an image").segments[i];
    let addr = seg.addr;
    let perms = format!(
        "{}{}{}",
        'r',
        if seg.write { 'w' } else { '-' },
        if seg.exec { 'x' } else { '-' }
    );
    row()
        .w_full()
        .h(ROW)
        .px(12.0)
        .gap(10.0)
        .items_center()
        .hover(p.hover)
        .on_press_tx(move |s: &mut App, tx| s.goto(addr, tx))
        .child(text(format!("{addr:#x}")).font(CODE).color(p.text))
        .child(text(perms).font(SMALL.mono()).color(if seg.exec {
            p.mnemonic_jump
        } else {
            p.faint
        }))
        .child(el().grow(1.0))
        .child(
            text(format!("{:#x}", seg.size))
                .font(SMALL.mono())
                .color(p.faint),
        )
}

/// Scroll the function list to the current function.
pub fn reveal(app: &App, tx: &mut Tx) {
    if app.side_tab != SideTab::Functions {
        return;
    }
    let Some(f) = app.function_of(app.cur) else {
        return;
    };
    let Some(index) = app.index.function_position(f) else {
        return;
    };
    if let Ok(row) = app.sidebar.functions.binary_search(&(index as u32)) {
        tx.scroll_into_view(format!("fn{row}"));
    }
}
