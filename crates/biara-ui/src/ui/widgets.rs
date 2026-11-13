//! The chrome around the views: toolbar, tabs, splitter, status bar and the screens shown
//! before analysis finishes.

use rune::{Cursor, Drag, El, Icon, Phase, Tx, col, el, icon, row, text};

use super::{App, Load, MainTab, theme::*};

pub static BACK: Icon = Icon {
    name: "biara-back",
    view: 16.0,
    body: r#"<path d="M10 3.5L5.5 8L10 12.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>"#,
};
pub static FORWARD: Icon = Icon {
    name: "biara-forward",
    view: 16.0,
    body: r#"<path d="M6 3.5L10.5 8L6 12.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>"#,
};
pub static SEARCH: Icon = Icon {
    name: "biara-search",
    view: 16.0,
    body: r#"<circle cx="7" cy="7" r="3.75" stroke="currentColor" stroke-width="1.3" fill="none"/><path d="M10 10L12.75 12.75" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>"#,
};

/// A square icon button; dimmed and inert when `enabled` is false.
pub fn icon_button(
    glyph: &'static Icon,
    enabled: bool,
    on_press: impl Fn(&mut App, &mut Tx) + 'static,
) -> El {
    let p = colors();
    let b = el()
        .size(28.0, 28.0)
        .radius(6.0)
        .center()
        .child(icon(glyph, 15.0).color(if enabled { p.muted } else { p.faint }));
    if enabled {
        b.hover(p.hover).on_press_tx(on_press)
    } else {
        b
    }
}

/// Top bar: navigation, the current location, and what is open.
pub fn toolbar(app: &App) -> El {
    let p = colors();
    let mut bar = row()
        .w_full()
        .h(44.0)
        .px(12.0)
        .gap(6.0)
        .items_center()
        .fill(p.panel)
        .child(
            row()
                .gap(7.0)
                .items_center()
                .mr(10.0)
                .child(el().size(9.0, 9.0).radius(3.0).fill(p.accent))
                .child(text("biara").font(TITLE).color(p.text)),
        )
        .child(icon_button(&BACK, app.can_go_back(), |s: &mut App, tx| {
            s.go_back(tx)
        }))
        .child(icon_button(
            &FORWARD,
            app.can_go_forward(),
            |s: &mut App, tx| s.go_forward(tx),
        ));

    // The current location: a name and its address.
    if matches!(app.load, Load::Ready) {
        let name = app.function_of(app.cur).map(|f| app.label(f));
        let mut pill = row()
            .h(28.0)
            .px(10.0)
            .gap(8.0)
            .items_center()
            .radius(6.0)
            .fill(p.raised)
            .child(text(format!("{:#x}", app.cur)).font(CODE).color(p.addr));
        if let Some(n) = name {
            pill = pill.child(text(n).font(CODE).color(p.target));
        }
        bar = bar.child(pill);
    }

    bar = bar.child(el().grow(1.0));
    bar = bar.child(open_button("Open…", false));
    if let Some(path) = &app.path {
        let file = path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        bar = bar.child(text(file).font(UI_MEDIUM).color(p.muted));
    }
    if let (Some(img), Some(arch)) = (&app.image, app.arch) {
        bar = bar
            .child(badge(&format!("{arch:?}").to_lowercase()))
            .child(badge(img.os));
    }
    col()
        .w_full()
        .child(bar)
        .child(el().w_full().h(1.0).fill(p.line))
}

/// A text button that opens the system file dialog.
pub fn open_button(label: &str, prominent: bool) -> El {
    let p = colors();
    row()
        .key("open-button")
        .h(if prominent { 34.0 } else { 26.0 })
        .px(if prominent { 18.0 } else { 10.0 })
        .radius(7.0)
        .items_center()
        .fill(if prominent { p.accent } else { p.raised })
        .hover(if prominent {
            p.accent.alpha(0.85)
        } else {
            p.hover
        })
        .on_press_tx(|_: &mut App, tx| super::overlay::open_file(tx))
        .child(text(label.to_owned()).font(UI_MEDIUM).color(if prominent {
            p.window
        } else {
            p.text
        }))
}

fn badge(label: &str) -> El {
    let p = colors();
    row()
        .h(20.0)
        .px(8.0)
        .radius(10.0)
        .fill(p.raised)
        .items_center()
        .child(text(label).font(SMALL_MEDIUM).color(p.muted))
}

/// One tab in a strip.
pub fn tab(label: &str, active: bool, on_press: impl Fn(&mut App, &mut Tx) + 'static) -> El {
    let p = colors();
    let t = col()
        .h(34.0)
        .px(14.0)
        .justify_center()
        .hover(p.hover)
        .on_press_tx(on_press)
        .child(
            text(label)
                .font(if active { UI_MEDIUM } else { UI })
                .color(if active { p.text } else { p.muted }),
        );
    // The active tab carries an accent bar under it.
    col().child(t).child(el().w_full().h(2.0).fill(if active {
        p.accent
    } else {
        rune::Color::TRANSPARENT
    }))
}

pub fn main_tabs(app: &App) -> El {
    let mut strip = row().w_full().h(36.0).px(6.0);
    for t in MainTab::ALL {
        strip = strip.child(tab(t.label(), app.main_tab == t, move |s: &mut App, tx| {
            s.select_tab(t, tx)
        }));
    }
    strip
}

/// The draggable edge between the sidebar and the main area.
pub fn splitter() -> El {
    let p = colors();
    el().w(5.0)
        .h_full()
        .fill(p.line)
        .hover(p.line_strong)
        .cursor(Cursor::ResizeColumn)
        .on_drag(|s: &mut App, d: &mut Drag, _tx: &mut Tx| match d.phase {
            Phase::Down => d.data = s.side_w,
            _ => s.side_w = (d.data + d.dx).clamp(200.0, 640.0),
        })
}

pub fn status_bar(app: &App) -> El {
    let p = colors();
    let (dot, message) = match &app.load {
        Load::Empty => (p.faint, "No binary open".to_owned()),
        Load::Opening {
            stage,
            functions,
            blocks,
        } => {
            let counts = if *blocks > 0 {
                format!(" · {functions} functions · {blocks} blocks")
            } else {
                String::new()
            };
            (p.warn, format!("{}{counts}", stage.label()))
        }
        Load::Failed(e) => (p.bad, e.lines().next().unwrap_or("failed").to_owned()),
        Load::Ready => (
            p.good,
            format!(
                "Analysis complete · {} functions",
                app.index.functions.len()
            ),
        ),
    };
    let mut bar = row()
        .w_full()
        .h(24.0)
        .px(12.0)
        .gap(8.0)
        .items_center()
        .fill(p.panel)
        .child(el().size(7.0, 7.0).radius(4.0).fill(dot))
        .child(text(message).font(SMALL).color(p.muted))
        .child(el().grow(1.0));
    if matches!(app.load, Load::Ready) {
        let at = match app.function_of(app.cur) {
            Some(f) if f != app.cur => format!("{}+{:#x}", app.label(f), app.cur - f),
            Some(f) => app.label(f),
            None => String::new(),
        };
        bar = bar.child(
            text(format!("{:#x}  {at}", app.cur))
                .font(SMALL.mono())
                .color(p.muted),
        );
    }
    col()
        .w_full()
        .child(el().w_full().h(1.0).fill(p.line))
        .child(bar)
}

/// What the main area shows before there is anything to look at.
pub fn placeholder(app: &App) -> El {
    let p = colors();
    let (title, detail): (String, String) = match &app.load {
        Load::Empty => (
            "Open a binary".into(),
            "Choose a file, drop one on this window, or run biara-ui <path>".into(),
        ),
        Load::Opening {
            stage,
            functions,
            blocks,
        } => (
            stage.label().into(),
            if *blocks > 0 {
                format!("{functions} functions · {blocks} blocks so far")
            } else {
                "Starting the analysis workers".into()
            },
        ),
        Load::Failed(e) => ("Could not open the binary".into(), e.clone()),
        Load::Ready => (String::new(), String::new()),
    };
    let welcome = matches!(app.load, Load::Empty);
    col()
        .w_full()
        .h_full()
        .center()
        .gap(8.0)
        .child(
            text(title)
                .font(TITLE.mono())
                .color(if matches!(app.load, Load::Failed(_)) {
                    p.bad
                } else {
                    p.text
                }),
        )
        .child(text(detail).font(UI).color(p.muted))
        .child(if welcome { el().h(10.0) } else { el() })
        .child(if welcome {
            open_button("Open binary…", true)
        } else {
            el()
        })
}
