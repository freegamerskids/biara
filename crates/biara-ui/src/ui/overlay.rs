//! Modal dialogs: go to anything, the command palette, and rename.
//!
//! One overlay serves all three. It owns a text field, a ranked list of results and a
//! selection; what a result does depends on the mode.

use rune::{Color, El, FileDialogOptions, Key, KeyEvent, TextEdit, Tx, col, el, row, text};
use rune_kit::TextInput;

use crate::backend::NameKind;

use super::{App, MainTab, bottom::BottomTab, parse_addr, theme::*, widgets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Goto,
    Commands,
    Rename { addr: u64, kind: NameKind },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Goto,
    Rename,
    OpenFile,
    Tab(MainTab),
    ToggleGraph,
    Back,
    Forward,
    Xrefs,
    Output,
    ToggleDemangle,
}

impl Command {
    const ALL: [(Command, &'static str, &'static str); 13] = [
        (Command::Goto, "Go to address or name…", "G"),
        (Command::Rename, "Rename the current symbol…", "N"),
        (Command::OpenFile, "Open binary…", "Ctrl+O"),
        (Command::Tab(MainTab::Listing), "Show disassembly", ""),
        (Command::Tab(MainTab::Graph), "Show graph", ""),
        (Command::Tab(MainTab::Pseudo), "Show pseudocode", "F5"),
        (Command::Tab(MainTab::Hex), "Show hex", ""),
        (
            Command::ToggleGraph,
            "Toggle graph and disassembly",
            "Space",
        ),
        (Command::Back, "Go back", "Esc"),
        (Command::Forward, "Go forward", "Alt+Right"),
        (Command::Xrefs, "Show cross-references", "X"),
        (Command::Output, "Show output", ""),
        (Command::ToggleDemangle, "Toggle demangled names", ""),
    ];
}

#[derive(Clone, Debug)]
pub enum Action {
    Goto(u64),
    Command(Command),
}

#[derive(Clone, Debug)]
pub struct Hit {
    pub label: String,
    pub detail: String,
    pub action: Action,
}

pub struct State {
    pub mode: Option<Mode>,
    pub input: TextEdit,
    pub hits: Vec<Hit>,
    pub selected: usize,
    /// Why the last submit was rejected (rename).
    pub error: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            mode: None,
            input: TextEdit::new(""),
            hits: Vec::new(),
            selected: 0,
            error: None,
        }
    }
}

const MAX_HITS: usize = 14;

/// Open the overlay in `mode`.
pub fn open(app: &mut App, mode: Mode) {
    let initial = match mode {
        Mode::Rename { addr, .. } => app.name_of(addr).unwrap_or_default(),
        _ => String::new(),
    };
    app.overlay = State {
        mode: Some(mode),
        input: TextEdit::new(initial),
        hits: Vec::new(),
        selected: 0,
        error: None,
    };
    update(app);
}

pub fn close(app: &mut App) {
    app.overlay = State::default();
}

/// Recompute the results for the current text.
pub fn update(app: &mut App) {
    let q = app.overlay.input.text.trim().to_owned();
    app.overlay.error = None;
    app.overlay.selected = 0;
    app.overlay.hits = match app.overlay.mode {
        Some(Mode::Goto) => goto_hits(app, &q),
        Some(Mode::Commands) => command_hits(&q),
        _ => Vec::new(),
    };
}

/// How well `hay` matches `needle` (lower is better); `None` if it does not.
fn rank(hay: &str, needle: &str) -> Option<u8> {
    let (h, n) = (hay.to_lowercase(), needle.to_lowercase());
    if h == n {
        Some(0)
    } else if h.starts_with(&n) {
        Some(1)
    } else if h.contains(&n) {
        Some(2)
    } else {
        None
    }
}

fn goto_hits(app: &App, q: &str) -> Vec<Hit> {
    if q.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    if let Some(addr) = parse_addr(q) {
        let place = match app.function_of(addr) {
            Some(f) if f != addr => format!("{}+{:#x}", app.label(f), addr - f),
            Some(f) => app.label(f),
            None => "address".into(),
        };
        hits.push(Hit {
            label: format!("{addr:#x}"),
            detail: place,
            action: Action::Goto(addr),
        });
    }
    let mut named: Vec<(u8, Hit)> = Vec::new();
    for f in &app.index.functions {
        let name = app.display_of(f.entry).unwrap_or_else(|| f.name.clone());
        if let Some(r) = rank_any(&app.search_names(f.entry, &f.name), q) {
            named.push((
                r,
                Hit {
                    label: name,
                    detail: format!("function  {:#x}", f.entry),
                    action: Action::Goto(f.entry),
                },
            ));
        }
    }
    for i in &app.index.imports {
        let shown = match &i.demangled {
            Some(d) if app.demangle => d.short.clone(),
            _ => i.name.clone(),
        };
        let mut forms = vec![i.name.as_str()];
        forms.extend(
            i.demangled
                .iter()
                .flat_map(|d| [d.short.as_str(), d.full.as_str()]),
        );
        if let Some(r) = rank_any(&forms, q) {
            named.push((
                r + 1,
                Hit {
                    label: shown,
                    detail: format!("import  {:#x}", i.slot),
                    action: Action::Goto(i.slot),
                },
            ));
        }
    }
    named.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.label.len().cmp(&b.1.label.len()))
    });
    hits.extend(named.into_iter().map(|(_, h)| h).take(MAX_HITS));
    if hits.len() < MAX_HITS {
        let room = MAX_HITS - hits.len();
        hits.extend(
            app.index
                .strings
                .iter()
                .filter(|s| rank(&s.text, q).is_some())
                .take(room.min(5))
                .map(|s| Hit {
                    label: format!("\"{}\"", s.text.replace('\n', " ")),
                    detail: format!("string  {:#x}", s.addr),
                    action: Action::Goto(s.addr),
                }),
        );
    }
    hits.truncate(MAX_HITS);
    hits
}

fn command_hits(q: &str) -> Vec<Hit> {
    // Real substring matches first (exact, prefix, contains), then letters-in-order matches.
    let mut hits: Vec<(u8, Hit)> = Command::ALL
        .iter()
        .filter_map(|&(c, label, keys)| {
            let rank = if q.is_empty() {
                0
            } else {
                rank(label, q).or_else(|| subsequence(label, q).then_some(3))?
            };
            Some((
                rank,
                Hit {
                    label: label.to_owned(),
                    detail: keys.to_owned(),
                    action: Action::Command(c),
                },
            ))
        })
        .collect();
    hits.sort_by_key(|(rank, _)| *rank);
    hits.into_iter().map(|(_, h)| h).collect()
}

/// Whether the letters of `needle` appear in order in `hay` (a fuzzy match).
fn subsequence(hay: &str, needle: &str) -> bool {
    let mut h = hay.chars().flat_map(char::to_lowercase);
    needle
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|c| !c.is_whitespace())
        .all(|n| h.any(|c| c == n))
}

/// Enter: run the selected result, or apply the rename.
pub fn submit(app: &mut App, tx: &mut Tx) {
    match app.overlay.mode {
        Some(Mode::Rename { addr, kind }) => {
            let name = app.overlay.input.text.trim().to_owned();
            match app.names.set(addr, kind, &name) {
                Ok(saved_error) => {
                    if let Some(e) = saved_error {
                        app.log.push(format!("names: could not save: {e}"));
                    }
                    app.names_changed();
                    close(app);
                }
                Err(e) => app.overlay.error = Some(e.to_string()),
            }
        }
        Some(_) => {
            let Some(hit) = app.overlay.hits.get(app.overlay.selected).cloned() else {
                return;
            };
            close(app);
            run(app, hit.action, tx);
        }
        None => {}
    }
}

pub fn run(app: &mut App, action: Action, tx: &mut Tx) {
    match action {
        Action::Goto(addr) => app.goto(addr, tx),
        Action::Command(c) => command(app, c, tx),
    }
}

pub fn command(app: &mut App, c: Command, tx: &mut Tx) {
    match c {
        Command::Goto => open(app, Mode::Goto),
        Command::Rename => {
            if let Some(m) = rename_mode(app) {
                open(app, m);
            }
        }
        Command::OpenFile => open_file(tx),
        Command::Tab(t) => app.select_tab(t, tx),
        Command::ToggleGraph => {
            let next = if app.main_tab == MainTab::Graph {
                MainTab::Listing
            } else {
                MainTab::Graph
            };
            app.select_tab(next, tx);
        }
        Command::Back => app.go_back(tx),
        Command::Forward => app.go_forward(tx),
        Command::Xrefs => app.bottom_tab = BottomTab::Xrefs,
        Command::Output => app.bottom_tab = BottomTab::Output,
        Command::ToggleDemangle => app.toggle_demangle(),
    }
}

/// What a rename would apply to: the symbol at the cursor, else the current function.
fn rename_mode(app: &App) -> Option<Mode> {
    let target = if app.index.base_name(app.cur).is_some() || app.names.get(app.cur).is_some() {
        app.cur
    } else {
        app.function_of(app.cur)?
    };
    let kind = if app.index.function(target).is_some() {
        NameKind::Function
    } else {
        NameKind::Data
    };
    Some(Mode::Rename { addr: target, kind })
}

/// Pick a binary with the system file dialog.
pub fn open_file(tx: &mut Tx) {
    let options = FileDialogOptions {
        title: "Open binary".into(),
        ..Default::default()
    };
    tx.open_file(options, |s: &mut App, result, _tx| match result {
        Ok(Some(path)) => s.open(path),
        Ok(None) => {}
        Err(e) => s.log.push(format!("open: {e}")),
    });
}

/// Keys for the whole window that open or act on dialogs. True if handled.
pub fn global_key(app: &mut App, key: &KeyEvent, tx: &mut Tx) -> bool {
    match &key.key {
        Key::Command('k') | Key::Command('p') if key.mods.cmd => {
            open(app, Mode::Commands);
            true
        }
        Key::Command('o') if key.mods.cmd => {
            open_file(tx);
            true
        }
        Key::Text(t) if !key.mods.cmd && !key.mods.alt => match t.as_str() {
            "g" => {
                open(app, Mode::Goto);
                true
            }
            "n" => match rename_mode(app) {
                Some(m) => {
                    open(app, m);
                    true
                }
                None => false,
            },
            "x" => {
                app.bottom_tab = BottomTab::Xrefs;
                true
            }
            _ => false,
        },
        _ => false,
    }
}

// View -------------------------------------------------------------------------------------

/// The overlay, if one is open.
pub fn view(app: &App) -> Option<El> {
    let mode = app.overlay.mode?;
    let p = colors();
    let (title, placeholder) = match mode {
        Mode::Goto => ("Go to", "Address, function, import or string".to_owned()),
        Mode::Commands => ("Commands", "Type a command".to_owned()),
        Mode::Rename { addr, .. } => ("Rename", format!("New name for {}", app.label(addr))),
    };
    let input = TextInput::new(&app.overlay.input)
        .placeholder(placeholder)
        .leading_icon(&widgets::SEARCH)
        .width(Some(554.0))
        .on_edit(|s: &mut App| &mut s.overlay.input)
        .on_change(|s: &mut App, _tx: &mut Tx| update(s))
        .on_submit(|s: &mut App, tx: &mut Tx| submit(s, tx))
        .on_key(|s: &mut App, k: &KeyEvent, _tx: &mut Tx| match k.key {
            Key::Down if !s.overlay.hits.is_empty() => {
                s.overlay.selected = (s.overlay.selected + 1) % s.overlay.hits.len();
                true
            }
            Key::Up if !s.overlay.hits.is_empty() => {
                s.overlay.selected =
                    (s.overlay.selected + s.overlay.hits.len() - 1) % s.overlay.hits.len();
                true
            }
            _ => false,
        })
        .build(kit());
    let mut card = col()
        .key("overlay-card")
        .w(580.0)
        .radius(12.0)
        .fill(p.raised)
        .border(1.0, p.line_strong)
        .shadow(18.0, 48.0, Color::BLACK.alpha(0.5))
        .child(
            row()
                .w_full()
                .px(16.0)
                .pt(12.0)
                .child(text(title).font(SMALL_MEDIUM).color(p.muted)),
        )
        .child(col().w_full().px(12.0).py(8.0).child(input));
    if let Some(e) = &app.overlay.error {
        card = card.child(
            row()
                .w_full()
                .px(16.0)
                .pb(10.0)
                .child(text(e.clone()).font(SMALL).color(p.bad)),
        );
    }
    if !app.overlay.hits.is_empty() {
        let mut list = col().w_full().pb(8.0).px(6.0);
        for (i, hit) in app.overlay.hits.iter().enumerate() {
            let action = hit.action.clone();
            let selected = i == app.overlay.selected;
            list = list.child(
                row()
                    .key(format!("hit{i}"))
                    .w_full()
                    .h(30.0)
                    .px(10.0)
                    .gap(12.0)
                    .items_center()
                    .radius(6.0)
                    .fill(if selected {
                        p.selected
                    } else {
                        Color::TRANSPARENT
                    })
                    .hover(p.hover)
                    .on_press_tx(move |s: &mut App, tx| {
                        close(s);
                        run(s, action.clone(), tx);
                    })
                    .child(
                        text(hit.label.clone())
                            .font(CODE)
                            .color(p.text)
                            .truncate()
                            .grow(1.0)
                            .min_w(0.0),
                    )
                    .child(text(hit.detail.clone()).font(SMALL).color(p.faint)),
            );
        }
        card = card.child(el().w_full().h(1.0).fill(p.line)).child(list);
    }
    Some(
        el().key("overlay")
            .absolute(0.0, 0.0)
            .w_full()
            .h_full()
            .fill(Color::BLACK.alpha(0.45))
            .items_start()
            .justify_center()
            .pt(110.0)
            .modal_tx(true, |s: &mut App, _tx: &mut Tx| close(s))
            .child(card),
    )
}

/// The best rank of `q` among several spellings of one name.
fn rank_any<S: AsRef<str>>(names: &[S], q: &str) -> Option<u8> {
    names.iter().filter_map(|n| rank(n.as_ref(), q)).min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substring_matches_outrank_scattered_letters() {
        let labels: Vec<_> = command_hits("gr").into_iter().map(|h| h.label).collect();
        let show = labels
            .iter()
            .position(|l| l == "Show graph")
            .expect("substring match listed");
        let goto = labels
            .iter()
            .position(|l| l == "Go to address or name…")
            .expect("fuzzy match listed");
        assert!(show < goto, "{labels:?}");
    }

    #[test]
    fn an_empty_query_lists_every_command_in_order() {
        assert_eq!(command_hits("").len(), Command::ALL.len());
        assert_eq!(
            command_hits("").first().map(|h| h.label.as_str()),
            Some("Go to address or name…")
        );
        assert!(command_hits("zzzz").is_empty());
    }
}
