//! Drive the real window state through Rune's headless runtime: keys, dialogs, clicks. Each
//! test opens a compiled program through the full backend, so what is asserted is what a
//! user would see happen.
#![cfg(target_os = "linux")]

use std::{path::PathBuf, process::Command};

use biara_ui::{
    backend::OpenOptions,
    ui::{self, App, MainTab, overlay::Mode},
};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const SOURCE: &str = r#"
extern int puts(const char *);
__attribute__((noinline,used)) unsigned long leaf(unsigned long v) { __asm__ volatile("" : "+r"(v)); return v * 3 + 1; }
__attribute__((noinline,used)) unsigned long target(unsigned long n) {
    unsigned long t = 0;
    for (unsigned long i = 0; i < n; i++) t += leaf(i);
    return t;
}
__attribute__((noinline,used)) int message(void) { return puts("ui fixture string"); }
int main(void) { return target(3) != 12; }
"#;

fn build(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("program.c"), SOURCE).unwrap();
    let binary = dir.join("program");
    let out = Command::new(env!("BIARA_CLANG"))
        .args(["-O1", "-fno-builtin", "-fno-pie", "-no-pie", "-fuse-ld=bfd"])
        .arg(dir.join("program.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    binary
}

/// A runtime showing the analysed program, with the app's own hooks.
fn runtime(name: &str) -> Runtime<App> {
    let binary = build(name);
    let mut app = App::default();
    app.open_with(
        binary.clone(),
        OpenOptions {
            database: Some(binary.with_extension("sqlite")),
            worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
            ..Default::default()
        },
    );
    app.wait_until_ready();
    let mut rt = Runtime::new(
        app,
        ui::view,
        (1280.0, 800.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(ui::poll);
    rt.on_key = Some(ui::on_key);
    settle(&mut rt);
    rt
}

fn settle(rt: &mut Runtime<App>) {
    for _ in 0..30 {
        rt.frame(1.0 / 60.0);
    }
}

fn press(rt: &mut Runtime<App>, key: Key) {
    rt.key(KeyEvent {
        key,
        mods: Mods::default(),
    });
    settle(rt);
}

fn type_text(rt: &mut Runtime<App>, s: &str) {
    for c in s.chars() {
        rt.key(KeyEvent {
            key: Key::Text(c.to_string()),
            mods: Mods::default(),
        });
    }
    settle(rt);
}

fn entry(rt: &Runtime<App>, name: &str) -> u64 {
    rt.state
        .index
        .functions
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"))
        .entry
}

#[test]
fn go_to_finds_a_function_by_name_and_back_returns() {
    let mut rt = runtime("ui-goto");
    let (target, start) = (entry(&rt, "target"), rt.state.cur);
    press(&mut rt, Key::Text("g".into()));
    assert_eq!(rt.state.overlay.mode, Some(Mode::Goto), "g opens go-to");
    type_text(&mut rt, "targ");
    assert_eq!(
        rt.state.overlay.hits.first().map(|h| h.label.as_str()),
        Some("target"),
        "{:?}",
        rt.state.overlay.hits
    );
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.cur, target);
    assert_eq!(rt.state.overlay.mode, None, "the dialog closed");
    press(&mut rt, Key::Escape);
    assert_eq!(rt.state.cur, start, "Escape goes back to where we were");
}

#[test]
fn go_to_accepts_an_address_and_a_string() {
    let mut rt = runtime("ui-goto2");
    let leaf = entry(&rt, "leaf");
    press(&mut rt, Key::Text("g".into()));
    type_text(&mut rt, &format!("{:#x}", leaf + 1));
    assert!(
        rt.state.overlay.hits[0].detail.starts_with("leaf+0x1"),
        "{:?}",
        rt.state.overlay.hits[0]
    );
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.cur, leaf + 1);

    press(&mut rt, Key::Text("g".into()));
    type_text(&mut rt, "fixture str");
    let string = rt
        .state
        .index
        .strings
        .iter()
        .find(|s| s.text == "ui fixture string")
        .unwrap()
        .addr;
    assert!(
        rt.state
            .overlay
            .hits
            .iter()
            .any(|h| h.detail.starts_with("string") && h.detail.contains(&format!("{string:#x}"))),
        "{:?}",
        rt.state.overlay.hits
    );
}

#[test]
fn rename_applies_everywhere_and_rejects_bad_names() {
    let mut rt = runtime("ui-rename");
    let leaf = entry(&rt, "leaf");
    rt.state.cur = leaf;
    press(&mut rt, Key::Text("n".into()));
    assert!(matches!(rt.state.overlay.mode, Some(Mode::Rename { addr, .. }) if addr == leaf));
    // The dialog starts with the current name; replace it.
    for _ in 0..4 {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "not valid");
    press(&mut rt, Key::Enter);
    assert!(
        rt.state.overlay.error.is_some(),
        "a name with a space is refused"
    );
    assert!(rt.state.overlay.mode.is_some(), "and the dialog stays open");
    assert_eq!(rt.state.names.get(leaf), None);

    for _ in 0..16 {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "scale_value");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.names.get(leaf), Some("scale_value"));
    assert_eq!(rt.state.name_of(leaf).as_deref(), Some("scale_value"));
    assert_eq!(
        rt.state.label(leaf),
        "scale_value",
        "listings and graphs use the new name"
    );
    assert_eq!(rt.state.overlay.mode, None);
    // The saved file is the engine's own annotation format.
    let saved = std::fs::read_to_string(rt.state.names.path().unwrap()).unwrap();
    assert!(saved.contains("scale_value"), "{saved}");
    let _ = std::fs::remove_file(rt.state.names.path().unwrap());
}

#[test]
fn the_command_palette_switches_views() {
    let mut rt = runtime("ui-palette");
    rt.key(KeyEvent {
        key: Key::Command('k'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    settle(&mut rt);
    assert_eq!(rt.state.overlay.mode, Some(Mode::Commands));
    type_text(&mut rt, "hex");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.main_tab, MainTab::Hex);
    // Space toggles disassembly and graph; F5 pseudocode.
    rt.state.main_tab = MainTab::Listing;
    press(&mut rt, Key::Text(" ".into()));
    assert_eq!(rt.state.main_tab, MainTab::Graph);
    press(&mut rt, Key::Text(" ".into()));
    assert_eq!(rt.state.main_tab, MainTab::Listing);
    press(&mut rt, Key::Function(5));
    assert_eq!(rt.state.main_tab, MainTab::Pseudo);
}

#[test]
fn clicking_a_function_in_the_sidebar_navigates_and_filtering_narrows_the_list() {
    let mut rt = runtime("ui-sidebar");
    let message = entry(&rt, "message");
    let row = rt
        .state
        .sidebar
        .functions
        .iter()
        .position(|&i| rt.state.index.functions[i as usize].entry == message)
        .unwrap();
    let (x, y) = rt
        .find(&format!("fn{row}"))
        .unwrap_or_else(|| panic!("row fn{row} is not mounted"));
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    assert_eq!(rt.state.cur, message);

    // Typing in the filter field narrows the list to matches.
    let all = rt.state.sidebar.functions.len();
    rt.state.filter = rune::TextEdit::new("leaf");
    rt.state.sidebar.rebuild(&rt.state.index.clone(), "leaf");
    settle(&mut rt);
    let names: Vec<_> = rt
        .state
        .sidebar
        .functions
        .iter()
        .map(|&i| rt.state.index.functions[i as usize].name.as_str())
        .collect();
    assert_eq!(names, ["leaf"], "{names:?} of {all}");
}

#[test]
fn pseudocode_arrives_for_the_current_function_and_follows_navigation() {
    let mut rt = runtime("ui-pseudo");
    let (target, leaf) = (entry(&rt, "target"), entry(&rt, "leaf"));
    rt.state.cur = target;
    press(&mut rt, Key::Function(5));
    // The decompiler runs on its own thread; frames poll for it.
    for _ in 0..600 {
        if rt.state.pseudo.doc.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        rt.frame(1.0 / 60.0);
    }
    let doc = rt.state.pseudo.doc.clone().expect("pseudocode arrived");
    assert_eq!(doc.entry, target);
    assert!(doc.body.contains("leaf("), "{}", doc.body);
    // Going to `leaf` retargets the view and drops the old document.
    rt.state.goto_for_test(leaf);
    settle(&mut rt);
    assert_eq!(rt.state.pseudo.entry, Some(leaf));
    assert!(
        rt.state.pseudo.doc.as_ref().is_none_or(|d| d.entry == leaf),
        "never shows another function's code"
    );
}

#[test]
fn the_graph_shows_the_current_function_and_a_rename_relays_it_out() {
    let mut rt = runtime("ui-graph");
    let target = entry(&rt, "target");
    rt.state.cur = target;
    press(&mut rt, Key::Text(" ".into())); // listing -> graph
    assert_eq!(rt.state.main_tab, MainTab::Graph);
    let model = rt.state.graph.model.clone().expect("graph built");
    assert_eq!(model.flow.entry, target);
    assert!(model.flow.nodes.len() >= 3);
    assert!(rt.find("n0").is_some(), "node elements are mounted");
    // A much longer name widens nodes that print it, so the layout must be rebuilt.
    let before = model.layout.width;
    let leaf = entry(&rt, "leaf");
    rt.state
        .names
        .set(
            leaf,
            biara_ui::backend::NameKind::Function,
            "an_extremely_long_descriptive_function_name_for_leaf",
        )
        .unwrap();
    rt.state.names_changed();
    settle(&mut rt);
    let after = rt.state.graph.model.clone().unwrap().layout.width;
    assert!(after > before, "{before} -> {after}");
    let _ = std::fs::remove_file(rt.state.names.path().unwrap());
}

/// Frames until the app has finished opening `rt`'s binary.
fn wait_ready(rt: &mut Runtime<App>) {
    for _ in 0..1500 {
        if matches!(rt.state.load, ui::Load::Ready) {
            return;
        }
        if let ui::Load::Failed(e) = &rt.state.load {
            panic!("open failed: {e}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        rt.frame(1.0 / 60.0);
    }
    panic!("never became ready");
}

fn empty_runtime(binary: &std::path::Path) -> Runtime<App> {
    let mut app = App::default();
    app.open_options = OpenOptions {
        database: Some(binary.with_extension("sqlite")),
        worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
        ..Default::default()
    };
    let mut rt = Runtime::new(
        app,
        ui::view,
        (1280.0, 800.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(ui::poll);
    rt.on_key = Some(ui::on_key);
    settle(&mut rt);
    rt
}

#[test]
fn the_open_button_shows_the_file_dialog_and_the_chosen_binary_is_analysed() {
    let binary = build("ui-open");
    let mut rt = empty_runtime(&binary);
    assert!(matches!(rt.state.load, ui::Load::Empty));
    assert!(rt.state.path.is_none());
    let (x, y) = rt
        .find("open-button")
        .expect("the welcome screen has an Open button");
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    assert!(
        rt.file_dialog().is_some(),
        "the button asked for a file dialog"
    );
    rt.resolve_file_dialog(Some(binary.clone()))
        .expect("the dialog was open");
    settle(&mut rt);
    assert_eq!(rt.state.path.as_deref(), Some(binary.as_path()));
    wait_ready(&mut rt);
    assert!(rt.state.index.functions.iter().any(|f| f.name == "target"));
    // Cancelling leaves things as they are.
    let (x, y) = rt
        .find("open-button")
        .expect("the toolbar keeps an Open button");
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    rt.resolve_file_dialog(None).expect("the dialog was open");
    settle(&mut rt);
    assert!(
        matches!(rt.state.load, ui::Load::Ready),
        "a cancelled dialog changes nothing"
    );
}

#[test]
fn a_missing_file_is_reported_not_swallowed() {
    let mut rt = empty_runtime(&PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("nothing-here"));
    rt.state
        .open(PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("does-not-exist"));
    for _ in 0..500 {
        if matches!(rt.state.load, ui::Load::Failed(_)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        rt.frame(1.0 / 60.0);
    }
    let ui::Load::Failed(message) = &rt.state.load else {
        panic!("expected a failure, got {:?}", rt.state.load)
    };
    assert!(message.contains("does-not-exist"), "{message}");
    assert!(
        rt.state.log.iter().any(|l| l.contains("does-not-exist")),
        "the output panel has it too"
    );
}

#[test]
fn analysis_started_before_the_window_has_a_waker_still_wakes_it() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // `init` starts the analysis from the command line before Rune calls `setup` with the
    // waker; the events that finish afterwards must still wake the window, or it would sit on
    // "Recovering…" forever (it did, in the real window).
    let binary = build("ui-waker");
    let mut app = App::default();
    app.open_with(
        binary.clone(),
        OpenOptions {
            database: Some(binary.with_extension("sqlite")),
            worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
            ..Default::default()
        },
    );
    let wakes = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = wakes.clone();
    ui::setup(
        &mut app,
        std::sync::Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
    );
    app.wait_until_ready();
    assert!(
        wakes.load(Ordering::SeqCst) > 0,
        "no wake reached the window after setup"
    );
}

#[test]
fn arrow_keys_step_the_cursor_through_the_listing_row_by_row() {
    let mut rt = runtime("ui-arrows");
    let leaf = entry(&rt, "leaf");
    rt.state.main_tab = MainTab::Listing;
    rt.state.cur = leaf;
    press(&mut rt, Key::Down);
    let first = rt.state.cur;
    assert!(first >= leaf, "moved forward");
    // The first instruction of leaf, then the next one: strictly increasing addresses.
    press(&mut rt, Key::Down);
    let second = rt.state.cur;
    assert!(second > first, "{first:#x} -> {second:#x}");
    press(&mut rt, Key::Up);
    assert_eq!(rt.state.cur, first, "Up undoes Down");
    // Still inside the same function while stepping through it.
    assert_eq!(rt.state.function_of(rt.state.cur), Some(leaf));
}

#[test]
fn dialogs_are_drawn_over_the_window_not_beside_it() {
    // `rune_kit::root` lays children out in a row, so an overlay that is not absolutely
    // positioned lands to the right of the page: open, but invisible. Check the geometry.
    let mut rt = runtime("ui-geometry");
    for (label, key, cmd) in [
        ("go to", Key::Text("g".into()), false),
        ("commands", Key::Command('k'), true),
    ] {
        rt.key(KeyEvent {
            key,
            mods: Mods {
                cmd,
                ..Mods::default()
            },
        });
        settle(&mut rt);
        let (rect, _) = rt
            .presented("overlay-card")
            .unwrap_or_else(|| panic!("{label}: no dialog card"));
        let [x, y, w, h] = rect;
        assert!(
            x >= 0.0 && x + w <= 1280.0 && y >= 0.0 && y + h <= 800.0,
            "{label}: card {rect:?} is outside the 1280x800 window"
        );
        assert!(
            ((x + w / 2.0) - 640.0).abs() < 2.0,
            "{label}: card is not centred horizontally: {rect:?}"
        );
        press(&mut rt, Key::Escape);
        assert!(rt.state.overlay.mode.is_none(), "{label}: Escape closes it");
    }
}
