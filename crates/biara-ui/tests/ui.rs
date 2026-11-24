//! Drive the real window state through Rune's headless runtime: keys, dialogs, clicks. Each
//! test opens a compiled program through the full backend, so what is asserted is what a
//! user would see happen.
#![cfg(target_os = "linux")]

use std::{path::PathBuf, process::Command};

use biara_session::OpenOptions;
use biara_ui::ui::{self, App, MainTab, overlay::Mode};
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

/// A function whose parameter 1 points at a four-field recovered struct: the layout analysis
/// names it `s1` and its fields `f_0`, `f_8`, `f_10`, `f_18` until a signature declares it.
const STRUCT_SOURCE: &str = r#"
struct four { unsigned long a, b, c, d; };
__attribute__((noinline,used)) unsigned long sum(unsigned long n, struct four *q) {
    return n + q->a + q->b + q->c + q->d;
}
__attribute__((noinline,used)) unsigned long caller(void) {
    struct four v = {1, 2, 3, 4};
    return sum(5, &v);
}
int main(void) { return caller() != 15; }
"#;

fn build(name: &str) -> PathBuf {
    build_source(name, SOURCE)
}

fn build_source(name: &str, source: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("program.c"), source).unwrap();
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
    runtime_with(name, None)
}

/// [`runtime`], recovering at most `max_blocks` blocks.
fn runtime_with(name: &str, max_blocks: Option<usize>) -> Runtime<App> {
    runtime_for(build(name), max_blocks)
}

/// A runtime for the fixture with a recovered struct parameter.
fn runtime_struct(name: &str) -> Runtime<App> {
    runtime_for(build_source(name, STRUCT_SOURCE), None)
}

fn runtime_for(binary: PathBuf, max_blocks: Option<usize>) -> Runtime<App> {
    let mut app = App::default();
    app.open_with(
        binary.clone(),
        OpenOptions {
            database: Some(binary.with_extension("sqlite")),
            worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
            max_blocks,
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

/// Everything the window currently draws, one text per line. Only accessible names: widget
/// keys are not drawn.
fn drawn(rt: &Runtime<App>) -> String {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
            out.push(name.to_owned());
        }
        for child in v
            .get("children")
            .and_then(|c| c.as_array())
            .into_iter()
            .flatten()
        {
            walk(child, out);
        }
    }
    let mut names = Vec::new();
    walk(&rt.accessibility_json(), &mut names);
    names.join("\n")
}

/// Run frames until the pseudocode for the viewed function arrives.
fn wait_pseudo(rt: &mut Runtime<App>) {
    for _ in 0..600 {
        if rt
            .state
            .pseudo
            .doc
            .as_ref()
            .is_some_and(|d| Some(d.entry) == rt.state.pseudo.entry)
        {
            settle(rt);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        rt.frame(1.0 / 60.0);
    }
    panic!("pseudocode never arrived");
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
    assert_eq!(rt.state.notes.get(leaf), None);

    for _ in 0..16 {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "scale_value");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.notes.get(leaf), Some("scale_value"));
    assert_eq!(rt.state.name_of(leaf).as_deref(), Some("scale_value"));
    assert_eq!(
        rt.state.label(leaf),
        "scale_value",
        "listings and graphs use the new name"
    );
    assert_eq!(rt.state.overlay.mode, None);
    // The saved file is the engine's own annotation format.
    let saved = std::fs::read_to_string(rt.state.notes.path().unwrap()).unwrap();
    assert!(saved.contains("scale_value"), "{saved}");
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
}

#[test]
fn renaming_a_local_in_the_pseudocode_updates_every_use_and_saves_it() {
    let mut rt = runtime("ui-local");
    let target = entry(&rt, "target");
    rt.state.cur = target;
    press(&mut rt, Key::Function(5));
    wait_pseudo(&mut rt);
    // Click a local in the pseudocode: the click highlights it by its emitted name.
    let candidates = rt.state.pseudo.doc.as_ref().unwrap().locals.clone();
    let emitted = candidates
        .iter()
        .find(|name| rt.find(&format!("w{name}")).is_some())
        .unwrap_or_else(|| panic!("none of {candidates:?} is on a mounted row"))
        .clone();
    let (x, y) = rt.find(&format!("w{emitted}")).unwrap();
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    assert_eq!(rt.state.pseudo.word.as_deref(), Some(emitted.as_str()));

    press(&mut rt, Key::Text("n".into()));
    assert!(
        matches!(
            &rt.state.overlay.mode,
            Some(Mode::RenameLocal { function, local })
                if *function == target && local == &emitted
        ),
        "{:?}",
        rt.state.overlay.mode
    );
    assert_eq!(
        rt.state.overlay.input.text, emitted,
        "the dialog starts with the name the view shows"
    );

    // A name another identifier already uses in the document is refused.
    for _ in 0..emitted.chars().count() {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "leaf");
    press(&mut rt, Key::Enter);
    assert!(
        rt.state.overlay.error.is_some(),
        "leaf is the callee's identifier in this function"
    );
    assert!(rt.state.overlay.mode.is_some(), "and the dialog stays open");
    assert_eq!(rt.state.notes.local(target, &emitted), None);

    for _ in 0..4 {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "renamed_value");
    press(&mut rt, Key::Enter);
    assert_eq!(
        rt.state.notes.local(target, &emitted),
        Some("renamed_value")
    );
    assert_eq!(rt.state.overlay.mode, None);
    let ui = drawn(&rt);
    assert!(ui.contains("renamed_value"), "{ui}");

    // The annotation file holds the emitted-to-display map for the function.
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(rt.state.notes.path().unwrap()).unwrap())
            .unwrap();
    assert_eq!(
        saved["functions"][target.to_string()]["locals"][&emitted],
        "renamed_value",
        "{saved}"
    );
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
}

#[test]
fn a_semicolon_comments_the_instruction_and_its_pseudocode_line() {
    let mut rt = runtime("ui-comment");
    let target = entry(&rt, "target");
    rt.state.cur = target;
    press(&mut rt, Key::Function(5));
    wait_pseudo(&mut rt);
    let doc = rt.state.pseudo.doc.clone().unwrap();
    // A line the decompiler maps to an instruction the listing shows as an instruction.
    let addr = (0..doc.lines.len())
        .find_map(|line| {
            doc.line_addresses(line).iter().copied().find(|&addr| {
                rt.state
                    .program
                    .as_ref()
                    .unwrap()
                    .listing
                    .heads
                    .iter()
                    .any(|h| h.addr == addr && h.kind == biara_session::HeadKind::Insn)
            })
        })
        .expect("a pseudocode line mapped to an instruction");

    // Show the listing at that instruction, then comment it with IDA's key.
    rt.state.main_tab = MainTab::Listing;
    settle(&mut rt);
    press(&mut rt, Key::Text("g".into()));
    type_text(&mut rt, &format!("{addr:#x}"));
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.cur, addr);
    press(&mut rt, Key::Text(";".into()));
    assert!(
        matches!(rt.state.overlay.mode, Some(Mode::Comment { addr: at }) if at == addr),
        "{:?}",
        rt.state.overlay.mode
    );
    assert_eq!(rt.state.overlay.input.text, "", "no comment yet");
    type_text(&mut rt, "first note");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.notes.comment(addr), Some("first note"));
    let ui = drawn(&rt);
    assert!(ui.contains("; first note"), "the row shows it: {ui}");

    // The decompiler reports the comment on the line that instruction produced.
    press(&mut rt, Key::Function(5));
    wait_pseudo(&mut rt);
    let ui = drawn(&rt);
    assert!(ui.contains("// first note"), "the line shows it: {ui}");
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
}

#[test]
fn notes_written_by_another_process_show_up_after_poll() {
    let mut rt = runtime("ui-external");
    let leaf = entry(&rt, "leaf");
    let path = rt.state.path.clone().unwrap();
    let mut other = biara_session::Notes::load(&path).0;
    other
        .set(leaf, biara_session::NameKind::Function, "outside_leaf")
        .unwrap();
    for _ in 0..300 {
        rt.frame(1.0 / 60.0);
        if rt.state.notes.get(leaf) == Some("outside_leaf") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        rt.state.notes.get(leaf),
        Some("outside_leaf"),
        "the watcher and poll took in the other process's write"
    );
    assert_eq!(rt.state.display_of(leaf).as_deref(), Some("outside_leaf"));
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
}

#[test]
fn a_signature_change_is_saved_and_redecompiles_the_function() {
    let mut rt = runtime("ui-signature");
    let target = entry(&rt, "target");
    rt.state.cur = target;
    press(&mut rt, Key::Function(5));
    wait_pseudo(&mut rt);
    let before = rt.state.pseudo.doc.clone().unwrap();
    press(&mut rt, Key::Text("y".into()));
    assert!(
        matches!(rt.state.overlay.mode, Some(Mode::Signature { function }) if function == target),
        "{:?}",
        rt.state.overlay.mode
    );
    assert_eq!(
        rt.state.overlay.input.text, before.signature,
        "the dialog starts with the shown signature"
    );

    for _ in 0..before.signature.chars().count() {
        press(&mut rt, Key::Backspace);
    }
    // A signature the engine rejects is put back: the dialog stays, the notes keep nothing.
    type_text(&mut rt, "not a signature");
    press(&mut rt, Key::Enter);
    assert!(
        rt.state.overlay.error.is_some(),
        "the engine's rejection is shown"
    );
    assert!(rt.state.overlay.mode.is_some(), "and the dialog stays open");
    assert_eq!(rt.state.notes.signature(target), None, "nothing was saved");

    for _ in 0.."not a signature".chars().count() {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "int target(unsigned long)");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.overlay.error, None, "{:?}", rt.state.overlay.error);
    assert_eq!(
        rt.state.notes.signature(target),
        Some("int target(unsigned long)")
    );

    // The signature changes the C, so the view must fetch a new decompilation rather than
    // keep showing the one made under the old calling convention.
    for _ in 0..600 {
        if rt
            .state
            .pseudo
            .doc
            .as_ref()
            .is_some_and(|doc| !std::sync::Arc::ptr_eq(doc, &before))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        rt.frame(1.0 / 60.0);
    }
    let after = rt.state.pseudo.doc.clone().unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&after, &before),
        "the shown document was replaced"
    );
    assert!(
        after.signature.contains("uint32_t target"),
        "the declared return type is in the new C: {}",
        after.signature
    );
    assert_ne!(
        after.signature, before.signature,
        "the signature actually changed"
    );
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
}

#[test]
fn a_struct_field_is_named_through_its_parameter_and_renamed() {
    let mut rt = runtime_struct("ui-struct-field");
    let sum = entry(&rt, "sum");
    rt.state.cur = sum;
    press(&mut rt, Key::Function(5));
    wait_pseudo(&mut rt);
    let before = rt.state.pseudo.doc.clone().unwrap();
    let layout = before
        .layouts
        .iter()
        .find(|layout| !layout.declared && layout.params.contains(&1))
        .unwrap_or_else(|| panic!("no recovered struct at parameter 1: {:?}", before.layouts));
    assert!(
        layout.fields.iter().any(|field| field.name == "f_8"),
        "the layout has a field at offset 8: {layout:?}"
    );

    // Click the `f_8` in `arg1->f_8`, then N: the struct is recovered, so the first dialog
    // asks for the permanent name of the struct parameter 1 points at.
    let (x, y) = rt.find("wf_8").expect("the field link is on a mounted row");
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    assert_eq!(rt.state.pseudo.word.as_deref(), Some("f_8"));
    press(&mut rt, Key::Text("n".into()));
    assert!(
        matches!(
            &rt.state.overlay.mode,
            Some(Mode::NameStruct { function, layout, .. })
                if *function == sum && layout.name == "s1"
        ),
        "{:?}",
        rt.state.overlay.mode
    );
    assert_eq!(
        rt.state.overlay.input.text, "",
        "the dialog asks for the permanent struct name"
    );
    type_text(&mut rt, "four");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.overlay.error, None, "{:?}", rt.state.overlay.error);
    assert!(
        matches!(
            &rt.state.overlay.mode,
            Some(Mode::RenameField { struct_name, offset, field })
                if struct_name == "four" && *offset == 8 && field == "f_8"
        ),
        "{:?}",
        rt.state.overlay.mode
    );
    assert_eq!(rt.state.overlay.input.text, "f_8");

    for _ in 0..3 {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "second");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.overlay.error, None, "{:?}", rt.state.overlay.error);
    assert_eq!(rt.state.overlay.mode, None);

    // The declared signature makes the engine bind the struct, so a new decompilation has to
    // arrive with the declared field name in place of the recovered one.
    for _ in 0..600 {
        if rt.state.pseudo.doc.as_ref().is_some_and(|doc| {
            !std::sync::Arc::ptr_eq(doc, &before) && doc.signature.contains("struct four")
        }) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        rt.frame(1.0 / 60.0);
    }
    let after = rt.state.pseudo.doc.clone().unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&after, &before),
        "the view fetched a new decompilation"
    );
    assert!(
        after.signature.contains("struct four"),
        "the declared struct is in the signature: {}",
        after.signature
    );
    let ui = drawn(&rt);
    assert!(ui.contains("second"), "the new field name is drawn: {ui}");
    assert!(
        !ui.contains("f_8"),
        "the recovered field name is gone: {ui}"
    );

    // Once the struct is declared, N on another field goes straight to the field dialog.
    settle(&mut rt);
    let (x, y) = rt.find("wf_0").expect("the other field link is mounted");
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    press(&mut rt, Key::Text("n".into()));
    assert!(
        matches!(
            &rt.state.overlay.mode,
            Some(Mode::RenameField { struct_name, offset, .. })
                if struct_name == "four" && *offset == 0
        ),
        "{:?}",
        rt.state.overlay.mode
    );
    press(&mut rt, Key::Escape);
    assert_eq!(rt.state.overlay.mode, None);

    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(rt.state.notes.path().unwrap()).unwrap())
            .unwrap();
    let fields = saved["structs"]["four"]["fields"]
        .as_array()
        .unwrap_or_else(|| panic!("no struct four: {saved}"));
    let field = fields
        .iter()
        .find(|field| field["offset"] == 8)
        .unwrap_or_else(|| panic!("no field at 8: {saved}"));
    assert_eq!(field["name"], "second", "{saved}");
    let signature = saved["functions"][sum.to_string()]["signature"]
        .as_str()
        .unwrap_or_else(|| panic!("no signature saved: {saved}"));
    assert!(
        signature.contains("struct four *"),
        "the signature names the struct: {signature}"
    );
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
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
        .notes
        .set(
            leaf,
            biara_session::NameKind::Function,
            "an_extremely_long_descriptive_function_name_for_leaf",
        )
        .unwrap();
    rt.state.names_changed();
    settle(&mut rt);
    let after = rt.state.graph.model.clone().unwrap().layout.width;
    assert!(after > before, "{before} -> {after}");
    let _ = std::fs::remove_file(rt.state.notes.path().unwrap());
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

#[test]
fn an_analysis_stopped_at_its_block_limit_is_raised_from_the_status_bar() {
    let mut rt = runtime_with("ui-limit", Some(4));
    assert_eq!(rt.state.block_limit_reached(), Some(4));
    let (x, y) = rt
        .find("raise-limit")
        .expect("the status bar offers to raise the limit");
    rt.pointer_down(x, y);
    rt.pointer_up(x, y);
    settle(&mut rt);
    assert_eq!(rt.state.overlay.mode, Some(Mode::BlockLimit));
    assert_eq!(
        rt.state.overlay.input.text, "8",
        "twice the limit it stopped at"
    );
    press(&mut rt, Key::Backspace);
    type_text(&mut rt, "lots");
    press(&mut rt, Key::Enter);
    assert!(rt.state.overlay.error.is_some(), "not a number");
    assert_eq!(rt.state.block_limit(), 4);
    for _ in 0..4 {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "1M");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.overlay.mode, None);
    assert_eq!(rt.state.block_limit(), 1_000_000);
    wait_ready(&mut rt);
    assert_eq!(
        rt.state.block_limit_reached(),
        None,
        "analysed again, whole"
    );
    assert!(rt.state.index.functions.iter().any(|f| f.name == "target"));
    assert!(rt.find("raise-limit").is_none());
}
