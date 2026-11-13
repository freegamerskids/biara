//! Mangled C++ and Rust names, from real compiler output, as the user sees them: in the sidebar,
//! the disassembly header, the pseudocode and the go-to search.
//!
//! What is asserted on is the window's accessibility tree, i.e. the text actually drawn.
#![cfg(target_os = "linux")]

use std::{path::PathBuf, process::Command};

use biara_ui::{
    backend::OpenOptions,
    ui::{self, App, MainTab, overlay::Mode},
};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

/// Freestanding C++ (no standard library): a namespaced const method, a template instance and,
/// through an asm label, a legacy-Rust-mangled symbol (the current rustc only writes v0).
const CPP: &str = r#"
namespace geometry {
struct Shape { int w, h; int area() const; };
__attribute__((noinline,used)) int Shape::area() const { int v = w; __asm__ volatile("" : "+r"(v)); return v * h; }
template <typename T> __attribute__((noinline,used)) T twice(T v) { __asm__ volatile("" : "+r"(v)); return v + v; }
template int twice<int>(int);
}
extern "C" int legacy_area(int) __asm__("_ZN7mycrate8geometry4area17h0123456789abcdefE");
extern "C" __attribute__((noinline,used)) int legacy_area(int v) { __asm__ volatile("" : "+r"(v)); return v * 5; }
extern "C" void _start() {
    geometry::Shape s{3, 4};
    int r = s.area() + geometry::twice<int>(2) + legacy_area(1);
    __asm__ volatile("mov $60, %%eax; syscall" :: "D"(r) : "rax");
    __builtin_unreachable();
}
"#;

const AREA: &str = "_ZNK8geometry5Shape4areaEv";
const TWICE: &str = "_ZN8geometry5twiceIiEET_S1_";
const LEGACY: &str = "_ZN7mycrate8geometry4area17h0123456789abcdefE";

const RUST: &str = r#"
#![no_std]
#![no_main]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
pub mod geometry {
    #[inline(never)]
    pub fn area(w: u32, h: u32) -> u32 { core::hint::black_box(w) * h }
}
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let r = geometry::area(3, 4);
    unsafe { core::arch::asm!("syscall", in("rax") 60, in("rdi") r, options(noreturn)) }
}
"#;

fn dir(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn check(out: std::process::Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn build_cpp(name: &str) -> PathBuf {
    let dir = dir(name);
    std::fs::write(dir.join("shapes.cpp"), CPP).unwrap();
    let binary = dir.join("shapes");
    check(
        Command::new(env!("BIARA_CLANG"))
            .args([
                "-x",
                "c++",
                "-std=c++17",
                "-O1",
                "-ffreestanding",
                "-fno-exceptions",
            ])
            .args([
                "-fno-rtti",
                "-fno-pie",
                "-nostdlib",
                "-static",
                "-fuse-ld=bfd",
            ])
            .arg(dir.join("shapes.cpp"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap(),
    );
    binary
}

fn build_rust(name: &str) -> PathBuf {
    let dir = dir(name);
    std::fs::write(dir.join("shapes.rs"), RUST).unwrap();
    let binary = dir.join("shapes");
    check(
        Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .args([
                "--edition",
                "2021",
                "--crate-type",
                "bin",
                "-C",
                "panic=abort",
            ])
            .args(["-C", "opt-level=1", "-C", "relocation-model=static"])
            .args(["-C", "link-arg=-nostartfiles", "-C", "link-arg=-nostdlib"])
            .args(["-C", "link-arg=-static", "-C", "link-arg=-fuse-ld=bfd"])
            .arg(dir.join("shapes.rs"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap(),
    );
    binary
}

fn runtime(binary: PathBuf) -> Runtime<App> {
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

fn entry(rt: &Runtime<App>, raw: &str) -> u64 {
    rt.state
        .index
        .functions
        .iter()
        .find(|f| f.name == raw)
        .unwrap_or_else(|| {
            let have: Vec<_> = rt.state.index.functions.iter().map(|f| &f.name).collect();
            panic!("no function {raw}; have {have:?}")
        })
        .entry
}

/// Everything the window currently draws, one text per line. Only the accessible names:
/// widget keys (which stay raw on purpose, for word highlighting) are not drawn.
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

fn toggle_from_palette(rt: &mut Runtime<App>) {
    rt.key(KeyEvent {
        key: Key::Command('k'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    settle(rt);
    type_text(rt, "demangle");
    press(rt, Key::Enter);
}

/// Run frames until the pseudocode for the current function has arrived.
fn wait_pseudo(rt: &mut Runtime<App>) {
    for _ in 0..600 {
        if rt
            .state
            .pseudo
            .doc
            .as_ref()
            .is_some_and(|d| d.entry == rt.state.cur)
        {
            settle(rt);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        rt.frame(1.0 / 60.0);
    }
    panic!("pseudocode never arrived");
}

#[test]
fn compiler_output_demangles_in_the_index_with_a_short_and_a_full_form() {
    let rt = runtime(build_cpp("dm-index"));
    let s = &rt.state;
    let (area, twice, legacy) = (entry(&rt, AREA), entry(&rt, TWICE), entry(&rt, LEGACY));
    assert_eq!(s.display_of(area).as_deref(), Some("geometry::Shape::area"));
    assert_eq!(
        s.full_name_of(area).as_deref(),
        Some("geometry::Shape::area() const")
    );
    assert_eq!(s.display_of(twice).as_deref(), Some("geometry::twice<int>"));
    assert_eq!(
        s.full_name_of(twice).as_deref(),
        Some("int geometry::twice<int>(int)")
    );
    // The legacy Rust scheme: the hash is gone.
    assert_eq!(
        s.display_of(legacy).as_deref(),
        Some("mycrate::geometry::area")
    );
    // Plain C names are untouched, and the raw name is still what the binary says.
    assert_eq!(
        s.display_of(entry(&rt, "_start")).as_deref(),
        Some("_start")
    );
    assert_eq!(s.name_of(area).as_deref(), Some(AREA));
    assert_eq!(s.index.function(area).unwrap().name, AREA);
}

#[test]
fn the_sidebar_header_and_pseudocode_show_demangled_names_until_switched_off() {
    let mut rt = runtime(build_cpp("dm-views"));
    let (area, start) = (entry(&rt, AREA), entry(&rt, "_start"));

    // Disassembly: the function list, and a header with the full signature plus the raw name.
    rt.state.main_tab = MainTab::Listing;
    rt.state.goto_for_test(area);
    settle(&mut rt);
    let ui = drawn(&rt);
    assert!(ui.contains("geometry::Shape::area() const"), "header: {ui}");
    assert!(
        ui.contains("geometry::twice&lt;int&gt;") || ui.contains("geometry::twice<int>"),
        "sidebar: {ui}"
    );
    assert!(
        ui.contains(AREA),
        "the raw name stays visible in the header comment"
    );

    // Pseudocode of the caller names the callees readably.
    rt.state.goto_for_test(start);
    press(&mut rt, Key::Function(5));
    wait_pseudo(&mut rt);
    let ui = drawn(&rt);
    assert!(ui.contains("geometry::Shape::area"), "{ui}");
    assert!(ui.contains("mycrate::geometry::area"), "{ui}");
    assert!(
        !ui.contains(AREA),
        "no raw name where the demangled one belongs: {ui}"
    );

    // Switching off (as a user does, from the command palette) shows the linker's names
    // everywhere.
    toggle_from_palette(&mut rt);
    let ui = drawn(&rt);
    assert!(ui.contains(AREA) && ui.contains(LEGACY), "{ui}");
    assert!(!ui.contains("geometry::Shape::area"), "{ui}");
    toggle_from_palette(&mut rt);
    assert!(drawn(&rt).contains("geometry::Shape::area"));
}

#[test]
fn the_command_palette_toggles_demangling() {
    let mut rt = runtime(build_cpp("dm-palette"));
    assert!(rt.state.demangle);
    rt.key(KeyEvent {
        key: Key::Command('k'),
        mods: Mods {
            cmd: true,
            ..Mods::default()
        },
    });
    settle(&mut rt);
    type_text(&mut rt, "demangle");
    press(&mut rt, Key::Enter);
    assert!(!rt.state.demangle, "the command flipped it");
    assert_eq!(rt.state.display_of(entry(&rt, AREA)).as_deref(), Some(AREA));
}

#[test]
fn go_to_finds_a_symbol_by_what_the_user_sees_or_what_the_linker_wrote() {
    let mut rt = runtime(build_cpp("dm-search"));
    let area = entry(&rt, AREA);
    for query in [
        "Shape::area",
        "Shape::area() const",
        "_ZNK8geometry5Shape4area",
        "geometry::Shape",
    ] {
        press(&mut rt, Key::Text("g".into()));
        assert_eq!(rt.state.overlay.mode, Some(Mode::Goto));
        type_text(&mut rt, query);
        let hit = rt
            .state
            .overlay
            .hits
            .first()
            .unwrap_or_else(|| panic!("no hit for {query:?}"));
        assert_eq!(
            hit.label, "geometry::Shape::area",
            "{query:?}: {:?}",
            rt.state.overlay.hits
        );
        press(&mut rt, Key::Enter);
        assert_eq!(rt.state.cur, area, "{query:?}");
        rt.state.goto_for_test(entry(&rt, "_start"));
        settle(&mut rt);
    }
    // The sidebar filter takes the same spellings.
    rt.state.filter.text = "area() const".into();
    rt.state.names_changed();
    let shown: Vec<_> = rt
        .state
        .sidebar
        .functions
        .iter()
        .map(|&i| &rt.state.index.functions[i as usize].name)
        .collect();
    assert_eq!(shown, [AREA], "filtering on the demangled signature");
}

#[test]
fn a_users_rename_wins_over_the_demangled_name() {
    let mut rt = runtime(build_cpp("dm-rename"));
    let area = entry(&rt, AREA);
    rt.state.cur = area;
    press(&mut rt, Key::Text("n".into()));
    assert!(matches!(rt.state.overlay.mode, Some(Mode::Rename { addr, .. }) if addr == area));
    for _ in 0..AREA.len() {
        press(&mut rt, Key::Backspace);
    }
    type_text(&mut rt, "shape_area");
    press(&mut rt, Key::Enter);
    assert_eq!(rt.state.display_of(area).as_deref(), Some("shape_area"));
    assert_eq!(
        rt.state.full_name_of(area),
        None,
        "a renamed function has no demangled header"
    );
    let _ = std::fs::remove_file(rt.state.names.path().unwrap());
}

#[test]
fn rust_v0_symbols_from_rustc_demangle() {
    let rt = runtime(build_rust("dm-rust"));
    let area = rt
        .state
        .index
        .functions
        .iter()
        .find(|f| f.name.starts_with("_R") && f.name.ends_with("8geometry4area"))
        .unwrap_or_else(|| panic!("no v0 symbol: {:?}", rt.state.index.functions));
    assert_eq!(
        rt.state.display_of(area.entry).as_deref(),
        Some("shapes::geometry::area")
    );
    // Rust names carry no parameter list, so the full form is the same.
    assert_eq!(
        rt.state.full_name_of(area.entry).as_deref(),
        Some("shapes::geometry::area")
    );
}
