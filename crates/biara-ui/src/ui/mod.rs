//! The workbench window: state, navigation and the shell around the views.
//!
//! One [`App`] owns everything the window shows. The analysis runs on background threads
//! (see `backend`) and reports through a channel that [`poll`] drains before every frame, so
//! the window never waits for the engine. Views are plain functions of `&App`.

pub mod bottom;
pub mod code;
pub mod graph_view;
pub mod hex;
pub mod listing;
pub mod overlay;
pub mod pseudo;
pub mod sidebar;
pub mod theme;
pub mod widgets;

use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
};

use biara_loader::Image;
use rune::{AppSpec, Cx, El, Key, KeyEvent, TextEdit, Tx, Waker, col, el, row};

use crate::backend::{self, Arch, Decompiler, Event, Index, Names, Program, Stage};
use theme::colors;

pub use bottom::BottomTab;
pub use sidebar::SideTab;

/// Where opening the binary stands.
#[derive(Clone, Debug)]
pub enum Load {
    /// No binary given.
    Empty,
    Opening {
        stage: Stage,
        functions: usize,
        blocks: usize,
    },
    Failed(String),
    Ready,
}

/// The views in the main area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainTab {
    Listing,
    Graph,
    Pseudo,
    Hex,
}

impl MainTab {
    pub const ALL: [MainTab; 4] = [
        MainTab::Listing,
        MainTab::Graph,
        MainTab::Pseudo,
        MainTab::Hex,
    ];

    pub fn label(self) -> &'static str {
        match self {
            MainTab::Listing => "Disassembly",
            MainTab::Graph => "Graph",
            MainTab::Pseudo => "Pseudocode",
            MainTab::Hex => "Hex",
        }
    }
}

pub struct App {
    /// The window's waker. Rune hands it over in `setup`, after `init` may already have started
    /// the analysis, so threads notify through this shared slot and not a copy.
    waker: Arc<parking_lot::Mutex<Option<Waker>>>,
    events: Option<mpsc::Receiver<Event>>,
    pub path: Option<PathBuf>,
    /// How the engine is run; kept so dropping a second file opens it the same way.
    pub open_options: backend::OpenOptions,
    pub load: Load,
    pub arch: Option<Arch>,
    pub image: Option<Arc<Image>>,
    /// The function table: from symbols while recovery runs, then from the program.
    pub index: Arc<Index>,
    pub program: Option<Arc<Program>>,
    pub decomp: Option<Decompiler>,
    pub names: Names,
    /// Messages for the output panel, oldest first.
    pub log: Vec<String>,

    /// The address the user is looking at.
    pub cur: u64,
    back: Vec<u64>,
    forward: Vec<u64>,

    pub side_w: f32,
    pub side_tab: SideTab,
    pub main_tab: MainTab,
    pub filter: TextEdit,
    pub sidebar: sidebar::Lists,
    pub listing: listing::State,
    pub pseudo: pseudo::State,
    pub graph: graph_view::State,
    pub hex: hex::State,
    pub bottom_tab: BottomTab,
    pub bottom_h: f32,
    pub overlay: overlay::State,
    /// Show demangled C++ and Rust names (the raw linker names stay what is saved and searched).
    pub demangle: bool,
    /// Bumped when anything that changes how names print changes, so views rebuild.
    display_epoch: u64,
    /// Scroll to `cur` on the next frame (after analysis, or a command-line `--goto`).
    reveal_pending: bool,
}

impl Default for App {
    fn default() -> Self {
        App {
            waker: Arc::default(),
            events: None,
            path: None,
            open_options: backend::OpenOptions::default(),
            load: Load::Empty,
            arch: None,
            image: None,
            index: Arc::new(Index::default()),
            program: None,
            decomp: None,
            names: Names::in_memory(),
            log: Vec::new(),
            cur: 0,
            back: Vec::new(),
            forward: Vec::new(),
            side_w: 300.0,
            side_tab: SideTab::Functions,
            main_tab: MainTab::Listing,
            filter: TextEdit::new(""),
            sidebar: sidebar::Lists::default(),
            listing: listing::State::default(),
            pseudo: pseudo::State::default(),
            graph: graph_view::State::default(),
            hex: hex::State::default(),
            bottom_tab: BottomTab::Xrefs,
            bottom_h: 190.0,
            overlay: overlay::State::default(),
            demangle: true,
            display_epoch: 0,
            reveal_pending: false,
        }
    }
}

// Startup ----------------------------------------------------------------------------------

/// Command line: `biara-ui [BINARY] [--sync] [--goto ADDR|NAME] [--tab listing|pseudo]`.
/// `--sync` waits for analysis (and the requested view) before the first frame, which is what
/// a headless snapshot needs.
struct Args {
    path: Option<PathBuf>,
    sync: bool,
    goto: Option<String>,
    tab: Option<MainTab>,
}

fn args() -> Args {
    let mut a = Args {
        path: None,
        sync: false,
        goto: None,
        tab: None,
    };
    let mut it = rune::extra_args().iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--sync" => a.sync = true,
            "--goto" => a.goto = it.next().cloned(),
            "--tab" => {
                a.tab = it.next().and_then(|v| match v.as_str() {
                    "listing" | "disasm" => Some(MainTab::Listing),
                    "graph" => Some(MainTab::Graph),
                    "pseudo" | "pseudocode" => Some(MainTab::Pseudo),
                    "hex" => Some(MainTab::Hex),
                    _ => None,
                })
            }
            other if !other.starts_with("--") && a.path.is_none() => {
                a.path = Some(PathBuf::from(other))
            }
            _ => {}
        }
    }
    a
}

/// `0x401000`, `401000h` or decimal.
pub fn parse_addr(text: &str) -> Option<u64> {
    let t = text.trim().trim_start_matches('*');
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        return u64::from_str_radix(h, 16).ok();
    }
    t.parse().ok().or_else(|| u64::from_str_radix(t, 16).ok())
}

fn init() -> App {
    let args = args();
    let mut app = App::default();
    if let Some(path) = args.path {
        app.open(path);
    }
    if args.sync {
        app.wait_until_ready();
    }
    if let Some(target) = args.goto {
        // An address, or the name of a function.
        let addr = parse_addr(&target).or_else(|| {
            app.index
                .functions
                .iter()
                .find(|f| app_names_match(&app.index, f, &target))
                .map(|f| f.entry)
        });
        if let Some(addr) = addr {
            app.cur = addr;
            app.reveal_pending = true;
        }
    }
    if let Some(tab) = args.tab {
        app.main_tab = tab;
    }
    app.refresh_pseudo();
    if args.sync {
        app.wait_for_pseudocode();
    }
    app
}

/// Called once with the window's waker. Analysis started in `init` (a path on the command
/// line) is already running; it finds the waker in the shared slot from now on.
pub fn setup(app: &mut App, waker: Waker) {
    *app.waker.lock() = Some(waker);
}

impl App {
    /// Start analysing `path`. Replaces whatever was open.
    pub fn open(&mut self, path: PathBuf) {
        let options = self.open_options.clone();
        self.open_with(path, options);
    }

    /// [`App::open`] with explicit engine settings (tests point the workers at the built binary).
    pub fn open_with(&mut self, path: PathBuf, options: backend::OpenOptions) {
        let notify = self.notify();
        *self = App {
            waker: self.waker.clone(),
            demangle: self.demangle,
            side_w: self.side_w,
            open_options: options.clone(),
            ..App::default()
        };
        let (names, problem) = Names::load(&path);
        self.names = names;
        if let Some(p) = problem {
            self.log.push(format!("names: {p}"));
        }
        self.load = Load::Opening {
            stage: Stage::Loading,
            functions: 0,
            blocks: 0,
        };
        self.events = Some(backend::recovery::open(path.clone(), notify, options));
        self.path = Some(path);
    }

    /// Block until analysis finishes (or fails): for headless runs and tests.
    pub fn wait_until_ready(&mut self) {
        while matches!(self.load, Load::Opening { .. }) {
            let Some(events) = &self.events else { return };
            match events.recv() {
                Ok(event) => self.apply(event),
                Err(_) => return,
            }
        }
    }

    /// Block until the pseudocode for the current function is ready (or failed), if that view
    /// is showing. For headless runs.
    fn wait_for_pseudocode(&mut self) {
        if self.main_tab != MainTab::Pseudo {
            return;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while self.pseudo.doc.is_none() && std::time::Instant::now() < deadline {
            if let Some(entry) = self.pseudo.entry {
                if matches!(
                    self.decomp.as_ref().map(|d| d.status(entry)),
                    Some(crate::backend::decomp::Status::Failed(_)) | None
                ) {
                    return;
                }
            } else {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            self.refresh_pseudo();
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Opened {
                image,
                preview,
                arch,
            } => {
                self.arch = Some(arch);
                self.cur = image.entry;
                self.hex.rebuild(&image);
                self.image = Some(image);
                self.index = preview;
                self.sidebar.rebuild(&self.index, &self.filter.text);
            }
            Event::Progress {
                stage,
                functions,
                blocks,
            } => {
                self.load = Load::Opening {
                    stage,
                    functions,
                    blocks,
                };
            }
            Event::Ready(program) => {
                self.index = program.index.clone();
                self.decomp = Some(Decompiler::new(program.clone(), self.notify()));
                self.program = Some(program);
                self.load = Load::Ready;
                self.sidebar.rebuild(&self.index, &self.filter.text);
                self.listing.invalidate();
                self.refresh_pseudo();
                // Start where a reverse engineer would: `main` if there is one, else the entry.
                let start = self
                    .index
                    .functions
                    .iter()
                    .find(|f| f.name == "main")
                    .map_or(self.cur, |f| f.entry);
                self.cur = start;
                self.reveal_pending = true;
                self.log.push(format!(
                    "{} functions, {} strings",
                    self.index.functions.len(),
                    self.index.strings.len()
                ));
            }
            Event::Failed(message) => {
                self.log.push(message.clone());
                self.load = Load::Failed(message);
            }
        }
    }

    fn notify(&self) -> backend::Notify {
        let slot = self.waker.clone();
        Arc::new(move || {
            // Clone out of the lock: waking the window must not happen while holding it.
            let waker = slot.lock().clone();
            if let Some(w) = waker {
                w();
            }
        })
    }

    /// Drain backend events. True if the view changed.
    fn drain(&mut self) -> bool {
        let mut changed = false;
        loop {
            let Some(event) = self.events.as_ref().and_then(|e| e.try_recv().ok()) else {
                break;
            };
            self.apply(event);
            changed = true;
        }
        changed
    }

    // Names ------------------------------------------------------------------------------

    /// The name for `addr`: the user's, else the binary's.
    pub fn name_of(&self, addr: u64) -> Option<String> {
        self.names
            .get(addr)
            .map(str::to_owned)
            .or_else(|| self.index.base_name(addr).map(str::to_owned))
    }

    /// The name to print for `addr`: the user's, else the demangled form when that is on and
    /// the name is mangled (without parameters, for dense views), else the binary's.
    pub fn display_of(&self, addr: u64) -> Option<String> {
        if let Some(n) = self.names.get(addr) {
            return Some(n.to_owned());
        }
        if self.demangle
            && let Some(d) = self.index.demangled(addr)
        {
            return Some(d.short.clone());
        }
        self.index.base_name(addr).map(str::to_owned)
    }

    /// The name to print for a token the decompiler wrote as `raw`: the user's name or the
    /// demangled one, else `raw` itself (which can differ from the symbol's, being a C identifier).
    pub fn token_name(&self, addr: u64, raw: &str) -> String {
        let demangled = self.demangle.then(|| self.index.demangled(addr)).flatten();
        match (self.names.get(addr), demangled) {
            (Some(user), _) => user.to_owned(),
            (None, Some(d)) => d.short.clone(),
            (None, None) => raw.to_owned(),
        }
    }

    /// The name to print for a local variable the decompiler wrote as `raw`. It names the
    /// result of a call after the callee (`<callee>_result`, with `_<n>` when repeated), so for
    /// a mangled callee the demangled name replaces the callee part.
    pub fn local_name(&self, raw: &str) -> String {
        if !self.demangle {
            return raw.to_owned();
        }
        let Some((callee, tail)) = raw.split_once("_result") else {
            return raw.to_owned();
        };
        let counter = tail.strip_prefix('_').unwrap_or(tail);
        if !(tail.is_empty() || !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()))
        {
            return raw.to_owned();
        }
        match crate::backend::demangle::demangle(callee) {
            Some(d) => format!("{}_result{tail}", d.short),
            None => raw.to_owned(),
        }
    }

    /// The demangled name with parameters, if `addr` has a mangled name the user has not
    /// replaced and demangling is on. For places with room to spare.
    pub fn full_name_of(&self, addr: u64) -> Option<String> {
        if !self.demangle || self.names.get(addr).is_some() {
            return None;
        }
        self.index.demangled(addr).map(|d| d.full.clone())
    }

    /// Every spelling of the name at `addr` that a search should match: the user's, the
    /// binary's, and the demangled forms. Matching all of them means the search finds a symbol
    /// whether the user types what they see or what the linker wrote.
    pub fn search_names<'a>(&'a self, addr: u64, raw: &'a str) -> Vec<&'a str> {
        let mut names = vec![raw];
        names.extend(self.names.get(addr));
        if let Some(d) = self.index.demangled(addr) {
            names.extend([d.short.as_str(), d.full.as_str()]);
        }
        names
    }

    /// Changes whenever the way names print changes (a rename, the demangling switch).
    pub fn display_version(&self) -> u64 {
        self.names
            .version()
            .wrapping_mul(31)
            .wrapping_add(self.display_epoch)
    }

    /// Flip between demangled and raw names everywhere.
    pub fn toggle_demangle(&mut self) {
        self.demangle = !self.demangle;
        self.names_changed();
    }

    /// A label for any code address: its name, `loc_<addr>` for a block, or hex.
    pub fn label(&self, addr: u64) -> String {
        if let Some(n) = self.display_of(addr) {
            return n;
        }
        match &self.program {
            Some(p) if p.cfg.blocks.contains_key(&addr) => format!("loc_{addr:x}"),
            _ => format!("{addr:#x}"),
        }
    }

    /// The function containing `addr`.
    pub fn function_of(&self, addr: u64) -> Option<u64> {
        if let Some(p) = &self.program {
            return p.function_containing(addr);
        }
        let fs = &self.index.functions;
        let i = fs.partition_point(|f| f.entry <= addr).checked_sub(1)?;
        let f = &fs[i];
        (addr < f.entry + f.size.max(1)).then_some(f.entry)
    }

    /// Names changed: every view that prints a name redraws.
    pub fn names_changed(&mut self) {
        self.display_epoch += 1;
        self.sidebar.rebuild(&self.index, &self.filter.text);
        self.listing.invalidate();
        self.pseudo.invalidate();
    }

    // Navigation -------------------------------------------------------------------------

    /// Go to `addr`, remembering where we were.
    pub fn goto(&mut self, addr: u64, tx: &mut Tx) {
        if addr != self.cur {
            self.back.push(self.cur);
            self.forward.clear();
        }
        self.show(addr, tx);
    }

    pub fn go_back(&mut self, tx: &mut Tx) {
        if let Some(prev) = self.back.pop() {
            self.forward.push(self.cur);
            self.show(prev, tx);
        }
    }

    pub fn go_forward(&mut self, tx: &mut Tx) {
        if let Some(next) = self.forward.pop() {
            self.back.push(self.cur);
            self.show(next, tx);
        }
    }

    /// `goto` without a `Tx`, for tests that have none to give.
    #[doc(hidden)]
    pub fn goto_for_test(&mut self, addr: u64) {
        if addr != self.cur {
            self.back.push(self.cur);
            self.forward.clear();
        }
        self.cur = addr;
        self.refresh_pseudo();
        graph_view::refresh(self);
    }

    pub fn can_go_back(&self) -> bool {
        !self.back.is_empty()
    }

    pub fn can_go_forward(&self) -> bool {
        !self.forward.is_empty()
    }

    fn show(&mut self, addr: u64, tx: &mut Tx) {
        self.cur = addr;
        self.refresh_pseudo();
        graph_view::refresh(self);
        match self.main_tab {
            MainTab::Listing => listing::reveal(self, tx),
            MainTab::Graph => graph_view::reveal(self),
            MainTab::Hex => hex::reveal(self, tx),
            MainTab::Pseudo => {}
        }
        sidebar::reveal(self, tx);
    }

    /// Show a view. The listing scrolls to the current address; pseudocode is requested.
    pub fn select_tab(&mut self, tab: MainTab, tx: &mut Tx) {
        self.main_tab = tab;
        self.refresh_pseudo();
        graph_view::refresh(self);
        match tab {
            MainTab::Listing => listing::reveal(self, tx),
            MainTab::Graph => graph_view::reveal(self),
            MainTab::Hex => hex::reveal(self, tx),
            MainTab::Pseudo => {}
        }
    }

    /// Move the cursor without recording history or scrolling: a click inside a view that
    /// already shows the place.
    pub fn sync_cursor(&mut self, addr: u64) {
        self.cur = addr;
    }

    /// Point the pseudocode view at the current function and ask for its decompilation when the
    /// view is on screen. True if what it shows changed.
    fn refresh_pseudo(&mut self) -> bool {
        let entry = self.function_of(self.cur);
        let (status, completed) = match (&self.decomp, entry) {
            (Some(d), Some(e)) => {
                if self.main_tab == MainTab::Pseudo {
                    d.request(e);
                }
                (d.status(e), d.completed())
            }
            (Some(d), None) => (crate::backend::decomp::Status::None, d.completed()),
            _ => (crate::backend::decomp::Status::None, 0),
        };
        self.pseudo.sync(entry, status, completed)
    }
}

pub fn poll(app: &mut App, _clock: f64, tx: &mut Tx) -> bool {
    let mut changed = app.drain();
    if app.decomp.is_some() {
        changed |= app.refresh_pseudo();
    }
    changed |= graph_view::refresh(app);
    if app.reveal_pending && matches!(app.load, Load::Ready) {
        app.reveal_pending = false;
        app.show(app.cur, tx);
        changed = true;
    }
    changed
}

pub fn on_key(app: &mut App, key: &KeyEvent, tx: &mut Tx) -> bool {
    if app.overlay.mode.is_none() && overlay::global_key(app, key, tx) {
        return true;
    }
    match &key.key {
        Key::Escape => {
            app.go_back(tx);
            true
        }
        Key::Text(t)
            if t == " "
                && !key.mods.cmd
                && matches!(app.main_tab, MainTab::Listing | MainTab::Graph) =>
        {
            let next = if app.main_tab == MainTab::Graph {
                MainTab::Listing
            } else {
                MainTab::Graph
            };
            app.select_tab(next, tx);
            true
        }
        Key::Up | Key::Down if !key.mods.cmd && !key.mods.alt => {
            let delta = if key.key == Key::Down { 1 } else { -1 };
            let next = match app.main_tab {
                MainTab::Listing => listing::step(app, delta),
                MainTab::Hex => app.cur.checked_add_signed(16 * delta as i64),
                _ => None,
            };
            match next {
                Some(addr) => {
                    app.cur = addr;
                    app.show(addr, tx);
                    true
                }
                None => false,
            }
        }
        Key::Function(5) => {
            let next = if app.main_tab == MainTab::Pseudo {
                MainTab::Listing
            } else {
                MainTab::Pseudo
            };
            app.select_tab(next, tx);
            true
        }
        Key::Left if key.mods.alt => {
            app.go_back(tx);
            true
        }
        Key::Right if key.mods.alt => {
            app.go_forward(tx);
            true
        }
        _ => false,
    }
}

// View -------------------------------------------------------------------------------------

pub fn view(app: &App, _cx: &mut Cx<App>) -> El {
    let p = colors();
    let body = col()
        .w_full()
        .h_full()
        .fill(p.window)
        .child(widgets::toolbar(app))
        .child(
            row()
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .child(sidebar::panel(app))
                .child(widgets::splitter())
                .child(main_area(app)),
        )
        .child(widgets::status_bar(app));
    let body = body.on_drop_files(|s: &mut App, files: &[PathBuf], _tx: &mut Tx| {
        if let Some(first) = files.first() {
            s.open(first.clone());
        }
    });
    rune_kit::root(body, overlay::view(app))
}

fn main_area(app: &App) -> El {
    let p = colors();
    let content = match (&app.load, app.main_tab) {
        // The hex view needs only the parsed image.
        (Load::Opening { .. } | Load::Ready, MainTab::Hex) => hex::view(app),
        (Load::Ready, MainTab::Listing) => listing::view(app),
        (Load::Ready, MainTab::Graph) => graph_view::view(app),
        (Load::Ready, MainTab::Pseudo) => pseudo::view(app),
        _ => widgets::placeholder(app),
    };
    col()
        .grow(1.0)
        .min_w(0.0)
        .h_full()
        .fill(p.panel)
        .child(widgets::main_tabs(app))
        .child(el().w_full().h(1.0).fill(p.line))
        .child(col().w_full().grow(1.0).min_h(0.0).child(content))
        .child(el().w_full().h(1.0).fill(p.line))
        .child(bottom::panel(app))
}

/// Run the workbench.
pub fn run() {
    rune::run(AppSpec::<App> {
        min_size: Some((900.0, 560.0)),
        fonts: rune_theme_opencode::FONTS,
        families: rune_theme_opencode::FAMILIES,
        setup: Some(setup),
        poll: Some(poll),
        on_key: Some(on_key),
        ..AppSpec::new("biara", (1440.0, 880.0), init, view)
    });
}

/// Whether `target` names `f`: its raw name, or its demangled short or full form.
fn app_names_match(
    index: &crate::backend::Index,
    f: &crate::backend::FunctionInfo,
    target: &str,
) -> bool {
    f.name == target
        || index
            .demangled(f.entry)
            .is_some_and(|d| d.short == target || d.full == target)
}
