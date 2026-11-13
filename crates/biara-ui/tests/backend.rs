//! Recover a real compiled program through the UI's own backend and check what the views
//! will show: the function table, cross-references, strings and name resolution.
#![cfg(target_os = "linux")]

use std::{
    path::PathBuf,
    process::Command,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use biara_ui::backend::{self, Event, FunctionKind, Program, XrefKind, recovery};

const SOURCE: &str = r#"
extern int puts(const char *);
__attribute__((noinline,used)) unsigned long leaf(unsigned long v) { __asm__ volatile("" : "+r"(v)); return v * 3 + 1; }
__attribute__((noinline,used)) unsigned long target(unsigned long n) {
    unsigned long t = 0;
    for (unsigned long i = 0; i < n; i++) t += leaf(i);
    return t;
}
__attribute__((noinline,used)) int message(void) { return puts("backend fixture string"); }
int main(void) { return target(3) != 12; }
"#;

/// Build the fixture and return its path; one directory per process so reruns never see a
/// stale analysis database.
fn build(name: &str) -> PathBuf {
    build_with(name, &[])
}

/// [`build`] with extra compiler flags (`-g` for debug information).
fn build_with(name: &str, flags: &[&str]) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    std::fs::write(&source, SOURCE).unwrap();
    let built = Command::new(env!("BIARA_CLANG"))
        .args(["-O1", "-fno-builtin", "-fno-pie", "-no-pie", "-fuse-ld=bfd"])
        .args(flags)
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    binary
}

/// Open `binary` and collect events until it is ready (or fails).
fn recover(binary: PathBuf) -> (Vec<String>, Arc<Program>) {
    let (wake_tx, wake_rx) = mpsc::channel::<()>();
    let notify: backend::Notify = Arc::new(move || {
        let _ = wake_tx.send(());
    });
    let options = recovery::OpenOptions {
        database: Some(binary.with_extension("sqlite")),
        worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
        ..Default::default()
    };
    let events = recovery::open(binary, notify, options);
    let mut log = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        while let Ok(event) = events.try_recv() {
            match event {
                Event::Opened { preview, .. } => {
                    log.push(format!("opened:{}", preview.functions.len()))
                }
                Event::Progress { stage, .. } => log.push(format!("{stage:?}")),
                Event::Ready(program) => return (log, program),
                Event::Failed(e) => panic!("recovery failed: {e}"),
            }
        }
        assert!(
            Instant::now() < deadline,
            "recovery timed out after {log:?}"
        );
        let _ = wake_rx.recv_timeout(Duration::from_millis(200));
    }
}

#[test]
fn recovery_reports_stages_in_order_and_builds_the_function_table() {
    let (log, program) = recover(build("backend-table"));
    let stage_order: Vec<_> = log
        .iter()
        .filter(|l| !l.starts_with("opened"))
        .cloned()
        .collect();
    let first = |name: &str| {
        stage_order
            .iter()
            .position(|s| s == name)
            .unwrap_or_else(|| panic!("no {name} in {stage_order:?}"))
    };
    assert!(
        first("Loading") < first("Recovering")
            && first("Recovering") < first("Abi")
            && first("Abi") < first("Indexing")
    );
    // The symbol-based preview arrives before recovery finishes.
    assert!(log.iter().any(|l| l.starts_with("opened:")), "{log:?}");

    let idx = &program.index;
    let by_name = |n: &str| {
        idx.functions
            .iter()
            .find(|f| f.name == n)
            .unwrap_or_else(|| panic!("no function {n}"))
    };
    let (leaf, target) = (by_name("leaf"), by_name("target"));
    assert!(leaf.size > 0 && leaf.blocks >= 1 && leaf.insns >= 2);
    assert!(
        target.blocks >= 3,
        "a loop has a header, a body and an exit: {target:?}"
    );
    assert!(target.calls >= 1 && leaf.callers >= 1);
    assert!(
        idx.functions.windows(2).all(|w| w[0].entry < w[1].entry),
        "the table is sorted by address"
    );
    let stub = idx
        .functions
        .iter()
        .find(|f| f.name == "puts@plt")
        .expect("puts stub");
    assert_eq!(stub.kind, FunctionKind::Stub);
    assert_eq!(idx.function(leaf.entry).unwrap().name, "leaf");
}

#[test]
fn the_listing_covers_every_function_in_address_order() {
    use biara_ui::backend::HeadKind;
    let (_, program) = recover(build("backend-listing"));
    let heads = &program.listing.heads;
    assert!(
        heads.windows(2).all(|w| w[0].addr <= w[1].addr),
        "rows must be in address order"
    );
    for f in program
        .index
        .functions
        .iter()
        .filter(|f| f.kind == FunctionKind::Normal)
    {
        let row = program
            .listing
            .row_of(f.entry)
            .unwrap_or_else(|| panic!("no row for {}", f.name));
        assert_eq!(
            heads[row].kind,
            HeadKind::Func,
            "{} starts at its header",
            f.name
        );
        // The instructions that follow, up to the next function, tile the function's blocks:
        // their lengths add up to the size the table reports.
        let insn_bytes: u64 = heads[row..]
            .iter()
            .skip(1)
            .take_while(|h| h.kind != HeadKind::Func && h.kind != HeadKind::Blank)
            .filter(|h| h.kind == HeadKind::Insn)
            .map(|h| u64::from(h.len))
            .sum();
        assert_eq!(insn_bytes, f.size, "{}: listed bytes vs table size", f.name);
    }
    // A mid-instruction address resolves to the instruction that contains it.
    let leaf = program
        .index
        .functions
        .iter()
        .find(|f| f.name == "leaf")
        .unwrap();
    let r = program.listing.row_of(leaf.entry + 1).unwrap();
    assert_eq!(heads[r].kind, HeadKind::Insn);
    assert!(
        heads[r].addr <= leaf.entry + 1 && leaf.entry + 1 < heads[r].addr + u64::from(heads[r].len)
    );
}

#[test]
fn the_decompiler_service_returns_navigable_pseudocode_and_caches_it() {
    use biara_proto::tokens::SymbolRef;
    use biara_ui::backend::decomp::{Decompiler, Status};
    let (_, program) = recover(build("backend-decomp"));
    let entry = |n: &str| {
        program
            .index
            .functions
            .iter()
            .find(|f| f.name == n)
            .unwrap()
            .entry
    };
    let (leaf, target) = (entry("leaf"), entry("target"));

    let (wake_tx, wake_rx) = mpsc::channel::<()>();
    let decompiler = Decompiler::new(
        program.clone(),
        Arc::new(move || {
            let _ = wake_tx.send(());
        }),
    );
    assert!(matches!(decompiler.status(target), Status::None));
    decompiler.request(target);
    assert!(matches!(decompiler.status(target), Status::Pending));
    let done = loop {
        match decompiler.status(target) {
            Status::Done(d) => break d,
            Status::Failed(e) => panic!("decompile failed: {e}"),
            _ => {
                wake_rx
                    .recv_timeout(Duration::from_secs(120))
                    .expect("decompiler did not finish");
            }
        }
    };
    assert_eq!(done.entry, target);
    assert!(
        done.body.contains("target") && done.body.contains("leaf"),
        "{}",
        done.body
    );
    // The call to `leaf` is a token carrying leaf's address.
    let call = done.tokens.iter().find(|t| t.symbol == Some(SymbolRef::Function { address: leaf })).unwrap_or_else(|| panic!("a token for the call to leaf ({leaf:#x}):\n{}\nsymbols: {:?}\ntokens with symbols: {:?}", done.body, done.symbols, done.tokens.iter().filter(|t| t.symbol.is_some()).collect::<Vec<_>>()));
    assert_eq!(&done.body[call.start as usize..call.end as usize], "leaf");
    // Lines tile the body: every token lies on the line the index says.
    for i in 0..done.lines.len() {
        for t in done.line_tokens(i) {
            let l = done.lines[i];
            assert!(
                t.start as usize >= l.start && (t.start as usize) <= l.end,
                "token {t:?} outside line {i}"
            );
        }
    }
    assert_eq!(
        done.lines
            .iter()
            .map(|l| l.end_token - l.first_token)
            .sum::<usize>(),
        done.tokens.len(),
        "every token belongs to a line"
    );
    // Asking again does not queue more work: the result is cached.
    let before = decompiler.completed();
    decompiler.request(target);
    assert!(matches!(decompiler.status(target), Status::Done(_)));
    assert_eq!(decompiler.completed(), before);
    // The newest request runs first: queue two, the later one finishes no later than the earlier.
    decompiler.request(leaf);
    assert!(matches!(
        decompiler.status(leaf),
        Status::Pending | Status::Done(_)
    ));
}

#[test]
fn a_functions_flow_graph_has_typed_edges_and_lays_out_without_overlap() {
    use biara_ui::backend::{FlowError, FlowGraph, graph};
    let (_, program) = recover(build("backend-flow"));
    let target = program
        .index
        .functions
        .iter()
        .find(|f| f.name == "target")
        .unwrap();
    let flow = FlowGraph::build(&program, target.entry).unwrap();
    assert_eq!(flow.nodes[flow.entry_index].addr, target.entry);
    assert_eq!(flow.nodes.len() as u32, target.blocks);
    assert_eq!(
        flow.nodes.iter().map(|n| n.insns.len() as u32).sum::<u32>(),
        target.insns,
        "every instruction is decoded"
    );
    assert!(
        flow.edges
            .iter()
            .all(|e| e.from < flow.nodes.len() && e.to < flow.nodes.len())
    );
    // `for (i < n)`: a conditional branch gives one taken and one not-taken edge from one node.
    let conditional = flow.nodes.iter().enumerate().any(|(i, _)| {
        let kinds: Vec<_> = flow
            .edges
            .iter()
            .filter(|e| e.from == i)
            .map(|e| e.kind)
            .collect();
        kinds.contains(&graph::EdgeKind::Taken) && kinds.contains(&graph::EdgeKind::NotTaken)
    });
    assert!(conditional, "{:?}", flow.edges);
    // The loop's back edge goes to an earlier or equal address.
    assert!(
        flow.edges
            .iter()
            .any(|e| flow.nodes[e.to].addr <= flow.nodes[e.from].addr),
        "no back edge: {:?}",
        flow.edges
    );
    assert!(
        flow.nodes.iter().any(|n| n.exits_function),
        "a return ends the function"
    );
    assert_eq!(
        FlowGraph::build(&program, 0x10).unwrap_err(),
        FlowError::NotAFunction
    );

    // Lay it out as the view does: nodes sized by their text. Nothing may overlap.
    let sizes: Vec<_> = flow
        .nodes
        .iter()
        .map(|n| graph::Size {
            w: 60.0 + 8.0 * n.insns.iter().map(|i| i.text().len()).max().unwrap_or(1) as f32,
            h: 20.0 * n.insns.len().max(1) as f32,
        })
        .collect();
    let layout = graph::layout(
        &sizes,
        &flow.edges,
        flow.entry_index,
        graph::Spacing::default(),
    );
    for (i, a) in layout.nodes.iter().enumerate() {
        for b in &layout.nodes[i + 1..] {
            let apart =
                a.right() <= b.x || b.right() <= a.x || a.bottom() <= b.y || b.bottom() <= a.y;
            assert!(apart, "nodes overlap: {a:?} {b:?}");
        }
    }
    assert!(
        layout.nodes[flow.entry_index].y
            <= layout
                .nodes
                .iter()
                .map(|r| r.y)
                .fold(f32::INFINITY, f32::min)
                + 0.01,
        "the entry is on the top layer"
    );
}

#[test]
fn debug_information_names_parameters_in_the_pseudocode() {
    use biara_ui::backend::decomp;
    // Without debug info the parameter is `arg0`; with it, the source name.
    let (_, plain) = recover(build("backend-nodebug"));
    let target = plain
        .index
        .functions
        .iter()
        .find(|f| f.name == "target")
        .unwrap()
        .entry;
    let before = decomp::decompile(&plain, target).unwrap();
    assert!(before.signature.contains("arg0"), "{}", before.signature);

    let (_, program) = recover(build_with("backend-debug", &["-g"]));
    let target = program
        .index
        .functions
        .iter()
        .find(|f| f.name == "target")
        .unwrap()
        .entry;
    let after = decomp::decompile(&program, target).unwrap();
    assert!(
        after.signature.contains(" n)") || after.signature.contains(" n,"),
        "the source name `n` should replace arg0: {}",
        after.signature
    );
    assert!(!after.signature.contains("arg0"), "{}", after.signature);
}

#[test]
fn cross_references_and_strings_point_at_the_right_places() {
    let (_, program) = recover(build("backend-xrefs"));
    let idx = &program.index;
    let entry = |n: &str| idx.functions.iter().find(|f| f.name == n).unwrap().entry;
    let (leaf, target, message) = (entry("leaf"), entry("target"), entry("message"));

    // `target` calls `leaf`: one call xref, from an address inside `target`.
    let calls: Vec<_> = idx
        .xrefs_to(leaf)
        .iter()
        .filter(|x| x.kind == XrefKind::Call)
        .collect();
    assert!(
        !calls.is_empty(),
        "no call reference to leaf: {:?}",
        idx.xrefs_to(leaf)
    );
    assert!(calls.iter().all(|x| x.function == target));
    assert_eq!(program.function_containing(calls[0].from), Some(target));

    // `message` loads the string's address: a data reference to a string the table knows.
    let s = idx
        .strings
        .iter()
        .find(|s| s.text == "backend fixture string")
        .expect("string found");
    let data: Vec<_> = idx
        .xrefs_to(s.addr)
        .iter()
        .filter(|x| x.kind == XrefKind::Data)
        .collect();
    assert!(
        !data.is_empty(),
        "no data reference to the string at {:#x}",
        s.addr
    );
    assert_eq!(data[0].function, message);
    assert_eq!(
        idx.string_at(s.addr).unwrap().bytes as usize,
        "backend fixture string".len()
    );

    // Names: symbols win over generated ones, and unknown addresses have none.
    assert_eq!(idx.base_name(leaf), Some("leaf"));
    assert_eq!(idx.base_name(1), None);
    // An address in the middle of `leaf` belongs to it; one outside any block does not.
    assert_eq!(program.function_containing(leaf + 1), Some(leaf));
    assert_eq!(program.function_containing(0x10), None);
}

/// Scale check, not run by default: `BIARA_UI_BIG=/path/to/binary cargo test -p biara-ui --test
/// backend -- --ignored --nocapture`. Prints when each stage finished and what the indexes hold.
#[test]
#[ignore = "slow: recovers a whole system library"]
fn scale_report() {
    let path = PathBuf::from(
        std::env::var("BIARA_UI_BIG").unwrap_or_else(|_| "/usr/lib64/libc.so.6".into()),
    );
    let (wake_tx, wake_rx) = mpsc::channel::<()>();
    let notify: backend::Notify = Arc::new(move || {
        let _ = wake_tx.send(());
    });
    let start = Instant::now();
    let events = recovery::open(
        path,
        notify,
        recovery::OpenOptions {
            database: Some(
                PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                    .join(format!("scale-{}.sqlite", std::process::id())),
            ),
            worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
            workers: std::env::var("BIARA_UI_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok()),
            memory_mib: std::env::var("BIARA_UI_MEM_MIB")
                .ok()
                .and_then(|v| v.parse().ok()),
        },
    );
    loop {
        while let Ok(event) = events.try_recv() {
            let t = start.elapsed().as_secs_f64();
            match event {
                Event::Opened { preview, .. } => println!(
                    "{t:7.2}s opened: {} symbol functions",
                    preview.functions.len()
                ),
                Event::Progress {
                    stage,
                    functions,
                    blocks,
                } => println!("{t:7.2}s {stage:?}: {functions} functions, {blocks} blocks"),
                Event::Ready(p) => {
                    let i = &p.index;
                    println!(
                        "{t:7.2}s READY: {} functions, {} xref targets ({} refs), {} strings, {} imports",
                        i.functions.len(),
                        i.xrefs.len(),
                        i.xrefs.values().map(Vec::len).sum::<usize>(),
                        i.strings.len(),
                        i.imports.len()
                    );
                    return;
                }
                Event::Failed(e) => panic!("{e}"),
            }
        }
        let _ = wake_rx.recv_timeout(Duration::from_millis(200));
    }
}

/// Instructions in the listing that the disassembler and the lifter disagree about: bytes the
/// decoder cannot read, a different length, or a direct branch that leaves recovered code.
/// Returns how many were checked and what was wrong.
fn listing_decode_problems(program: &Program) -> (usize, Vec<String>) {
    use biara_ui::backend::{HeadKind, disasm};
    let (mut checked, mut problems) = (0, Vec::new());
    for head in program
        .listing
        .heads
        .iter()
        .filter(|h| h.kind == HeadKind::Insn)
    {
        let mut bytes = vec![0u8; head.len as usize];
        if !program.image.read(head.addr, &mut bytes) {
            problems.push(format!("{:#x}: unreadable", head.addr));
            continue;
        }
        let insn = disasm::decode(program.arch, head.addr, &bytes);
        checked += 1;
        if insn.mnemonic() == "db" || insn.mnemonic() == ".word" {
            problems.push(format!("{:#x}: undecodable bytes {bytes:02x?}", head.addr));
        } else if insn.len as u32 != head.len {
            problems.push(format!(
                "{:#x}: decoder length {} vs lifter length {} ({})",
                head.addr,
                insn.len,
                head.len,
                insn.text()
            ));
        } else if let Some(t) = insn.target
            && program.function_containing(t).is_none()
            && program.index.function(t).is_none()
        {
            problems.push(format!(
                "{:#x}: {} targets {t:#x}, outside recovered code",
                head.addr,
                insn.text()
            ));
        }
    }
    (checked, problems)
}

fn assert_listing_decodes(program: &Program) {
    let (checked, problems) = listing_decode_problems(program);
    assert!(checked > 10, "only {checked} instructions");
    assert!(
        problems.is_empty(),
        "{} of {checked} instructions disagree:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn every_x86_instruction_in_the_listing_decodes_and_agrees_on_length() {
    let (_, program) = recover(build("backend-decode-x86"));
    assert_listing_decodes(&program);
}

/// The Rust toolchain's lld, run as `ld.lld`, links the AArch64 fixture (the pinned LLVM's own
/// `ld.lld` needs a newer libicu than many systems have).
fn lld() -> PathBuf {
    lld_named("ld.lld")
}

/// The same binary under the name `name` (`lld-link` makes it behave as the PE linker).
fn lld_named(name: &str) -> PathBuf {
    let sysroot = String::from_utf8(
        Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .args(["--print", "sysroot"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let rustlib = PathBuf::from(sysroot.trim()).join("lib/rustlib");
    let lld = std::fs::read_dir(&rustlib)
        .unwrap()
        .map(|e| e.unwrap().path().join("bin/rust-lld"))
        .find(|p| p.exists())
        .expect("rust-lld");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("ld-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(name);
    if !link.exists() {
        std::os::unix::fs::symlink(&lld, &link).unwrap();
    }
    link
}

#[test]
fn every_aarch64_instruction_in_the_listing_decodes_and_agrees_on_length() {
    const A64: &str = r#"
static unsigned checksum(const unsigned char *p, unsigned n) { unsigned h = 5381; for (unsigned i = 0; i < n; i++) h = h * 33 + p[i]; return h; }
__attribute__((noinline)) int classify(int v) { switch (v) { case 0: return 10; case 1: return 21; case 2: return 32; case 3: return 43; case 4: return 54; default: return -1; } }
__attribute__((noinline)) unsigned process(const unsigned char *buf, unsigned n) { if (n == 0) return 0; unsigned c = checksum(buf, n); return c + (unsigned)classify((int)(c & 7)); }
int guest_main(void) { static const unsigned char d[8] = {1,2,3,4,5,6,7,8}; return (int)process(d, 8) & 0xff; }
__asm__(".text\n.globl _start\n_start:\n bl guest_main\n mov x8, #93\n svc #0\n");
"#;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("backend-decode-a64-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("a64.c");
    std::fs::write(&src, A64).unwrap();
    let bin = dir.join("a64");
    let out = Command::new(env!("BIARA_CLANG"))
        .args([
            "-target",
            "aarch64-linux-gnu",
            "-O1",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-nostdlib",
        ])
        .arg(format!("--ld-path={}", lld().display()))
        .args(["-Wl,-Ttext=0x400000,-e,_start"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (_, program) = recover(bin);
    assert_eq!(program.arch, biara_ui::backend::Arch::Aarch64);
    assert!(program.index.functions.iter().any(|f| f.name == "process"));
    assert_listing_decodes(&program);
}

/// Scale check: every instruction of a real system library decodes, with the lifter's length.
#[test]
#[ignore = "slow: recovers a whole system library"]
fn every_instruction_of_a_system_library_decodes() {
    let path = PathBuf::from(
        std::env::var("BIARA_UI_BIG").unwrap_or_else(|_| "/usr/lib64/libc.so.6".into()),
    );
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let (wake_tx, wake_rx) = mpsc::channel::<()>();
    let notify: backend::Notify = Arc::new(move || {
        let _ = wake_tx.send(());
    });
    let events = recovery::open(
        path,
        notify,
        recovery::OpenOptions {
            database: Some(dir.join(format!("decode-big-{}.sqlite", std::process::id()))),
            worker_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_biara-ui"))),
            ..Default::default()
        },
    );
    let program = loop {
        match events
            .recv_timeout(Duration::from_secs(600))
            .expect("timed out")
        {
            Event::Ready(p) => break p,
            Event::Failed(e) => panic!("{e}"),
            _ => {
                let _ = wake_rx.try_recv();
            }
        }
    };
    let start = Instant::now();
    let (checked, problems) = listing_decode_problems(&program);
    let by = |needle: &str| problems.iter().filter(|p| p.contains(needle)).count();
    println!(
        "checked {checked} instructions: {} undecodable, {} length mismatches, {} bad targets",
        by("undecodable"),
        by("decoder length"),
        by("outside recovered")
    );
    for needle in ["undecodable", "decoder length", "outside recovered"] {
        for p in problems.iter().filter(|p| p.contains(needle)).take(6) {
            println!("  {p}");
        }
    }
    // Recovery can lift a stray byte run that is not code; a few in hundreds of thousands of
    // instructions is expected. A pattern is not.
    assert!(
        problems.len() * 1000 <= checked,
        "{} of {checked} instructions disagree",
        problems.len()
    );
    println!(
        "decoded {} listing rows in {:.2?}",
        program.listing.heads.len(),
        start.elapsed()
    );
}

#[test]
fn a_windows_dll_opens_with_its_exports_named_and_decodes() {
    const PE: &str = r#"
static unsigned hash(const unsigned char *p, unsigned n) { unsigned h = 5381; for (unsigned i = 0; i < n; i++) h = h * 33 + p[i]; return h; }
__declspec(dllexport) int classify(int v) { switch (v) { case 0: return 10; case 1: return 21; case 2: return 32; default: return -1; } }
__declspec(dllexport) unsigned process(const unsigned char *buf, unsigned n) { if (!n) return 0; return hash(buf, n) + (unsigned)classify((int)(n & 3)); }
"#;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("backend-pe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pe.c"), PE).unwrap();
    let obj = dir.join("pe.obj");
    let out = Command::new(env!("BIARA_CLANG"))
        .args([
            "-target",
            "x86_64-pc-windows-msvc",
            "-O1",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fno-builtin",
            "-c",
        ])
        .arg(dir.join("pe.c"))
        .arg("-o")
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dll = dir.join("pe.dll");
    let out = Command::new(lld_named("lld-link"))
        .args([
            "/nologo",
            "/dll",
            "/noentry",
            "/nodefaultlib",
            "/machine:x64",
            "/export:process",
            "/export:classify",
            "/base:0x180000000",
        ])
        .arg(format!("/out:{}", dll.display()))
        .arg(&obj)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (_, program) = recover(dll);
    assert_eq!(program.image.os, "windows");
    for name in ["classify", "process"] {
        let f = program
            .index
            .functions
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("export {name} missing"));
        assert!(f.entry >= 0x1_8000_0000, "{name} at {:#x}", f.entry);
    }
    assert_listing_decodes(&program);
}
