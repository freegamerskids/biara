//! Persistent analysis must not confuse code revisions, entry sets or budgets.
//!
//! The guests are freestanding x86-64 Linux programs built with the pinned
//! clang, so every host analyses them; only a Linux x86-64 host also runs them.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use biara_loader::Image;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// The host runs the x86-64 Linux guests too.
const NATIVE: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

/// Build freestanding x86-64 Linux `source` into `binary`.
fn compile(source: &Path, binary: &Path, flags: &[&str]) {
    let built = Command::new(env!("BIARA_CLANG"))
        .args([
            "--target=x86_64-linux-gnu",
            "-ffreestanding",
            "-nostdlib",
            "-static",
            "-fno-pie",
            "-fno-builtin",
            "-fuse-ld=lld",
        ])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(binary)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

/// Run `binary` where the host can: it exits 0 when it computes what it should.
fn check_runs(binary: &Path) {
    if NATIVE {
        assert!(Command::new(binary).status().unwrap().success());
    }
}

/// `_start` exits with `main`'s result.
const START: &str = r#"
__attribute__((noreturn,used)) void _start(void) {
    long status = main();
    __asm__ volatile("syscall"::"a"(60L),"D"(status):"rcx","r11","memory");
    __builtin_unreachable();
}
"#;

fn build(dir: &Path, multiplier: u64, bias: u64) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    fs::write(
        &source,
        format!(
            r#"
#include <stdint.h>
__attribute__((noinline,used)) uint64_t leaf(uint64_t x) {{
    __asm__ volatile("" : "+r"(x)); return x*{multiplier}+{bias};
}}
__attribute__((noinline,used)) uint64_t other(uint64_t x) {{ return leaf(x)+10; }}
int main(void) {{ return other(2)!={expected}; }}
{START}"#,
            expected = 2 * multiplier + bias + 10
        ),
    )
    .unwrap();
    compile(&source, &binary, &["-O2", "-g"]);
    check_runs(&binary);
    binary
}
fn run(binary: &Path, database: &Path, root: &str, emit: &str, budget: &str, jobs: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_biara"));
    command
        .arg("lift")
        .arg(binary)
        .arg(root)
        .args(["--emit", emit, "--max-blocks", budget, "--jobs", jobs])
        .arg("--database")
        .arg(database);
    if emit == "cfg" {
        command.args(["--format", "json"]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn execute_c(dir: &Path, code: &[u8], multiplier: u64, bias: u64) {
    let source = dir.join("recovered.c");
    fs::write(&source, code).unwrap();
    let harness = dir.join("check.c");
    fs::write(
        &harness,
        format!(
            r#"
#include "recovered.c"
{cpu}
int main(void) {{
    uint64_t values[] = {{0,1,19,UINT64_C(0x8000000000000000),UINT64_MAX}};
    for (unsigned i=0;i<5;i++)
        if (leaf(values[i]) != values[i]*UINT64_C({multiplier})+UINT64_C({bias})) return 1;
    return 0;
}}
"#,
            cpu = if code
                .windows(b"extern struct cpu_state biara_cpu;".len())
                .any(|w| w == b"extern struct cpu_state biara_cpu;")
            {
                "struct cpu_state biara_cpu;"
            } else {
                ""
            },
        ),
    )
    .unwrap();
    // The recovered C is plain C: it builds and runs on the host.
    let executable = dir.join("check");
    let built = Command::new(env!("BIARA_CLANG"))
        .args([
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fuse-ld=lld",
        ])
        .arg(&harness)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}

#[test]
fn database_reuse_preserves_execution_and_invalidates_changed_binary_bytes() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-code-revisions");
    let database = dir.join("analysis.sqlite");
    let binary = build(&dir, 3, 1);
    let first = run(&binary, &database, "leaf", "c", "32", "1");
    let cached = run(&binary, &database, "leaf", "c", "32", "2");
    assert_eq!(first.stdout, cached.stdout);
    execute_c(&dir, &cached.stdout, 3, 1);
    let binary = build(&dir, 5, 2);
    let changed = run(&binary, &database, "leaf", "c", "32", "2");
    execute_c(&dir, &changed.stdout, 5, 2);
}

#[test]
fn small_budget_and_entry_selection_do_not_poison_later_recovery() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-recovery-variants");
    let database = dir.join("analysis.sqlite");
    let binary = build(&dir, 3, 1);
    let image = Image::load(&binary).unwrap();
    let leaf = image.symbol("leaf").unwrap().addr;
    let other = image.symbol("other").unwrap().addr;
    let limited: Value =
        serde_json::from_slice(&run(&binary, &database, "other", "cfg", "1", "2").stdout).unwrap();
    assert!(
        limited["completeness"]["recovery"]["block_limit_reached"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(limited["analysis"]["functions"][0]["address"], other);
    assert!(
        limited["analysis"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["address"] != leaf)
    );
    let complete: Value =
        serde_json::from_slice(&run(&binary, &database, "other", "cfg", "32", "1").stdout).unwrap();
    let addresses: Vec<_> = complete["analysis"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["address"].as_u64().unwrap())
        .collect();
    let mut expected = vec![leaf, other];
    expected.sort_unstable();
    assert_eq!(addresses, expected);
    let selected: Value =
        serde_json::from_slice(&run(&binary, &database, "leaf", "cfg", "32", "2").stdout).unwrap();
    let addresses: Vec<_> = selected["analysis"]["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["address"].as_u64().unwrap())
        .collect();
    assert_eq!(addresses, [leaf]);
}

#[test]
fn minimum_memory_budget_recovers_calls_and_rejects_smaller_limits() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-minimum-memory");
    let binary = build(&dir, 3, 1);
    let image = Image::load(&binary).unwrap();
    let database = dir.join(format!("analysis-{}.sqlite", std::process::id()));
    let invoke = |memory: &str| {
        Command::new(env!("CARGO_BIN_EXE_biara"))
            .arg("lift")
            .arg(&binary)
            .arg("other")
            .args([
                "--emit",
                "cfg",
                "--format",
                "json",
                "--jobs",
                "16",
                "--memory-mib",
                memory,
            ])
            .arg("--database")
            .arg(&database)
            .output()
            .unwrap()
    };
    let rejected = invoke("2047");
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!database.exists());
    let recovered = invoke("2048");
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let report: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    let functions = report["analysis"]["functions"].as_array().unwrap();
    let other = image.symbol("other").unwrap().addr;
    let leaf = image.symbol("leaf").unwrap().addr;
    let caller = functions.iter().find(|f| f["address"] == other).unwrap();
    assert_eq!(caller["calls"], serde_json::json!([leaf]));
    assert!(functions.iter().any(|f| f["address"] == leaf));
    assert_eq!(
        report["completeness"]["recovery"]["block_limit_reached"],
        false
    );
}

#[test]
fn database_failure_is_not_reported_as_successful_partial_recovery() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-database-error");
    let binary = build(&dir, 3, 1);
    let output = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(binary)
        .arg("leaf")
        .args(["--emit", "cfg", "--format", "json", "--jobs", "2"])
        .arg("--database")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn simultaneous_coordinators_share_a_cold_database_without_corrupting_results() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-concurrent");
    let binary = build(&dir, 3, 1);
    let database = dir.join(format!("analysis-{}.sqlite", std::process::id()));
    let barrier = std::sync::Barrier::new(4);
    let outputs = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    run(&binary, &database, "leaf", "c", "32", "2")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    for output in &outputs[1..] {
        assert_eq!(outputs[0].stdout, output.stdout);
    }
    execute_c(&dir, &outputs[0].stdout, 3, 1);
}

#[test]
fn legacy_database_migration_preserves_jobs_and_retires_obsolete_graphs() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-schema-migration");
    let binary = build(&dir, 3, 1);
    let database = dir.join(format!("legacy-{}.sqlite", std::process::id()));
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection.execute_batch("
CREATE TABLE projects(id TEXT PRIMARY KEY,binary_hash TEXT NOT NULL,library_hash TEXT NOT NULL);
CREATE TABLE variants(id TEXT PRIMARY KEY,project TEXT NOT NULL,cfg BLOB,snapshot BLOB,finished INTEGER NOT NULL DEFAULT 0);
CREATE TABLE candidates(variant TEXT NOT NULL,address TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(variant,address));
CREATE TABLE jobs(id TEXT PRIMARY KEY,project TEXT NOT NULL,stage TEXT NOT NULL,result BLOB NOT NULL);
INSERT INTO projects VALUES('legacy','old-image','old-library');
INSERT INTO variants VALUES('legacy-request','legacy',x'010203',x'040506',1);
INSERT INTO candidates VALUES('legacy-request','0000000000001000','analyzed');
INSERT INTO jobs VALUES('old-job','legacy','translate',x'070809');
PRAGMA user_version=1;").unwrap();
    drop(connection);
    let migrated = run(&binary, &database, "leaf", "c", "32", "2");
    execute_c(&dir, &migrated.stdout, 3, 1);
    let connection = rusqlite::Connection::open(&database).unwrap();
    let preserved: Vec<u8> = connection
        .query_row("SELECT result FROM jobs WHERE id='old-job'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(preserved, [7, 8, 9]);
    let retired: (Option<Vec<u8>>, Option<Vec<u8>>, bool) = connection
        .query_row(
            "SELECT graph,resolver_graph,finished FROM variants WHERE id='legacy-request'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retired, (None, None, false));
    let state: String = connection
        .query_row(
            "SELECT state FROM candidates WHERE variant='legacy-request'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "pending");
    let cached = run(&binary, &database, "leaf", "c", "32", "1");
    assert_eq!(migrated.stdout, cached.stdout);
}

#[test]
fn corrupted_checkpoint_blocks_abort_instead_of_emitting_wrong_or_partial_code() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-corrupt-artifact");
    let binary = build(&dir, 3, 1);
    let database = dir.join(format!("analysis-{}.sqlite", std::process::id()));
    let first = run(&binary, &database, "leaf", "c", "32", "2");
    execute_c(&dir, &first.stdout, 3, 1);
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute("UPDATE cfg_blocks SET result=x'00'", [])
        .unwrap();
    drop(connection);
    let failed = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(binary)
        .arg("leaf")
        .args(["--emit", "c", "--jobs", "1", "--max-blocks", "32"])
        .arg("--database")
        .arg(database)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
}

#[test]
fn persistent_resolution_keeps_shared_memory_and_named_register_results() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("engine-shared-frame");
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    fs::write(
        &source,
        r#"
typedef unsigned long Word;
typedef long (*Callback)(long);
__attribute__((noinline,used)) long chosen(long x) { return x+7; }
extern long frame(Word *);
extern long named_frame(Callback,Word);
__attribute__((noinline,used)) long run_frame(Callback first) {
    long prefix=first(3);
    Word slots[2]={(Word)chosen^0x1234,0xdeadbeef00001234UL};
    return prefix+frame(slots);
}
__attribute__((noinline,used)) long run_named(Callback first) {
    return named_frame(first,(Word)chosen);
}
__attribute__((noreturn,used)) void _start(void) {
    long result=run_frame(chosen)+run_named(chosen);
    __asm__ volatile("syscall"::"a"(60L),"D"(result==34 ? 0L : 1L):"rcx","r11","memory");
    __builtin_unreachable();
}
__asm__(".text\n.globl frame\n.type frame,@function\nframe:\n"
        "movq (%rdi),%rax\nmovzwl 8(%rdi),%ecx\nxorq %rcx,%rax\n"
        "movl $5,%edi\nsubq $8,%rsp\ncall *%rax\naddq $8,%rsp\nret\n.size frame,.-frame\n"
        ".globl publish\n.type publish,@function\npublish:\n"
        "pushq %rsi\nmovl $3,%edi\ncall *%rax\npopq %r10\nret\n.size publish,.-publish\n"
        ".globl named_frame\n.type named_frame,@function\nnamed_frame:\n"
        "pushq %rbx\nmovq %rdi,%rax\ncall publish\n"
        "movl $5,%edi\ncall *%r10\npopq %rbx\nret\n.size named_frame,.-named_frame\n");
"#,
    )
    .unwrap();
    compile(&source, &binary, &["-O2", "-funwind-tables"]);
    check_runs(&binary);
    let image = Image::load(&binary).unwrap();
    let chosen = image.symbol("chosen").unwrap().addr;
    let database = dir.join(format!("analysis-{}.sqlite", std::process::id()));
    for jobs in ["2", "1"] {
        let report: Value =
            serde_json::from_slice(&run(&binary, &database, "_start", "cfg", "64", jobs).stdout)
                .unwrap();
        for name in ["frame", "named_frame"] {
            let symbol = image.symbol(name).unwrap();
            // A tail-call-only assembly entry may remain in its caller's
            // function. The resolved transfer inside that code is the
            // observable contract, not the chosen function partition.
            let targets = report["analysis"]["blocks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|block| {
                    block["address"].as_u64().is_some_and(|address| {
                        symbol.addr <= address && address - symbol.addr < symbol.size
                    })
                })
                .find_map(|block| block["call_targets"].as_object())
                .unwrap_or_else(|| panic!("{name}: no resolved indirect call in assembly body"));
            assert_eq!(targets["targets"], serde_json::json!([chosen]), "{name}");
            assert_eq!(targets["complete"], false, "{name}");
        }
    }
}

/// Recover `binary` from its function symbols with workers started from
/// `worker`; the graph, or the engine's error.
fn recover_with_worker(
    binary: &Path,
    database: &Path,
    worker: &Path,
    workers: usize,
) -> Result<biara_cfg::Cfg, String> {
    let image = Image::load(binary).unwrap();
    let entries: Vec<u64> = image.function_starts().into_iter().collect();
    let opts = biara_lift::ResolveOptions {
        cfg: biara_cfg::Options {
            os: image.os,
            imports: image.imports.clone(),
            function_starts: image.function_starts(),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut session = biara_engine::Session::open(
        biara_engine::Options {
            binary: binary.to_owned(),
            libtcg: biara_tcg::Libtcg::find(image.arch).unwrap(),
            cpu: None,
            database: Some(database.to_owned()),
            workers,
            memory_budget: 4 << 30,
            executable: worker.to_owned(),
        },
        &entries,
        &opts,
    )
    .map_err(|e| e.to_string())?;
    let cfg = biara_lift::recover_resolving(
        &mut session,
        &biara_lift::analysis_machine().unwrap(),
        &|pc| image.code_at(pc),
        &|addr, buf| image.read_const(addr, buf),
        &entries,
        opts,
    )
    .map_err(|e| e.to_string())?;
    session.finish(&cfg).map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[test]
fn a_worker_dying_in_one_resolution_is_retried_alone_then_left_unresolved() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("engine-worker-exit-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    fs::write(
        &source,
        r#"
#define KEEP __attribute__((noinline, used))
KEEP long one(long v) { __asm__ volatile("" : "+r"(v)); return v + 1; }
KEEP long two(long v) { __asm__ volatile("" : "+r"(v)); return v * 2; }
extern long (*const ops[2])(long);
__asm__(".section .rodata\n.balign 8\n.globl ops\nops: .quad one, two\n.text\n");
KEEP long pick(unsigned long i, long v) { return ops[i & 1](v) + 3; }
volatile unsigned long which = 1;
long main(void) { return pick(which, 2) == 0; }
"#,
    )
    .unwrap();
    fs::write(&source, fs::read_to_string(&source).unwrap() + START).unwrap();
    compile(&source, &binary, &["-O2"]);
    let image = Image::load(&binary).unwrap();
    let pick = image.symbol("pick").unwrap().addr;
    let site = |cfg: &biara_cfg::Cfg| {
        cfg.functions[&pick]
            .blocks
            .iter()
            .copied()
            .find(|pc| {
                cfg.blocks[pc]
                    .exits
                    .iter()
                    .any(|x| matches!(x.kind, biara_cfg::ExitKind::IndirectCall { .. }))
            })
            .expect("pick calls through the table")
    };

    // With the real worker, the call through the table resolves to both entries.
    let real = Path::new(env!("CARGO_BIN_EXE_biara"));
    let cfg = recover_with_worker(&binary, &dir.join("real.sqlite"), real, 2).unwrap();
    let targets = &cfg.indirect_calls[&site(&cfg)].targets;
    assert_eq!(targets.len(), 2, "{targets:?}");

    // The real worker, killed at a resolution request (frame tag 1) when
    // `guard` holds: as if out of memory.
    let worker = |name: &str, guard: &str| {
        let path = dir.join(name);
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
# The real worker (exec'd, so the coordinator stays its parent), killed by
# the filter feeding it at a resolution request (frame tag 1) if the guard
# holds. The filter gets stdin through fd 4: a background list reads
# /dev/null, and dash swaps that in before applying a `<&0` redirection.
fifo="$(mktemp -u)"
mkfifo "$fifo"
exec 4<&0
(
    exec 3> "$fifo"
    while :; do
        length=$(dd bs=1 count=4 2>/dev/null | od -An -tu4 | tr -d ' ')
        [ -n "$length" ] || exit 0
        tag=$(dd bs=1 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
        if [ "$tag" = 1 ] && {guard}; then
            kill -9 $$
            exit 0
        fi
        {{ printf "$(printf '\\%03o' $((length & 255)) $((length >> 8 & 255)) $((length >> 16 & 255)) $((length >> 24 & 255)) "$tag")"
           dd bs=1 count=$((length - 1)) 2>/dev/null; }} >&3
    done
) <&4 4<&- >/dev/null &
exec 4<&-
exec "{real}" "$1" "$2" < "$fifo"
"#,
                real = real.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    };

    // Two workers in 4 GiB get 1 GiB each; alone, one gets both shares. A job
    // that needs more than a share (here: dies under a 2 GB address-space
    // cap) is resolved by the retry on its own.
    // The cap in KiB: RLIMIT_AS, or what a macOS worker is handed instead.
    let starved = worker(
        "starved-worker",
        r#"{ limit=$(ulimit -v); [ -z "$BIARA_MEMORY_LIMIT" ] || limit=$((BIARA_MEMORY_LIMIT / 1024)); [ "$limit" != unlimited ] && [ "$limit" -lt 2000000 ]; }"#,
    );
    let cfg = recover_with_worker(&binary, &dir.join("starved.sqlite"), &starved, 2).unwrap();
    let targets = &cfg.indirect_calls[&site(&cfg)].targets;
    assert_eq!(targets.len(), 2, "{targets:?}");

    // A worker that dies at every resolution request, alone too, costs only
    // those results: recovery completes without them.
    let dying = worker("dying-worker", "true");
    let cfg = recover_with_worker(&binary, &dir.join("dying.sqlite"), &dying, 2).unwrap();
    let site = site(&cfg);
    assert!(
        cfg.indirect_calls
            .get(&site)
            .is_none_or(|t| t.targets.is_empty()),
        "{:?}",
        cfg.indirect_calls.get(&site)
    );
    assert!(
        cfg.issues()
            .any(|i| i == biara_cfg::CfgIssue::UnknownIndirectCall { address: site }),
        "the unresolved call is reported"
    );
}
