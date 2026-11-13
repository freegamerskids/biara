//! Function packages are independently navigable and never hide bounded context.
#![cfg(target_os = "linux")]
use biara_loader::Image;
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

fn fixture(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    fs::write(&source,r#"
extern int puts(const char *);
__attribute__((noinline,used)) unsigned long leaf(unsigned long value) { __asm__ volatile("" : "+r"(value)); return value*3+1; }
__attribute__((noinline,used)) unsigned long target(unsigned long count) { unsigned long total=0; for(unsigned long i=0;i<count;i++) total+=leaf(i); return total; }
__attribute__((noinline,used)) int message(void) { return puts("package evidence"); }
__attribute__((noinline,used)) long open_callback(long (*callback)(long),long value) { return callback(value)+1; }
int main(void) { return target(3)!=12; }
"#).unwrap();
    let built = Command::new(env!("BIARA_CLANG"))
        .args([
            "-O2",
            "-g",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-fuse-ld=bfd",
        ])
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
    assert!(Command::new(&binary).status().unwrap().success());
    binary
}
fn run_emit(binary: &PathBuf, emit: &str, roots: &[&str], args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(binary)
        .args(roots)
        .args(["--emit", emit])
        .args(args)
        .output()
        .unwrap()
}
fn run(binary: &PathBuf, roots: &[&str], args: &[&str]) -> Output {
    run_emit(binary, "decomp", roots, args)
}
fn report(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn body(record: &Value) -> String {
    record["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["text"].as_str().unwrap())
        .collect()
}
#[test]
fn chunked_packages_preserve_code_and_source_links_with_explicit_context_caps() {
    let binary = fixture("decomp-chunks");
    let image = Image::load(&binary).unwrap();
    let target = image.symbol("target").unwrap().addr;
    let leaf = image.symbol("leaf").unwrap().addr;
    let full = report(run(
        &binary,
        &["target"],
        &[
            "--format",
            "json",
            "--chunk-lines",
            "10000",
            "--context-depth",
            "1",
        ],
    ));
    let split = report(run(
        &binary,
        &["target"],
        &[
            "--format",
            "json",
            "--chunk-lines",
            "4",
            "--context-depth",
            "1",
        ],
    ));
    let f = &split["functions"][0];
    assert_eq!(f["function"]["address"], target);
    assert_eq!(body(f), body(&full["functions"][0]));
    let mut expected_line = 1;
    for chunk in f["chunks"].as_array().unwrap() {
        assert_eq!(chunk["first_line"], expected_line);
        let last = chunk["last_line"].as_u64().unwrap();
        assert!(last - expected_line < 4);
        expected_line = last + 1;
    }
    let text = body(f);
    let lines: Vec<_> = text.lines().collect();
    for s in f["function"]["statements"].as_array().unwrap() {
        let line = s["line"].as_u64().unwrap() as usize;
        assert!((1..=lines.len()).contains(&line));
        let owners: Vec<_> = f["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["statement_ids"].as_array().unwrap().contains(&s["id"]))
            .collect();
        assert_eq!(owners.len(), 1);
        assert!(
            owners[0]["first_line"].as_u64().unwrap() <= line as u64
                && owners[0]["last_line"].as_u64().unwrap() >= line as u64
        );
        if s["provenance"] == "unknown" {
            assert!(s["addresses"].as_array().unwrap().is_empty());
        }
        for address in s["addresses"].as_array().unwrap() {
            assert!(image.code_at(address.as_u64().unwrap()).is_some());
        }
    }
    assert!(
        f["context"]["callees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["address"] == leaf)
    );
    let capped = report(run(
        &binary,
        &["target"],
        &[
            "--format",
            "json",
            "--context-depth",
            "1",
            "--context-functions",
            "1",
        ],
    ));
    assert_eq!(capped["functions"].as_array().unwrap().len(), 1);
    assert!(
        capped["metadata"]["selection"]["omitted"]
            .as_array()
            .unwrap()
            .contains(&Value::from(leaf))
    );
    assert_eq!(capped["metadata"]["selection"]["callers_complete"], false);
}
#[test]
fn jsonl_retains_dependencies_unknown_callbacks_and_failed_gate_reports() {
    let binary = fixture("decomp-records");
    let output = run(
        &binary,
        &["message", "open_callback"],
        &[
            "--format",
            "jsonl",
            "--chunk-lines",
            "3",
            "--max-body-tokens",
            "0",
        ],
    );
    assert!(!output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.first().unwrap()["record"], "index");
    let message = records
        .iter()
        .find(|r| r["record"] == "function" && r["function"]["name"] == "message")
        .unwrap();
    let dependencies = message["function"]["dependencies"].as_array().unwrap();
    assert!(
        dependencies
            .iter()
            .any(|d| d["text"].as_str().unwrap().contains("puts"))
    );
    let callback = records
        .iter()
        .find(|r| r["record"] == "function" && r["function"]["name"] == "open_callback")
        .unwrap();
    assert!(
        callback["context"]["indirect_transfers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["exhaustive"] == false)
    );
    assert!(
        callback["context"]["debug_parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|parameter| parameter["name"] == "callback"
                && parameter["type_name"] == "long (*)(long)")
    );
    assert_eq!(records.last().unwrap()["analysis"]["passed"], false);
    let failed = run(
        &binary,
        &["target"],
        &["--format", "json", "-o", "/dev/full"],
    );
    assert!(!failed.status.success());
}
#[test]
fn entry_debug_names_and_repeated_packages_have_stable_identities() {
    let binary = fixture("decomp-debug");
    let first = report(run(&binary, &["leaf"], &["--format", "json"]));
    let second = report(run(&binary, &["leaf"], &["--format", "json"]));
    assert_eq!(first, second);
    let f = &first["functions"][0]["function"];
    assert!(
        f["names"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["name"] == "value" && n["evidence"] == "debug")
    );
}

#[test]
fn serial_and_parallel_decompilation_agree_deterministically() {
    let binary = fixture("decomp-jobs");
    let serial = report(run(
        &binary,
        &["target"],
        &["--format", "json", "--jobs", "1"],
    ));
    let parallel = report(run(
        &binary,
        &["target"],
        &["--format", "json", "--jobs", "16"],
    ));
    assert_eq!(serial, parallel);
    let first = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(&binary)
        .arg("target")
        .args(["--emit", "decomp", "--format", "jsonl", "--jobs", "1"])
        .output()
        .unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_biara"))
        .arg("lift")
        .arg(&binary)
        .arg("target")
        .args(["--emit", "decomp", "--format", "jsonl", "--jobs", "16"])
        .output()
        .unwrap();
    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn serial_and_parallel_c_output_agree() {
    let binary = fixture("decomp-jobs-c");
    let serial = run_emit(&binary, "c", &["target"], &["--jobs", "1"]);
    assert!(
        serial.status.success(),
        "{}",
        String::from_utf8_lossy(&serial.stderr)
    );
    let parallel = run_emit(&binary, "c", &["target"], &["--jobs", "16"]);
    assert!(
        parallel.status.success(),
        "{}",
        String::from_utf8_lossy(&parallel.stderr)
    );
    assert_eq!(serial.stdout, parallel.stdout);
}

#[test]
fn jobs_controls_recovery_for_all_emit_modes_and_rejects_zero() {
    let binary = fixture("decomp-jobs-recovery");
    for emit in ["llvm", "tcg", "cfg", "abi", "calls", "audit"] {
        let serial = run_emit(&binary, emit, &["target"], &["--jobs", "1"]);
        let parallel = run_emit(&binary, emit, &["target"], &["--jobs", "2"]);
        for output in [&serial, &parallel] {
            assert!(
                output.status.success(),
                "{emit}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(serial.stdout, parallel.stdout, "{emit}");
    }
    for emit in ["llvm", "tcg", "cfg", "abi", "calls", "audit", "c", "decomp"] {
        assert!(
            !run_emit(&binary, emit, &["target"], &["--jobs", "0"])
                .status
                .success()
        );
    }
}

#[test]
fn jobs_preserves_gate_and_sink_failures() {
    let binary = fixture("decomp-jobs-gates");
    // Failed readability gates still emit the complete report before
    // failing, with an explicit serial budget and a clamped request alike.
    for jobs in ["1", "16"] {
        let output = run(
            &binary,
            &["message", "open_callback"],
            &[
                "--format",
                "jsonl",
                "--chunk-lines",
                "3",
                "--max-body-tokens",
                "0",
                "--jobs",
                jobs,
            ],
        );
        assert!(!output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let records: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.first().unwrap()["record"], "index");
        assert_eq!(records.last().unwrap()["analysis"]["passed"], false);
    }
    let failed = run(
        &binary,
        &["target"],
        &["--format", "json", "-o", "/dev/full", "--jobs", "16"],
    );
    assert!(!failed.status.success());
}

#[test]
fn semantic_tokens_address_the_complete_body_in_json_and_jsonl() {
    use biara_proto::tokens::{SymbolRef, Token, substitute};
    use std::collections::BTreeMap;

    let binary = fixture("decomp-semantic-tokens");
    let image = Image::load(&binary).unwrap();
    let target = image.symbol("target").unwrap().addr;
    let leaf = image.symbol("leaf").unwrap().addr;
    let check_addresses = |header: &Value| {
        let symbols: biara_proto::PackageSymbols =
            serde_json::from_value(header["symbols"].clone()).unwrap();
        for function in symbols.functions {
            assert!(
                image.code_at(function.address).is_some(),
                "{} has no guest code at {:#x}",
                function.text,
                function.address
            );
        }
    };
    for format in ["json", "jsonl"] {
        let output = run(
            &binary,
            &["target", "message"],
            &[
                "--format",
                format,
                "--chunk-lines",
                "3",
                "--context-depth",
                "1",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (header, text) = if format == "json" {
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            for record in report["functions"].as_array().unwrap() {
                check_addresses(&record["function"]);
            }
            let record = report["functions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["function"]["address"] == target)
                .unwrap();
            (record["function"].clone(), body(record))
        } else {
            let records: Vec<Value> = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            for record in records.iter().filter(|r| r["record"] == "function") {
                check_addresses(&record["function"]);
            }
            let record = records
                .iter()
                .find(|r| r["record"] == "function" && r["function"]["address"] == target)
                .unwrap();
            let text = records
                .iter()
                .filter(|r| r["record"] == "chunk" && r["function_address"] == target)
                .map(|r| r["chunk"]["text"].as_str().unwrap())
                .collect::<String>();
            (record["function"].clone(), text)
        };
        let tokens: Vec<Token> = serde_json::from_value(header["tokens"].clone()).unwrap();
        let symbols: biara_proto::PackageSymbols =
            serde_json::from_value(header["symbols"].clone()).unwrap();
        let callee = symbols
            .functions
            .iter()
            .find(|f| f.address == leaf)
            .unwrap();
        let key = SymbolRef::Function { address: leaf };
        let mut offset = 0;
        let mut expected = String::new();
        let mut call_found = false;
        for token in &tokens {
            assert_eq!(token.start, offset);
            assert!(token.end > token.start);
            let span = &text[token.start as usize..token.end as usize];
            if token.symbol.as_ref() == Some(&key) {
                assert_eq!(span, callee.text);
                expected.push_str("renamed_leaf");
                call_found = true;
            } else {
                expected.push_str(span);
            }
            offset = token.end;
        }
        assert_eq!(offset as usize, text.len());
        assert!(call_found, "missing callee identity in {format}");
        assert_eq!(
            substitute(
                &text,
                &tokens,
                &BTreeMap::from([(key, "renamed_leaf".into())])
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn signed_annotations_preserve_unsigned_guest_arithmetic() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("decomp-signed-arithmetic-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("program.c");
    let binary = dir.join("program");
    fs::write(
        &source,
        r#"
#include <stdint.h>
__attribute__((noinline,used)) uint64_t logical(uint64_t x) { return x >> 1; }
__attribute__((noinline,used)) uint64_t wrapping(uint64_t x) { return x + 1; }
__attribute__((noinline,used)) int16_t narrow(int16_t x) { return x - 300; }
int main(void) { return 0; }
"#,
    )
    .unwrap();
    let built = Command::new(env!("BIARA_CLANG"))
        .args(["-O2", "-fno-pie", "-no-pie", "-fuse-ld=bfd"])
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
    let image = Image::load(&binary).unwrap();
    let mut functions = serde_json::Map::new();
    for (name, signature) in [
        ("logical", "int64_t logical(int64_t)"),
        ("wrapping", "int64_t wrapping(int64_t)"),
        ("narrow", "int16_t narrow(int16_t)"),
    ] {
        functions.insert(
            image.symbol(name).unwrap().addr.to_string(),
            serde_json::json!({"signature": signature}),
        );
    }
    let annotations = dir.join("annotations.json");
    fs::write(
        &annotations,
        serde_json::to_vec(&serde_json::json!({"version": 1, "functions": functions})).unwrap(),
    )
    .unwrap();
    let report = report(run(
        &binary,
        &["logical", "wrapping", "narrow"],
        &[
            "--format",
            "json",
            "--annotations",
            annotations.to_str().unwrap(),
        ],
    ));
    let recovered: String = report["functions"]
        .as_array()
        .unwrap()
        .iter()
        .map(body)
        .collect();
    let consumer = dir.join("consumer.c");
    fs::write(
        &consumer,
        format!(
            r#"
#include <stdint.h>
#include <limits.h>
{recovered}
int main(void) {{
    if ((uint64_t)logical(-2) != UINT64_C(0x7fffffffffffffff)) return 1;
    if (wrapping(INT64_MAX) != INT64_MIN) return 2;
    if (wrapping(-1) != 0) return 3;
    for (int32_t x = INT16_MIN; x <= INT16_MAX; ++x)
        if (narrow((int16_t)x) != (int16_t)(x - 300)) return 4;
    return 0;
}}
"#
        ),
    )
    .unwrap();
    let executable = dir.join("consumer");
    let compiled = Command::new(env!("BIARA_CLANG"))
        .args([
            "-O2",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=undefined",
        ])
        .arg(&consumer)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(executable).output().unwrap();
    assert!(
        result.status.success(),
        "{:?}: {}",
        result.status.code(),
        String::from_utf8_lossy(&result.stderr)
    );
}
