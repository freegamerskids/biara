//! Real executable/stripped pairs: metrics, resource gates and code identity.
//! Requires the pinned clang/LLVM tools and the host libtcg, like the lift tests.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use biara_loader::Image;
use serde_json::Value;

fn llvm_tool(name: &str) -> PathBuf {
    Path::new(env!("BIARA_CLANG")).parent().unwrap().join(name)
}

fn build(dir: &Path, opt: u8, name: &str, rebase: bool) -> PathBuf {
    let binary = dir.join(name);
    let mut command = Command::new(env!("BIARA_CLANG"));
    command.args([
        &format!("-O{opt}"),
        "-g",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-optimize-sibling-calls",
        "-fno-pie",
        "-no-pie",
        "-fuse-ld=bfd",
    ]);
    if rebase {
        command.arg("-Wl,-Ttext-segment=0x500000");
    }
    let output = command
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/quality/prog.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn stripped(reference: &Path, candidate: &Path) {
    std::fs::copy(reference, candidate).unwrap();
    let output = Command::new(llvm_tool("llvm-strip"))
        .arg("--strip-all")
        .arg(candidate)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn command(reference: &Path, candidate: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_biara"));
    command.arg("quality").arg(reference).arg(candidate);
    command
}

fn measured(reference: &Path, candidate: &Path) -> Output {
    command(reference, candidate)
        .args([
            "--format",
            "json",
            "--min-function-recall",
            "0",
            "--min-edge-recall",
            "0",
            "--max-translation-failures",
            "1000000",
        ])
        .output()
        .unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid report: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn count(report: &Value, field: &str) -> usize {
    report[field].as_u64().unwrap() as usize
}

fn check_accounting(comparison: &Value) {
    let oracle = count(comparison, "oracle_count");
    let candidate = count(comparison, "candidate_count");
    let matched = count(comparison, "matched_count");
    assert_eq!(matched, comparison["matched"].as_array().unwrap().len());
    assert_eq!(
        oracle,
        matched + comparison["missing"].as_array().unwrap().len()
    );
    assert_eq!(
        candidate,
        matched + comparison["outside_oracle"].as_array().unwrap().len()
    );
    assert_eq!(
        comparison["recall"].as_f64().unwrap(),
        matched as f64 / oracle as f64
    );
}

#[test]
fn stripped_o0_o2_reports_have_native_ground_truth_and_repeatable_recovery() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("quality-native");
    std::fs::create_dir_all(&dir).unwrap();
    for opt in [0, 2] {
        let reference = build(&dir, opt, &format!("reference-o{opt}"), false);
        let candidate = dir.join(format!("candidate-o{opt}"));
        stripped(&reference, &candidate);
        for binary in [&reference, &candidate] {
            let native = Command::new(binary).output().unwrap();
            assert!(native.status.success(), "native ground truth failed");
            assert_eq!(native.stdout, b"55 7 8 12 18 7 1 -1\n");
        }
        let reference_image = Image::load(&reference).unwrap();
        let candidate_image = Image::load(&candidate).unwrap();
        assert!(
            candidate_image.symbol("fib").is_none(),
            "candidate was not stripped"
        );
        let expected: BTreeSet<_> = reference_image
            .symbols
            .iter()
            .filter(|s| s.is_function && reference_image.is_code(s.addr))
            .map(|s| s.addr)
            .collect();
        let first = measured(&reference, &candidate);
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let report = json(&first);
        let second = measured(&reference, &candidate);
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        let repeat = json(&second);
        for field in [
            "functions",
            "edges",
            "reference_recovery",
            "candidate_recovery",
            "function_names",
        ] {
            assert_eq!(
                report[field], repeat[field],
                "nonrepeatable {field} at O{opt}"
            );
        }
        assert_eq!(report["version"], 1);
        assert_eq!(count(&report["functions"], "oracle_count"), expected.len());
        check_accounting(&report["functions"]);
        check_accounting(&report["edges"]);
        let recovered: BTreeSet<_> = report["functions"]["matched"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap())
            .collect();
        for name in [
            "fib",
            "plus",
            "quality_multiply",
            "dispatch",
            "callback",
            "unknown_callback",
            "checks",
            "main",
        ] {
            let address = reference_image.symbol(name).unwrap().addr;
            assert!(
                recovered.contains(&address),
                "stripped recovery missed {name} at O{opt}"
            );
        }
        let fib = reference_image.symbol("fib").unwrap().addr;
        let matched_edges = report["edges"]["matched"].as_array().unwrap();
        assert!(
            matched_edges
                .iter()
                .any(|edge| edge["kind"] == "direct_call" && edge["target"].as_u64() == Some(fib))
        );
        assert!(
            matched_edges
                .iter()
                .any(|edge| edge["kind"] == "call_return")
        );
        for name in ["plus", "quality_multiply"] {
            let target = reference_image.symbol(name).unwrap().addr;
            assert!(
                matched_edges
                    .iter()
                    .any(|edge| edge["kind"] == "indirect_call"
                        && edge["target"].as_u64() == Some(target)),
                "resolved pointer/callback edge missing for {name} at O{opt}"
            );
        }
        assert!(
            count(&report["candidate_recovery"], "unknown_edges") > 0,
            "volatile callback must not be treated as exhaustively resolved"
        );
        assert!(
            report["candidate_recovery"]["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["kind"] == "unknown_indirect_call")
        );
        assert_eq!(
            report["oracle_scope"]["reference_is_completeness_certificate"],
            false
        );
        assert_eq!(
            report["oracle_scope"]["outside_oracle_is_false_positive"],
            false
        );
        assert!(report["oracle_scope"]["vulnerability_recall"].is_null());
        assert!(report["resources"]["wall_seconds"].as_f64().unwrap() > 0.0);
        assert!(report["resources"]["peak_rss_mib"].as_f64().unwrap() > 0.0);
        assert!(report["passed"].as_bool().unwrap());
    }
}

#[test]
fn threshold_failure_flushes_complete_reports_and_preserves_limit_evidence() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("quality-gates");
    std::fs::create_dir_all(&dir).unwrap();
    let reference = build(&dir, 0, "reference", false);
    let candidate = dir.join("candidate");
    stripped(&reference, &candidate);
    for (option, metric) in [
        ("--max-unknown-edges", "unknown_edges"),
        ("--max-seconds", "wall_seconds"),
        ("--max-rss-mib", "peak_rss_mib"),
    ] {
        let path = dir.join(format!("{metric}.json"));
        let output = command(&reference, &candidate)
            .args([
                "--format",
                "json",
                "--min-function-recall",
                "0",
                "--min-edge-recall",
                "0",
                "--max-translation-failures",
                "1000000",
                option,
                "0",
                "-o",
            ])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{metric} gate should fail");
        assert!(output.stdout.is_empty());
        let report: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report["passed"], false);
        assert!(
            report["gates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gate| gate["metric"] == metric && gate["passed"] == false)
        );
    }
    let limited = command(&reference, &candidate)
        .args(["--format", "json", "--max-blocks", "1"])
        .output()
        .unwrap();
    assert!(!limited.status.success());
    let report = json(&limited);
    assert!(report["functions"]["recall"].as_f64().unwrap() < 1.0);
    for name in ["reference_recovery", "candidate_recovery"] {
        assert_eq!(report[name]["recovery"]["block_limit_reached"], true);
        assert!(
            report[name]["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["kind"] == "block_limit")
        );
    }
    let text = command(&reference, &candidate)
        .args([
            "--min-function-recall",
            "0",
            "--min-edge-recall",
            "0",
            "--max-seconds",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!text.status.success());
    assert!(
        !text.stdout.is_empty(),
        "failed gate must still emit the text report"
    );
}

#[test]
fn mismatched_code_rebases_and_symbolless_oracles_are_rejected() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("quality-rejections");
    std::fs::create_dir_all(&dir).unwrap();
    let reference = build(&dir, 0, "reference", false);
    let candidate = dir.join("candidate");
    stripped(&reference, &candidate);
    let original = std::fs::read(&candidate).unwrap();
    let image = Image::load(&reference).unwrap();
    let address = image.symbol("fib").unwrap().addr;
    let stripped_image = Image::load(&candidate).unwrap();
    let (code, base) = stripped_image.code_at(address).unwrap();
    let offset = original
        .windows(code.len())
        .position(|bytes| bytes == code)
        .unwrap();
    let mut changed = original;
    changed[offset + usize::try_from(address - base).unwrap()] ^= 1;
    let modified = dir.join("modified");
    std::fs::write(&modified, changed).unwrap();
    let rebased = build(&dir, 0, "rebased", true);
    let differently_optimized = build(&dir, 2, "different-code", false);
    for other in [&modified, &rebased, &differently_optimized] {
        let rejected = command(&reference, other)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        assert!(
            rejected.stdout.is_empty(),
            "invalid pair must not produce quality measurements"
        );
    }
    let no_oracle = command(&candidate, &candidate).output().unwrap();
    assert!(!no_oracle.status.success());
    assert!(no_oracle.stdout.is_empty());
    for invalid in ["NaN", "inf", "-0.1", "1.01"] {
        let rejected = command(&reference, &candidate)
            .args(["--min-function-recall", invalid])
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "invalid recall threshold {invalid} was accepted"
        );
        assert!(rejected.stdout.is_empty());
    }
}

#[test]
fn translation_failures_are_measured_and_gated_not_hidden_as_unknown_edges() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("quality-translation-failure");
    std::fs::create_dir_all(&dir).unwrap();
    let reference = dir.join("reference");
    let candidate = dir.join("candidate");
    let built = Command::new(env!("BIARA_CLANG"))
        .args(["-O0", "-g", "-fno-pie", "-no-pie", "-fuse-ld=bfd"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/quality/failure.c"
        ))
        .arg("-o")
        .arg(&reference)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    stripped(&reference, &candidate);
    for binary in [&reference, &candidate] {
        assert!(Command::new(binary).status().unwrap().success());
    }
    let failed = command(&reference, &candidate)
        .args([
            "--format",
            "json",
            "--min-function-recall",
            "0",
            "--min-edge-recall",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    let report = json(&failed);
    let failures = count(&report["candidate_recovery"], "translation_failures");
    assert!(failures > 0);
    assert_eq!(
        failures,
        report["candidate_recovery"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|issue| issue["kind"] == "translation_failure")
            .count()
    );
    assert!(
        report["gates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gate| gate["metric"] == "translation_failures"
                && gate["passed"] == false
                && gate["measured"].as_f64() == Some(failures as f64))
    );
    let accepted = measured(&reference, &candidate);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_eq!(
        count(
            &json(&accepted)["candidate_recovery"],
            "translation_failures"
        ),
        failures
    );
}
