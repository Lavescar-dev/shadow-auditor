//! Integration tests for AI provenance detection and the `--ai-*` flags.

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture(name: &str) -> std::path::PathBuf {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

fn scan_json(args: &[&str], path: &std::path::Path) -> serde_json::Value {
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(args)
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    serde_json::from_str(&stdout[json_start..]).expect("parse json")
}

#[test]
fn inline_ai_marker_forces_full_score() {
    // Create a temp dir with only the AI-marked fixture.
    let tmp = tempfile::tempdir().unwrap();
    let src = fixture("ai-authored/ai_marker.rs");
    std::fs::copy(&src, tmp.path().join("ai_marker.rs")).unwrap();

    // Use `secrets` as the verifier just so pipeline runs; detection output
    // is attached to any emitted findings. We need at least one finding to
    // inspect `provenance_score`, so append an AWS-like literal.
    std::fs::write(
        tmp.path().join("leak.rs"),
        "// shaudit:ai\nfn main() { let _ = \"AKIAIOSFODNN7EXAMPLE\"; }\n",
    )
    .unwrap();

    let out = scan_json(
        &["scan", "--verifiers", "secrets", "--format", "json"],
        tmp.path(),
    );
    let findings = out["findings"].as_array().expect("findings");
    let any_high_score = findings
        .iter()
        .any(|f| f["provenance_score"].as_f64().is_some_and(|v| v >= 0.99));
    assert!(
        any_high_score,
        "expected a finding with provenance_score = 1.0 under // shaudit:ai, got: {findings:?}"
    );
}

#[test]
fn no_detect_flag_suppresses_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("leak.rs"),
        "// shaudit:ai\nfn main() { let _ = \"AKIAIOSFODNN7EXAMPLE\"; }\n",
    )
    .unwrap();

    let out = scan_json(
        &[
            "scan",
            "--verifiers",
            "secrets",
            "--no-detect",
            "--format",
            "json",
        ],
        tmp.path(),
    );
    let findings = out["findings"].as_array().expect("findings");
    let any_with_score = findings
        .iter()
        .any(|f| f["provenance_score"].as_f64().is_some());
    assert!(
        !any_with_score,
        "--no-detect must not populate provenance_score, got: {findings:?}"
    );
}

#[test]
fn ai_only_filters_out_human_marked_files() {
    let tmp = tempfile::tempdir().unwrap();
    // One human-marked file (0.0) with a leak — should be filtered out.
    std::fs::write(
        tmp.path().join("human.rs"),
        "// shaudit:human\nfn main() { let _ = \"AKIAIOSFODNN7EXAMPLE\"; }\n",
    )
    .unwrap();
    // One AI-marked file (1.0) with a different leak — should remain.
    std::fs::write(
        tmp.path().join("ai.rs"),
        "// shaudit:ai\nfn main() { let _ = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz12\"; }\n",
    )
    .unwrap();

    let out = scan_json(
        &[
            "scan",
            "--verifiers",
            "secrets",
            "--ai-only",
            "--format",
            "json",
        ],
        tmp.path(),
    );
    let findings = out["findings"].as_array().expect("findings");
    let from_human = findings.iter().any(|f| {
        f["location"]["path"]
            .as_str()
            .unwrap_or("")
            .ends_with("human.rs")
    });
    let from_ai = findings.iter().any(|f| {
        f["location"]["path"]
            .as_str()
            .unwrap_or("")
            .ends_with("ai.rs")
    });
    assert!(
        !from_human,
        "--ai-only should filter human.rs, got findings: {findings:?}"
    );
    assert!(from_ai, "expected findings from ai.rs, got: {findings:?}");
}

#[test]
fn detect_stub_command_exists() {
    Command::cargo_bin("shaudit")
        .unwrap()
        .args(["detect"])
        .assert()
        .success();
}

#[test]
fn verifiers_command_lists_all_verifiers() {
    Command::cargo_bin("shaudit")
        .unwrap()
        .arg("verifiers")
        .assert()
        .success()
        .stdout(predicate::str::contains("secrets"))
        .stdout(predicate::str::contains("cve"));
}
