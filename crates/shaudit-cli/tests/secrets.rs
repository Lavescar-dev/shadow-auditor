//! Integration tests for the `secrets` verifier end-to-end.

use assert_cmd::Command;
use predicates::prelude::*;

/// Repository-root fixture directory. We compute this from CARGO_MANIFEST_DIR
/// (which is the `shaudit-cli` crate) and traverse up two levels.
fn workspace_fixture(name: &str) -> std::path::PathBuf {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn scan_detects_aws_key_in_rust() {
    let fixtures = workspace_fixture("with-secrets");
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--verifiers", "secrets", "--format", "json"])
        .arg(&fixtures)
        .output()
        .unwrap();
    assert!(
        out.status.code().unwrap_or(-1) <= 1,
        "exit {:?}, stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings array");

    let rule_ids: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    assert!(
        rule_ids.iter().any(|r| r.contains("aws")),
        "expected AWS rule match in: {rule_ids:?}"
    );
}

#[test]
fn scan_detects_github_pat_in_typescript() {
    let fixtures = workspace_fixture("with-secrets");
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--verifiers", "secrets", "--format", "json"])
        .arg(&fixtures)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings array");
    let has_github = findings
        .iter()
        .any(|f| f["rule_id"].as_str().is_some_and(|r| r.contains("github")));
    assert!(has_github, "expected GitHub rule match");
}

#[test]
fn scan_detects_high_entropy_literal() {
    let fixtures = workspace_fixture("with-secrets");
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--verifiers", "secrets", "--format", "json"])
        .arg(&fixtures)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings array");
    let has_entropy = findings
        .iter()
        .any(|f| f["rule_id"] == "secrets.generic-high-entropy");
    assert!(has_entropy, "expected generic-high-entropy match");
}

#[test]
fn scan_respects_inline_allowlist_marker() {
    // Scan only the commented_out fixture (which has a shaudit:allow marker)
    // and confirm 0 findings are produced.
    let fixture_file = workspace_fixture("with-secrets").join("commented_out.rs");
    let tmp = tempfile::tempdir().unwrap();
    std::fs::copy(&fixture_file, tmp.path().join("commented_out.rs")).unwrap();
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--verifiers", "secrets", "--format", "json"])
        .arg(tmp.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings");
    assert!(
        findings.is_empty(),
        "expected zero findings on allowlisted file, got: {findings:?}"
    );
}

#[test]
fn sarif_output_has_rule_descriptors_and_properties() {
    let fixtures = workspace_fixture("with-secrets");
    let tmp = tempfile::tempdir().unwrap();
    let sarif_path = tmp.path().join("out.sarif");
    Command::cargo_bin("shaudit")
        .unwrap()
        .args([
            "scan",
            "--verifiers",
            "secrets",
            "--format",
            "sarif",
            "--output",
        ])
        .arg(&sarif_path)
        .arg(&fixtures)
        .assert()
        .code(predicate::in_iter([0, 1]));

    let content = std::fs::read_to_string(&sarif_path).expect("read sarif");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse sarif");
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    assert!(!rules.is_empty(), "expected non-empty rules[]");
    assert!(
        rules.iter().any(|r| r["id"] == "secrets"),
        "expected `secrets` verifier descriptor"
    );

    let results = parsed["runs"][0]["results"].as_array().expect("results");
    assert!(!results.is_empty(), "expected at least one result");
    let first = &results[0];
    assert!(first["properties"]["shaudit"]["verifier_id"] == "secrets");
}

#[test]
fn scan_skip_flag_excludes_verifier() {
    let fixtures = workspace_fixture("with-secrets");
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--skip", "secrets", "--format", "json"])
        .arg(&fixtures)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings");
    assert!(
        findings.is_empty(),
        "--skip secrets should yield zero findings, got: {findings:?}"
    );
}

#[test]
fn scan_clean_fixture_reports_no_findings() {
    let fixtures = workspace_fixture("clean");
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--verifiers", "secrets", "--format", "json"])
        .arg(&fixtures)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json_start = stdout.find('{').expect("json output");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).expect("parse json");
    let findings = parsed["findings"].as_array().expect("findings");
    assert!(
        findings.is_empty(),
        "clean fixture should have no findings, got: {findings:?}"
    );
}
