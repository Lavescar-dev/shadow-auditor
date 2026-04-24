use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn fixture_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
    fs::write(dir.path().join("b.py"), "print('hi')").unwrap();
    fs::write(dir.path().join("c.ts"), "export const x = 1;").unwrap();
    dir
}

#[test]
fn help_prints_usage() {
    Command::cargo_bin("shaudit")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Verify what your AI just wrote"));
}

#[test]
fn version_command_shows_homepage() {
    Command::cargo_bin("shaudit")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit.lavescar.com.tr"));
}

#[test]
fn verifiers_lists_the_six_plan_verifiers() {
    Command::cargo_bin("shaudit")
        .unwrap()
        .arg("verifiers")
        .assert()
        .success()
        .stdout(predicate::str::contains("secrets"))
        .stdout(predicate::str::contains("hallucination"))
        .stdout(predicate::str::contains("property"));
}

#[test]
fn scan_with_no_findings_exits_zero() {
    let dir = fixture_dir();
    Command::cargo_bin("shaudit")
        .unwrap()
        .arg("scan")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("0 findings"));
}

#[test]
fn scan_json_output_is_valid_json() {
    let dir = fixture_dir();
    let out = Command::cargo_bin("shaudit")
        .unwrap()
        .args(["scan", "--format", "json"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "scan failed: {:?}", out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("json parse: {e}\n---\n{stdout}"));
    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("run").is_some());
}

#[test]
fn init_creates_config_files() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("shaudit")
        .unwrap()
        .arg("init")
        .current_dir(dir.path())
        .assert()
        .success();
    assert!(dir.path().join("shaudit.toml").exists());
    assert!(dir.path().join(".shauditignore").exists());
}
