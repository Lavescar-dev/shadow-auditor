//! Rust-ecosystem CVE scanning via the `rustsec` crate.
//!
//! Uses the `rustsec` advisory database (local clone at
//! `~/.cargo/advisory-db` by default; fetched on first use) and the
//! `Cargo.lock` found at the workspace root.

use std::path::Path;

use shaudit_core::{Finding, Location, Severity};

use crate::CveError;

pub fn scan(workspace_root: &Path) -> Result<Vec<Finding>, CveError> {
    let lockfile_path = workspace_root.join("Cargo.lock");
    if !lockfile_path.exists() {
        return Ok(Vec::new());
    }

    let lockfile = rustsec::Lockfile::load(&lockfile_path)
        .map_err(|e| CveError::Parse(format!("Cargo.lock: {e}")))?;

    // Open or fetch the advisory database. Offline-first: if the user
    // already cloned it, skip the fetch. Otherwise pull from GitHub.
    let db = load_database()?;

    let report = rustsec::Report::generate(&db, &lockfile, &rustsec::report::Settings::default());

    let mut findings = Vec::new();
    for vuln in &report.vulnerabilities.list {
        let advisory = &vuln.advisory;
        let pkg_name = vuln.package.name.to_string();
        let pkg_version = vuln.package.version.to_string();

        let severity = advisory
            .cvss
            .as_ref()
            .map(|cvss| map_cvss_severity(cvss.score()))
            .unwrap_or(Severity::High);

        let patched_versions = vuln
            .versions
            .patched()
            .iter()
            .map(|v: &rustsec::VersionReq| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let fix_hint = if patched_versions.is_empty() {
            "(no patched version available)".to_string()
        } else {
            format!("(fixed in: {patched_versions})")
        };

        findings.push(Finding {
            verifier_id: crate::ID.to_string(),
            rule_id: format!("cve.rust.{}", advisory.id),
            severity,
            message: format!(
                "{pkg_name} {pkg_version}: {title} {fix_hint}",
                title = advisory.title
            ),
            location: Location {
                path: lockfile_path.clone(),
                start_line: 1,
                start_col: 1,
                end_line: 1,
                end_col: 1,
                snippet: Some(format!("{pkg_name} = \"{pkg_version}\"")),
            },
            fix: None,
            provenance_score: None,
            metadata: serde_json::json!({
                "advisory_id": advisory.id.to_string(),
                "package": pkg_name,
                "version": pkg_version,
                "patched_versions": patched_versions,
                "url": advisory.url.as_ref().map(|u| u.to_string()),
            }),
        });
    }

    Ok(findings)
}

fn load_database() -> Result<rustsec::Database, CveError> {
    // Default location used by cargo-audit: ~/.cargo/advisory-db
    let default_path = dirs::home_dir()
        .map(|h| h.join(".cargo/advisory-db"))
        .ok_or_else(|| CveError::Env("HOME not set".into()))?;

    if default_path.exists() {
        return rustsec::Database::open(&default_path)
            .map_err(|e| CveError::Database(format!("open local DB: {e}")));
    }

    tracing::info!(
        path = %default_path.display(),
        "advisory DB not found locally; fetching from upstream"
    );
    rustsec::Database::fetch().map_err(|e| CveError::Database(format!("fetch: {e}")))
}

fn map_cvss_severity(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}
