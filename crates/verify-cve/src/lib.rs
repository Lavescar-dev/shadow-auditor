//! Shadow Auditor — CVE verifier (plan §4.2).
//!
//! Rust: `rustsec` advisory-db + Cargo.lock.
//! Node / Python / Go: lockfile parsers + OSV.dev REST batch query + 24h
//! filesystem cache (`~/.cache/shaudit/cve/`).

use std::path::Path;

use async_trait::async_trait;

use shaudit_core::{Candidate, Concurrency, Finding, Language, Verifier, VerifyContext};

mod cache;
mod lockfiles;
mod osv;
mod rust;

pub const ID: &str = "cve";

#[derive(Debug, thiserror::Error)]
pub enum CveError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("network error: {0}")]
    Network(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("advisory database error: {0}")]
    Database(String),
    #[error("environment: {0}")]
    Env(String),
}

pub struct CveVerifier {
    supported: [Language; 5],
    /// Cache TTL in seconds. Defaults to 24 hours (`cache::DEFAULT_TTL_SECS`).
    ttl_secs: u64,
}

impl CveVerifier {
    pub fn new() -> Self {
        Self {
            supported: [
                Language::Rust,
                Language::TypeScript,
                Language::JavaScript,
                Language::Python,
                Language::Go,
            ],
            ttl_secs: cache::DEFAULT_TTL_SECS,
        }
    }

    pub fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }
}

impl Default for CveVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Verifier for CveVerifier {
    fn id(&self) -> &'static str {
        ID
    }

    fn description(&self) -> &'static str {
        "Detects known-vulnerable dependencies across Rust/Node/Python/Go lockfiles"
    }

    fn supported_languages(&self) -> &[Language] {
        &self.supported
    }

    fn concurrency(&self) -> Concurrency {
        // CVE runs once at workspace scope, not per-file; but we still emit
        // findings from a candidate-matching call for pipeline simplicity.
        Concurrency::Parallel
    }

    async fn verify(
        &self,
        candidate: &Candidate,
        ctx: &VerifyContext<'_>,
    ) -> shaudit_core::Result<Vec<Finding>> {
        // The CVE scanner is workspace-scoped. We only run it once per
        // workspace — on the first Rust-ecosystem candidate we see. Other
        // candidates yield no findings.
        if candidate.language != Language::Rust || !is_first_rust_candidate(candidate) {
            return Ok(Vec::new());
        }
        run_scan(ctx.workspace_root, self.ttl_secs)
            .await
            .map_err(|e| shaudit_core::Error::VerifierFailed {
                verifier: ID,
                source: Box::new(e),
            })
    }
}

/// Very simple per-process latch so multiple Rust candidates don't re-run
/// the workspace scan. First invocation wins.
fn is_first_rust_candidate(_candidate: &Candidate) -> bool {
    static LATCH: std::sync::OnceLock<std::sync::Mutex<bool>> = std::sync::OnceLock::new();
    let lock = LATCH.get_or_init(|| std::sync::Mutex::new(false));
    let mut guard = lock.lock().unwrap();
    if *guard {
        false
    } else {
        *guard = true;
        true
    }
}

async fn run_scan(workspace_root: &Path, ttl_secs: u64) -> Result<Vec<Finding>, CveError> {
    let mut findings = Vec::new();

    // --- Rust via rustsec (synchronous, wrap in spawn_blocking) ---
    let ws = workspace_root.to_path_buf();
    let rust_findings = tokio::task::spawn_blocking(move || rust::scan(&ws))
        .await
        .map_err(|e| CveError::Database(format!("rustsec task: {e}")))??;
    findings.extend(rust_findings);

    // --- Node / Python / Go via OSV.dev ---
    let eco = lockfiles::detect_and_parse(workspace_root);

    if let Some((path, pkgs)) = eco.node {
        match osv::query_batch(&pkgs, "npm", &path, ttl_secs).await {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => tracing::warn!(%e, "osv.dev npm query failed"),
        }
    }
    if let Some((path, pkgs)) = eco.python {
        match osv::query_batch(&pkgs, "PyPI", &path, ttl_secs).await {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => tracing::warn!(%e, "osv.dev PyPI query failed"),
        }
    }
    if let Some((path, pkgs)) = eco.go {
        match osv::query_batch(&pkgs, "Go", &path, ttl_secs).await {
            Ok(mut f) => findings.append(&mut f),
            Err(e) => tracing::warn!(%e, "osv.dev Go query failed"),
        }
    }

    Ok(findings)
}
