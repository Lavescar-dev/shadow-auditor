//! Shadow Auditor — rendering findings to terminal, JSON, or SARIF.
//!
//! Full SARIF v2.1.0 compliance and the terminal table view land across Hafta
//! 3-7. This module defines the `Renderer` trait + minimal terminal and JSON
//! renderers that work today.

use std::io::Write;
use std::time::Duration;

use shaudit_core::{Finding, Severity};

mod json;
mod sarif;
mod terminal;

pub use json::JsonRenderer;
pub use sarif::SarifRenderer;
pub use terminal::TerminalRenderer;

/// Minimal descriptor for SARIF's `rules[]` array. Built by the CLI from
/// each registered verifier's `id()` and `description()`.
#[derive(Debug, Clone)]
pub struct RuleDescriptor {
    pub verifier_id: String,
    pub description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialize error: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, RenderError>;

#[derive(Debug, Clone)]
pub struct RunMeta {
    pub tool_version: &'static str,
    pub candidates_scanned: usize,
    pub verifiers_run: Vec<String>,
    pub duration: Duration,
}

pub trait Renderer {
    fn render(&self, findings: &[Finding], meta: &RunMeta, w: &mut dyn Write) -> Result<()>;
}

pub fn counts_by_severity(findings: &[Finding]) -> [usize; 5] {
    let mut c = [0usize; 5];
    for f in findings {
        c[severity_idx(f.severity)] += 1;
    }
    c
}

fn severity_idx(s: Severity) -> usize {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}
