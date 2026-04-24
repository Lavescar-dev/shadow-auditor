//! Core types for Shadow Auditor.
//!
//! Defines the `Verifier` trait and the `Finding` shape that every verifier
//! emits. All other crates depend on this one.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("verifier `{0}` timed out")]
    Timeout(&'static str),

    #[error("verifier `{verifier}` failed: {source}")]
    VerifierFailed {
        verifier: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "info" | "none" => Some(Self::Info),
            _ => None,
        }
    }

    /// Numeric rank for severity comparisons. Higher = more severe.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: PathBuf,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub description: String,
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub verifier_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_score: Option<f32>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concurrency {
    Parallel,
    SerialPerWorkspace,
    SerialGlobal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    TypeScript,
    JavaScript,
    Python,
    Go,
    Unknown,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_ascii_lowercase().as_str() {
            "rs" => Language::Rust,
            "ts" | "tsx" => Language::TypeScript,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "py" | "pyi" => Language::Python,
            "go" => Language::Go,
            _ => Language::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::TypeScript => "typescript",
            Language::JavaScript => "javascript",
            Language::Python => "python",
            Language::Go => "go",
            Language::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RangeSet {
    /// Half-open ranges `[start, end)` over 1-based line numbers.
    ranges: Vec<(u32, u32)>,
}

impl RangeSet {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn push(&mut self, start: u32, end: u32) {
        if start < end {
            self.ranges.push((start, end));
        }
    }

    pub fn contains(&self, line: u32) -> bool {
        self.ranges.iter().any(|(s, e)| line >= *s && line < *e)
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }
}

/// A file that is a candidate for verification.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub language: Language,
    pub changed_lines: Option<RangeSet>,
    pub commit_sha: Option<String>,
    /// AI-authorship score in [0.0, 1.0], filled by `shaudit-detect`.
    pub provenance_score: Option<f32>,
}

impl Candidate {
    pub fn new(path: PathBuf, language: Language) -> Self {
        Self {
            path,
            language,
            changed_lines: None,
            commit_sha: None,
            provenance_score: None,
        }
    }
}

/// Context shared across verifiers for a single run.
pub struct VerifyContext<'a> {
    pub workspace_root: &'a Path,
    /// Optional AI-authorship score for the current candidate (0.0–1.0).
    pub provenance: Option<f32>,
}

#[async_trait]
pub trait Verifier: Send + Sync {
    /// Stable identifier, e.g., `"secrets"`, `"cve"`.
    fn id(&self) -> &'static str;

    /// Human-readable description for help/docs.
    fn description(&self) -> &'static str;

    /// Languages this verifier supports.
    fn supported_languages(&self) -> &[Language];

    /// Concurrency hint.
    fn concurrency(&self) -> Concurrency {
        Concurrency::Parallel
    }

    /// Run verifier on a candidate; return findings.
    async fn verify(&self, candidate: &Candidate, ctx: &VerifyContext<'_>) -> Result<Vec<Finding>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_rank_is_monotonic() {
        assert!(Severity::Info.rank() < Severity::Low.rank());
        assert!(Severity::Low.rank() < Severity::Medium.rank());
        assert!(Severity::Medium.rank() < Severity::High.rank());
        assert!(Severity::High.rank() < Severity::Critical.rank());
    }

    #[test]
    fn severity_round_trip() {
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let s = sev.as_str();
            assert_eq!(Severity::from_str_ci(s), Some(sev));
            assert_eq!(Severity::from_str_ci(&s.to_ascii_uppercase()), Some(sev));
        }
    }

    #[test]
    fn language_from_extension() {
        assert_eq!(Language::from_extension("rs"), Language::Rust);
        assert_eq!(Language::from_extension("TSX"), Language::TypeScript);
        assert_eq!(Language::from_extension("py"), Language::Python);
        assert_eq!(Language::from_extension("xyz"), Language::Unknown);
    }

    #[test]
    fn range_set_contains() {
        let mut rs = RangeSet::new();
        rs.push(10, 20);
        rs.push(30, 35);
        assert!(rs.contains(10));
        assert!(rs.contains(19));
        assert!(!rs.contains(20));
        assert!(rs.contains(34));
        assert!(!rs.contains(25));
    }
}
