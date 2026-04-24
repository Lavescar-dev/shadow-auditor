//! Shadow Auditor — AI provenance detection (plan §3.2).
//!
//! Eight signals, weighted sum in `[0.0, 1.0]`. See `signals/*.rs` for the
//! individual implementations. `score` is the public entry point used by
//! the CLI after discovery.

use std::path::Path;

use shaudit_core::Candidate;

pub mod git;
pub mod scorer;
pub mod signals;

pub use scorer::ProvenanceReport;

pub use git::GitContext;

/// Compute the provenance score for a candidate. The workspace root is
/// passed so the git-based signals can shell out to `git log`.
///
/// Returns `None` if the candidate's language is unsupported or the source
/// cannot be read.
pub fn score_candidate(candidate: &Candidate, workspace_root: &Path) -> Option<ProvenanceReport> {
    let source = std::fs::read_to_string(&candidate.path).ok()?;
    let git_ctx = git::context_for_file(workspace_root, &candidate.path);
    Some(scorer::score(&source, candidate.language, &git_ctx))
}

/// Look for inline override markers on any line of the file.
///
/// `// shaudit:ai` → force 1.0; `// shaudit:human` → force 0.0.
pub fn inline_override(source: &str) -> Option<f32> {
    if source.contains("shaudit:ai") {
        Some(1.0)
    } else if source.contains("shaudit:human") {
        Some(0.0)
    } else {
        None
    }
}

/// Compatibility shim for callers that only need the score. Falls back to
/// a None result when detection is disabled or the file can't be read.
pub fn detect_provenance(candidate: &Candidate) -> Option<f32> {
    // Previous scaffold signature — kept so existing wiring compiles. CLI
    // should prefer `score_candidate` for full signal inspection.
    score_candidate(candidate, std::path::Path::new(".")).map(|r| r.score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shaudit_core::Language;

    #[test]
    fn empty_file_yields_empty_report() {
        let c = Candidate::new(std::path::PathBuf::from("nonexistent.rs"), Language::Rust);
        assert!(score_candidate(&c, std::path::Path::new(".")).is_none());
    }

    #[test]
    fn override_ai_marker() {
        assert_eq!(inline_override("// shaudit:ai\nfn main() {}"), Some(1.0));
    }

    #[test]
    fn override_human_marker() {
        assert_eq!(inline_override("fn main() {} // shaudit:human"), Some(0.0));
    }

    #[test]
    fn no_override_none() {
        assert_eq!(inline_override("fn main() {}"), None);
    }
}
