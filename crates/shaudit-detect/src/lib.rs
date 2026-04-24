//! Shadow Auditor — AI provenance detection (plan §3.2).
//!
//! Week 1-2 scope: stub that returns `None` for every candidate. Signals and
//! scoring (commit-message regex, time-of-day histogram, docstring density,
//! defensive null density, etc.) land in Hafta 4.

use shaudit_core::Candidate;

/// Return an AI-authorship score in `[0.0, 1.0]`, or `None` if detection is
/// disabled or signals are insufficient.
pub fn detect_provenance(_candidate: &Candidate) -> Option<f32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use shaudit_core::{Candidate, Language};
    use std::path::PathBuf;

    #[test]
    fn stub_returns_none() {
        let c = Candidate::new(PathBuf::from("dummy.rs"), Language::Rust);
        assert_eq!(detect_provenance(&c), None);
    }
}
