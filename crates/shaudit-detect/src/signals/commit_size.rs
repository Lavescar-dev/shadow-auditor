//! Large single-commit additions. Signal (0.10).
//!
//! > 500 LOC added in one commit is a known AI-output fingerprint.

pub fn evaluate(additions: u32) -> f32 {
    // Smooth threshold: linear ramp between 200 and 500 additions.
    match additions {
        0..=199 => 0.0,
        200..=499 => (additions - 200) as f32 / 300.0,
        _ => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_commit_no_signal() {
        assert_eq!(evaluate(50), 0.0);
    }

    #[test]
    fn large_commit_full_signal() {
        assert_eq!(evaluate(1000), 1.0);
    }

    #[test]
    fn medium_commit_ramps() {
        let v = evaluate(350);
        assert!((0.3..0.7).contains(&v), "expected mid-ramp, got {v}");
    }
}
