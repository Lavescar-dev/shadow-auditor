//! Defensive-null-check density. Signal (0.10).
//!
//! Pragmatic simplification: count occurrences of common null/option checks
//! (`is_none`, `== None`, `is_null`, `is None`, `!= null`, `=== null`) divided
//! by the number of `if`/`match`/`?.` constructs.
//!
//! Avoids proper AST analysis; this regex heuristic is fast and directionally
//! correct for the V1 detection pipeline.

use regex::Regex;

use std::sync::LazyLock;

static NULL_CHECKS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\.is_none\(\)|\.is_some\(\)|== *None|== *null|=== *null|!== *null|is *None|is *not *None|\.is_null\(\)|\?\?)")
        .expect("compile null-check regex")
});

static CONTROL_FLOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:if|else|match|when)\b").expect("compile control-flow regex")
});

pub fn evaluate(source: &str) -> f32 {
    if source.is_empty() {
        return 0.0;
    }
    let nulls = NULL_CHECKS.find_iter(source).count();
    let flows = CONTROL_FLOW.find_iter(source).count().max(1);
    let ratio = nulls as f32 / flows as f32;
    // Ramp 0.10 → 0.30.
    if ratio <= 0.10 {
        0.0
    } else if ratio >= 0.30 {
        1.0
    } else {
        (ratio - 0.10) / 0.20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_nulls_no_signal() {
        let src = "fn main() { if 1 == 1 { println!(\"hi\"); } }";
        assert_eq!(evaluate(src), 0.0);
    }

    #[test]
    fn heavy_null_checks_full_signal() {
        let src = "\
if x.is_none() { return; }
if y == None { return; }
if z.is_some() { doit(); }
if a.is_none() { return; }
let _ = b?;
";
        assert!(evaluate(src) > 0.5);
    }
}
