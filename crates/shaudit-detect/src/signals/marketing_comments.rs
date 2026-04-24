//! "Comprehensive"/"robust"/"production-ready" phrase density. Signal (0.05).

use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

const PATTERNS: &[&str] = &[
    "robust",
    "comprehensive",
    "production-ready",
    "production ready",
    "scalable",
    "enterprise-grade",
    "enterprise grade",
    "best practice",
    "best practices",
    "seamless",
    "seamlessly",
    "elegant",
    "elegantly",
    "modular",
    "extensible",
    "highly performant",
];

static MATCHER: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(PATTERNS).expect("build AC automaton"));

pub fn evaluate(source: &str) -> f32 {
    if source.is_empty() {
        return 0.0;
    }
    let count = MATCHER.find_iter(&source.to_ascii_lowercase()).count() as f32;
    // 3+ hits = full signal; 0 = none; linear in between.
    (count / 3.0).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_marketing_zero() {
        assert_eq!(evaluate("fn add(a: i32, b: i32) -> i32 { a + b }"), 0.0);
    }

    #[test]
    fn heavy_marketing_full() {
        let v = evaluate("// This is a robust, comprehensive, production-ready implementation.");
        assert_eq!(v, 1.0);
    }
}
