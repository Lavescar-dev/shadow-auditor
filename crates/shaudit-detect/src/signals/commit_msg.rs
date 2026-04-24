//! Commit message contains AI-marker regex. Highest-weight signal (0.40).

use regex::Regex;
use std::sync::LazyLock;

static AI_MARKERS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)generated with .*claude",
        r"(?i)co-authored-by: *claude",
        r"(?i)co-authored-by: *cursor",
        r"(?i)co-authored-by: *.*copilot",
        r"(?i)cursor\.com",
        r"(?i)github[- ]?copilot",
        r"(?i)🤖 +generated",
        r"(?i)anthropic\.com",
    ]
    .iter()
    .filter_map(|pat| Regex::new(pat).ok())
    .collect()
});

pub fn evaluate(message: &str) -> f32 {
    if message.is_empty() {
        return 0.0;
    }
    if AI_MARKERS.iter().any(|re| re.is_match(message)) {
        1.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_co_authored_by_claude() {
        assert_eq!(
            evaluate("feat: add thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>"),
            1.0
        );
    }

    #[test]
    fn detects_generated_with_claude() {
        assert_eq!(evaluate("🤖 Generated with Claude Code"), 1.0);
    }

    #[test]
    fn no_marker_returns_zero() {
        assert_eq!(evaluate("fix: typo in readme"), 0.0);
    }
}
