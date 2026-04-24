//! Inline allowlist marker detection.
//!
//! Users can mark intentional "secrets" (fixtures, demo code, paper
//! examples) so the scanner skips them. Supported forms on the same line
//! as the finding:
//!
//! - `// shaudit:allow secrets`                     — any rule
//! - `// shaudit:allow secrets.aws-access-token`    — specific rule id
//! - `# shaudit:allow secrets`                      — Python/shell form
//! - `/* shaudit:allow secrets */`                  — block-comment form
//!
//! The scanner computes the line number from the match byte offset and
//! checks if the same line contains a marker that allows this rule.

use std::ops::Range;

use regex::Regex;

#[derive(Debug, Clone)]
pub struct AllowMarker {
    /// Byte range of the line containing the marker (not just the marker).
    pub line_bytes: Range<usize>,
    /// Specific rule ids allowed on this line, or empty for "any".
    pub rule_ids: Vec<String>,
}

/// Scan source for allowlist markers.
pub fn scan(source: &str) -> Vec<AllowMarker> {
    // Compile once per call; small overhead acceptable per-file.
    // shaudit:allow secrets
    let marker_re = Regex::new(
        r"shaudit:allow\s+(secrets(?:\.[a-zA-Z0-9_.-]+)?(?:\s*,\s*secrets(?:\.[a-zA-Z0-9_.-]+)?)*)", // shaudit:allow secrets
    )
    .expect("compile allow marker regex");

    let mut out = Vec::new();
    let mut byte_cursor = 0usize;
    for line in source.split_inclusive('\n') {
        if let Some(caps) = marker_re.captures(line) {
            let ids_group = caps
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();

            let rule_ids: Vec<String> = ids_group
                .into_iter()
                .map(|raw| {
                    // "secrets" → "" (wildcard); "secrets.xyz" → "xyz"
                    raw.strip_prefix("secrets.").unwrap_or("").to_string()
                })
                .collect();

            out.push(AllowMarker {
                line_bytes: byte_cursor..byte_cursor + line.len(),
                rule_ids,
            });
        }
        byte_cursor += line.len();
    }
    out
}

/// Check if `byte_offset` falls on a line where `rule_id` is allowlisted.
pub fn is_allowed(markers: &[AllowMarker], byte_offset: usize, rule_id: &str) -> bool {
    for m in markers {
        if byte_offset >= m.line_bytes.start && byte_offset < m.line_bytes.end {
            if m.rule_ids.is_empty() {
                return true; // wildcard `secrets`
            }
            // Accept exact id or a prefix match (e.g., "aws" matches "aws-access-token").
            if m.rule_ids
                .iter()
                .any(|r| rule_id == r || rule_id.contains(r))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wildcard_marker() {
        let src = "let k = \"AKIA...\";  // shaudit:allow secrets\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert!(is_allowed(&markers, 10, "aws-access-token"));
    }

    #[test]
    fn detects_specific_rule_marker() {
        let src = "let k = \"AKIA...\";  // shaudit:allow secrets.aws-access-token\n";
        let markers = scan(src);
        let offset = 10;
        assert!(is_allowed(&markers, offset, "aws-access-token"));
        assert!(!is_allowed(&markers, offset, "github-pat"));
    }

    #[test]
    fn no_marker_no_allow() {
        let src = "let k = \"AKIA...\";\n";
        let markers = scan(src);
        assert!(markers.is_empty());
        assert!(!is_allowed(&markers, 10, "aws"));
    }

    #[test]
    fn python_hash_form() {
        let src = "key = 'ghp_...'  # shaudit:allow secrets\n";
        let markers = scan(src);
        assert_eq!(markers.len(), 1);
        assert!(is_allowed(&markers, 8, "github-pat"));
    }
}
