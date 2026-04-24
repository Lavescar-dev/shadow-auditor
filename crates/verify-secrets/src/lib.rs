//! Shadow Auditor — secrets verifier.
//!
//! Wraps the vendored gitleaks rule set with tree-sitter AST context
//! filtering and Shannon-entropy fallback for high-entropy strings that
//! match no rule.

use async_trait::async_trait;
use tree_sitter::{Parser, Tree};

use shaudit_core::{
    Candidate, Concurrency, Finding, Language, Location, Severity, Verifier, VerifyContext,
};

mod allowlist;
mod context;
mod entropy;
mod rules;

use allowlist::AllowMarker;
pub use rules::{RuleSet, SecretRule};

pub const ID: &str = "secrets";

/// Minimum string length below which entropy-only detection is ignored.
const ENTROPY_MIN_LEN: usize = 20;
/// Minimum Shannon entropy (bits) for entropy-only detection.
const ENTROPY_THRESHOLD: f32 = 4.5;

pub struct SecretsVerifier {
    rules: RuleSet,
    supported: [Language; 4],
}

impl SecretsVerifier {
    pub fn with_builtin_rules() -> Self {
        Self {
            rules: rules::load_builtin(),
            supported: [
                Language::Rust,
                Language::TypeScript,
                Language::JavaScript,
                Language::Python,
            ],
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.rules.len()
    }

    pub fn rules_iter(&self) -> impl Iterator<Item = &SecretRule> {
        self.rules.rules.iter()
    }
}

#[async_trait]
impl Verifier for SecretsVerifier {
    fn id(&self) -> &'static str {
        ID
    }

    fn description(&self) -> &'static str {
        "Detects hardcoded secrets (API keys, tokens, private keys) via regex + AST context + Shannon entropy"
    }

    fn supported_languages(&self) -> &[Language] {
        &self.supported
    }

    fn concurrency(&self) -> Concurrency {
        Concurrency::Parallel
    }

    async fn verify(
        &self,
        candidate: &Candidate,
        _ctx: &VerifyContext<'_>,
    ) -> shaudit_core::Result<Vec<Finding>> {
        // Synchronous scan on the tokio runtime thread; fine for CPU-bound
        // work under the assumption most scans are parallelized across
        // candidates, not within a single file.
        let rule_refs: Vec<&SecretRule> = self.rules.rules.iter().collect();
        scan_file(&candidate.path, candidate.language, &rule_refs)
    }
}

fn scan_file(
    path: &std::path::Path,
    language: Language,
    rules: &[&SecretRule],
) -> shaudit_core::Result<Vec<Finding>> {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            tracing::debug!(path = %path.display(), "skipping non-utf8 file");
            return Ok(Vec::new());
        }
        Err(e) => return Err(shaudit_core::Error::Io(e)),
    };

    let tree = parse_for_context(&source, language);
    let allow_markers = allowlist::scan(&source);

    let mut findings = Vec::new();
    let mut seen_keys: std::collections::HashSet<(String, u32, u32)> = Default::default();

    for rule in rules {
        for m in rule.regex.find_iter(&source) {
            let match_start = m.start();
            let match_str = m.as_str();

            if allowlist::is_allowed(&allow_markers, match_start, &rule.id) {
                continue;
            }

            if let Some(thresh) = rule.entropy {
                let e = entropy::shannon(match_str.as_bytes());
                if e < thresh {
                    continue;
                }
            }

            if let Some(tree) = &tree {
                let ctx = context::classify(tree, match_start, language);
                if matches!(ctx, context::MatchContext::Comment) {
                    continue;
                }
            }

            let (line, col) = offset_to_line_col(&source, match_start);
            let (end_line, end_col) = offset_to_line_col(&source, m.end());

            let key = (rule.id.clone(), line, col);
            if !seen_keys.insert(key) {
                continue;
            }

            findings.push(Finding {
                verifier_id: ID.to_string(),
                rule_id: format!("secrets.{}", rule.id),
                severity: rule.severity(),
                message: format!("{} ({})", rule.description, truncate_preview(match_str)),
                location: Location {
                    path: path.to_path_buf(),
                    start_line: line,
                    start_col: col,
                    end_line,
                    end_col,
                    snippet: Some(truncate_preview(match_str)),
                },
                fix: None,
                provenance_score: None,
                metadata: serde_json::Value::Null,
            });
        }
    }

    if let Some(tree) = &tree {
        findings.extend(entropy_pass(
            &source,
            tree,
            language,
            &allow_markers,
            path,
            &mut seen_keys,
        ));
    }

    Ok(findings)
}

fn parse_for_context(source: &str, language: Language) -> Option<Tree> {
    let ts_lang = match language {
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::JavaScript => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        _ => return None,
    };
    let mut parser = Parser::new();
    parser.set_language(&ts_lang).ok()?;
    parser.parse(source.as_bytes(), None)
}

fn entropy_pass(
    source: &str,
    tree: &Tree,
    language: Language,
    allow_markers: &[AllowMarker],
    path: &std::path::Path,
    seen_keys: &mut std::collections::HashSet<(String, u32, u32)>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut visit = |node: tree_sitter::Node<'_>| {
        let byte_range = node.byte_range();
        let text = &source[byte_range.clone()];
        let cleaned = text.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
        if cleaned.len() < ENTROPY_MIN_LEN {
            return;
        }
        // Skip prose-like strings: high whitespace ratio usually means
        // multi-line templates, markdown, docstring text.
        let whitespace = cleaned.bytes().filter(|b| b.is_ascii_whitespace()).count();
        if (whitespace as f32) / (cleaned.len() as f32) > 0.08 {
            return;
        }
        // Skip strings containing common English separators (quoted prose).
        if cleaned.contains(". ") || cleaned.contains(", ") || cleaned.contains("; ") {
            return;
        }
        let e = entropy::shannon(cleaned.as_bytes());
        if e < ENTROPY_THRESHOLD {
            return;
        }
        if allowlist::is_allowed(allow_markers, byte_range.start, "generic-high-entropy") {
            return;
        }
        let (line, col) = offset_to_line_col(source, byte_range.start);
        let (end_line, end_col) = offset_to_line_col(source, byte_range.end);
        let key = ("generic-high-entropy".to_string(), line, col);
        if !seen_keys.insert(key) {
            return;
        }
        findings.push(Finding {
            verifier_id: ID.to_string(),
            rule_id: "secrets.generic-high-entropy".to_string(),
            severity: Severity::Medium,
            message: format!(
                "High-entropy string literal ({:.1} bits); may be a hardcoded credential",
                e
            ),
            location: Location {
                path: path.to_path_buf(),
                start_line: line,
                start_col: col,
                end_line,
                end_col,
                snippet: Some(truncate_preview(cleaned)),
            },
            fix: None,
            provenance_score: None,
            metadata: serde_json::json!({ "entropy": e }),
        });
    };
    visit_string_literals(tree.root_node(), language, &mut visit);
    findings
}

fn visit_string_literals<'a, F: FnMut(tree_sitter::Node<'a>)>(
    node: tree_sitter::Node<'a>,
    language: Language,
    visit: &mut F,
) {
    if is_string_node_kind(node.kind(), language) {
        visit(node);
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            visit_string_literals(child, language, visit);
        }
    }
}

fn is_string_node_kind(kind: &str, language: Language) -> bool {
    match language {
        Language::Rust => matches!(
            kind,
            "string_literal" | "raw_string_literal" | "byte_string_literal"
        ),
        Language::TypeScript | Language::JavaScript => {
            matches!(kind, "string" | "template_string")
        }
        Language::Python => matches!(kind, "string"),
        _ => false,
    }
}

fn offset_to_line_col(source: &str, offset: usize) -> (u32, u32) {
    let mut line = 1u32;
    let mut col = 1u32;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

fn truncate_preview(s: &str) -> String {
    const MAX: usize = 50;
    if s.len() <= MAX {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(MAX).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn run_on(path: std::path::PathBuf, language: Language) -> Vec<Finding> {
        let verifier = SecretsVerifier::with_builtin_rules();
        let rules_refs: Vec<&SecretRule> = verifier.rules.rules.iter().collect();
        scan_file(&path, language, &rules_refs).expect("scan")
    }

    #[test]
    fn builtin_rules_compile() {
        let v = SecretsVerifier::with_builtin_rules();
        assert!(v.rule_count() > 100);
    }

    #[test]
    fn detects_aws_access_key_in_rust() {
        // shaudit:allow secrets
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("rs");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "fn main() {{ let k = \"AKIAIOSFODNN7EXAMPLE\"; }}").unwrap(); // shaudit:allow secrets
        let findings = run_on(path, Language::Rust);
        assert!(
            findings.iter().any(|f| f.rule_id.contains("aws")),
            "expected AWS finding, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn allowlist_suppresses_finding() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("rs");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "fn main() {{ let k = \"AKIAIOSFODNN7EXAMPLE\"; }} // shaudit:allow secrets"
        ) // shaudit:allow secrets
        .unwrap();
        let findings = run_on(path, Language::Rust);
        assert!(
            findings.is_empty(),
            "allowlist should suppress, got {:?}",
            findings
        );
    }

    #[test]
    fn high_entropy_literal_detected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("rs");
        let mut f = std::fs::File::create(&path).unwrap();
        // 40-char mixed base64-like string, not matching any vendor rule
        writeln!(
            f,
            "fn main() {{ let k = \"Xk2Yz9qP4mT7nR8sL1cW3vF5jB6gH0aD\"; }}"
        ) // shaudit:allow secrets
        .unwrap();
        let findings = run_on(path, Language::Rust);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "secrets.generic-high-entropy"),
            "expected generic-high-entropy finding, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn match_in_comment_filtered() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("rs");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "// Example: AKIAIOSFODNN7EXAMPLE").unwrap(); // shaudit:allow secrets
        writeln!(f, "fn main() {{}}").unwrap();
        let findings = run_on(path, Language::Rust);
        assert!(
            findings.iter().all(|f| !f.rule_id.contains("aws")),
            "comment context should filter AWS match"
        );
    }
}
