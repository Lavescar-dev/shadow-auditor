//! Unused-import ratio. Signal (0.10).
//!
//! Pragmatic: parse import lines via regex per language, then check whether
//! each imported identifier appears again in the file body. Cross-module
//! symbol resolution is out of scope for V1; this over-approximates and is
//! acceptable as a noisy-but-directional signal.

use regex::Regex;

use std::sync::LazyLock;

use shaudit_core::Language;

pub fn evaluate(source: &str, language: Language) -> f32 {
    if source.is_empty() {
        return 0.0;
    }
    let imports = imports_in(source, language);
    if imports.is_empty() {
        return 0.0;
    }
    let mut unused = 0;
    for ident in &imports {
        // Count occurrences beyond the import line itself.
        let count = source.match_indices(ident.as_str()).count();
        if count <= 1 {
            unused += 1;
        }
    }
    let ratio = unused as f32 / imports.len() as f32;
    if ratio <= 0.10 {
        0.0
    } else if ratio >= 0.40 {
        1.0
    } else {
        (ratio - 0.10) / 0.30
    }
}

static RUST_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^use\s+(?:[\w:]+::)?(\w+)(?:\s+as\s+(\w+))?\s*;").unwrap());
static TS_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+["']"#).unwrap());
static PY_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(?:from\s+\S+\s+)?import\s+(.+?)(?:\s+as\s+(\w+))?$").unwrap()
});

fn imports_in(source: &str, language: Language) -> Vec<String> {
    match language {
        Language::Rust => RUST_IMPORT
            .captures_iter(source)
            .filter_map(|c| {
                c.get(2)
                    .map(|m| m.as_str().to_string())
                    .or_else(|| c.get(1).map(|m| m.as_str().to_string()))
            })
            .collect(),
        Language::TypeScript | Language::JavaScript => {
            let mut out = Vec::new();
            for c in TS_IMPORT.captures_iter(source) {
                if let Some(group) = c.get(1) {
                    for ident in group.as_str().split(',') {
                        let name = ident
                            .trim()
                            .split(" as ")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !name.is_empty() {
                            out.push(name);
                        }
                    }
                } else if let Some(single) = c.get(2) {
                    out.push(single.as_str().to_string());
                }
            }
            out
        }
        Language::Python => PY_IMPORT
            .captures_iter(source)
            .flat_map(|c| {
                let raw = c.get(1).map(|m| m.as_str()).unwrap_or("");
                raw.split(',')
                    .map(|s| {
                        s.trim()
                            .split(" as ")
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string()
                    })
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_imports_no_signal() {
        assert_eq!(evaluate("fn main() {}", Language::Rust), 0.0);
    }

    #[test]
    fn all_used_no_signal() {
        let src = "use std::collections::HashMap;\nfn main() { let _: HashMap<i32, i32> = HashMap::new(); }";
        let v = evaluate(src, Language::Rust);
        assert_eq!(v, 0.0);
    }

    #[test]
    fn many_unused_full_signal() {
        let src = "\
use std::collections::HashMap;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
fn main() {
    let _: HashMap<i32, i32> = HashMap::new();
}
";
        let v = evaluate(src, Language::Rust);
        assert!(v > 0.5, "expected unused signal, got {v}");
    }
}
