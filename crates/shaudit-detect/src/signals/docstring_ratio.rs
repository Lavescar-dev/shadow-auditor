//! Verbose docstring density. Signal (0.10).
//!
//! Pragmatic: counts bytes inside "doc comments" (Rust `///`, Python `"""..."""`,
//! JSDoc-style `/** */`) versus total bytes of the file. AI tends to over-document;
//! a ratio above 25% is the trigger.

use shaudit_core::Language;

pub fn evaluate(source: &str, language: Language) -> f32 {
    if source.is_empty() {
        return 0.0;
    }
    let doc_bytes = match language {
        Language::Rust => rust_doc_bytes(source),
        Language::TypeScript | Language::JavaScript => js_doc_bytes(source),
        Language::Python => python_doc_bytes(source),
        _ => 0,
    };
    let ratio = doc_bytes as f32 / source.len() as f32;
    // Ramp 0.10 → 0.30 linearly.
    if ratio <= 0.10 {
        0.0
    } else if ratio >= 0.30 {
        1.0
    } else {
        (ratio - 0.10) / 0.20
    }
}

fn rust_doc_bytes(source: &str) -> usize {
    let mut total = 0;
    for line in source.lines() {
        let t = line.trim_start();
        if t.starts_with("///") || t.starts_with("//!") {
            total += line.len();
        }
    }
    total
}

fn js_doc_bytes(source: &str) -> usize {
    // Very rough: count bytes between /** and */
    let mut total = 0;
    let bytes = source.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if &bytes[i..i + 3] == b"/**" {
            let start = i;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            total += i - start;
        } else {
            i += 1;
        }
    }
    total
}

fn python_doc_bytes(source: &str) -> usize {
    // Rough: count bytes between triple-quote markers.
    let mut total = 0;
    for marker in [r#"""""#, "'''"] {
        let mut i = 0;
        while let Some(start) = source[i..].find(marker) {
            let abs_start = i + start;
            let after = abs_start + marker.len();
            if let Some(rel_end) = source[after..].find(marker) {
                let end = after + rel_end + marker.len();
                total += end - abs_start;
                i = end;
            } else {
                break;
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_docs_no_signal() {
        let src = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        assert_eq!(evaluate(src, Language::Rust), 0.0);
    }

    #[test]
    fn heavy_rust_docs_full_signal() {
        let src = r#"/// A comprehensive, production-ready adder function.
/// # Arguments
/// * `a` - the first integer
/// * `b` - the second integer
/// # Returns
/// The sum of `a` and `b`.
/// # Safety
/// This function is safe for all valid i32 inputs.
/// # Examples
/// ```
/// let s = add(2, 3);
/// assert_eq!(s, 5);
/// ```
fn add(a: i32, b: i32) -> i32 { a + b }
"#;
        let v = evaluate(src, Language::Rust);
        assert!(v > 0.8, "expected high docstring ratio, got {v}");
    }
}
