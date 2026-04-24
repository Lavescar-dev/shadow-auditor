//! Tree-sitter AST context classifier for regex matches.
//!
//! A regex hit inside a string literal in code is a real secret; the same
//! text inside a comment or a markdown fenced block is almost always an
//! example. This module returns that classification so the verifier can
//! filter out false positives.

use tree_sitter::{Node, Tree};

use shaudit_core::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchContext {
    /// Inside code as a string/bytes literal — most likely a real secret.
    StringLiteral,
    /// Inside a comment — treat as example / documentation.
    Comment,
    /// Plain code outside strings (e.g., identifier match) — suspicious.
    Code,
    /// Could not be classified (tree-sitter failed or text-only heuristic).
    Unknown,
}

pub fn classify(tree: &Tree, byte_offset: usize, language: Language) -> MatchContext {
    let node = match tree
        .root_node()
        .descendant_for_byte_range(byte_offset, byte_offset)
    {
        Some(n) => n,
        None => return MatchContext::Unknown,
    };

    if is_in_ancestor(node, |k| is_string_node(k, language)) {
        return MatchContext::StringLiteral;
    }
    if is_in_ancestor(node, |k| is_comment_node(k, language)) {
        return MatchContext::Comment;
    }
    MatchContext::Code
}

fn is_in_ancestor(mut node: Node, pred: impl Fn(&str) -> bool) -> bool {
    loop {
        if pred(node.kind()) {
            return true;
        }
        match node.parent() {
            Some(p) => node = p,
            None => return false,
        }
    }
}

fn is_string_node(kind: &str, language: Language) -> bool {
    match language {
        Language::Rust => matches!(
            kind,
            "string_literal"
                | "raw_string_literal"
                | "byte_string_literal"
                | "string_content"
                | "char_literal"
        ),
        Language::TypeScript | Language::JavaScript => matches!(
            kind,
            "string"
                | "string_fragment"
                | "template_string"
                | "template_literal"
                | "template_substitution"
        ),
        Language::Python => matches!(
            kind,
            "string" | "string_content" | "concatenated_string" | "raw_string"
        ),
        _ => matches!(kind, "string" | "string_literal"),
    }
}

fn is_comment_node(kind: &str, language: Language) -> bool {
    match language {
        Language::Rust => matches!(
            kind,
            "line_comment" | "block_comment" | "doc_comment" | "comment"
        ),
        Language::TypeScript | Language::JavaScript => matches!(kind, "comment"),
        Language::Python => matches!(kind, "comment"),
        _ => matches!(kind, "comment"),
    }
}
