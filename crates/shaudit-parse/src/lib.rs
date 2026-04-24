//! Shadow Auditor — tree-sitter parsing layer with a per-run AST cache.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use shaudit_core::Language;
use tree_sitter::{Parser, Tree};

mod cache;

pub use cache::AstCache;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("i/o error reading `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported language for `{0}`")]
    UnsupportedLanguage(PathBuf),

    #[error("failed to set tree-sitter language: {0}")]
    LanguageInit(String),

    #[error("parser returned no tree for `{0}`")]
    NoTree(PathBuf),
}

pub type Result<T> = std::result::Result<T, ParseError>;

/// Parsed source: text + tree. Kept together so verifiers can snip ranges.
pub struct ParsedFile {
    pub path: PathBuf,
    pub language: Language,
    pub source: String,
    pub tree: Tree,
}

/// Parse a single file into a `ParsedFile` with an owned tree.
pub fn parse_file(path: &Path, language: Language) -> Result<ParsedFile> {
    let source = std::fs::read_to_string(path).map_err(|source| ParseError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let ts_lang = tree_sitter_language_for(language)
        .ok_or_else(|| ParseError::UnsupportedLanguage(path.to_path_buf()))?;

    let mut parser = Parser::new();
    parser
        .set_language(&ts_lang)
        .map_err(|e| ParseError::LanguageInit(e.to_string()))?;

    let tree = parser
        .parse(source.as_bytes(), None)
        .ok_or_else(|| ParseError::NoTree(path.to_path_buf()))?;

    Ok(ParsedFile {
        path: path.to_path_buf(),
        language,
        source,
        tree,
    })
}

fn tree_sitter_language_for(lang: Language) -> Option<tree_sitter::Language> {
    match lang {
        Language::Rust => Some(tree_sitter_rust::LANGUAGE.into()),
        Language::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Language::JavaScript => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        Language::Python => Some(tree_sitter_python::LANGUAGE.into()),
        Language::Go | Language::Unknown => None,
    }
}

/// Shared store used by a single scan run to avoid re-parsing files that
/// multiple verifiers will touch.
#[derive(Default)]
pub struct SharedAstCache {
    inner: RwLock<HashMap<PathBuf, std::sync::Arc<ParsedFile>>>,
}

impl SharedAstCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_or_parse(
        &self,
        path: &Path,
        language: Language,
    ) -> Result<std::sync::Arc<ParsedFile>> {
        if let Some(hit) = self.inner.read().unwrap().get(path).cloned() {
            return Ok(hit);
        }
        let parsed = parse_file(path, language)?;
        let arc = std::sync::Arc::new(parsed);
        self.inner
            .write()
            .unwrap()
            .insert(path.to_path_buf(), arc.clone());
        Ok(arc)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rust_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.rs");
        std::fs::write(&path, "fn hello() -> i32 { 42 }").unwrap();
        let parsed = parse_file(&path, Language::Rust).unwrap();
        assert_eq!(parsed.language, Language::Rust);
        assert!(parsed.tree.root_node().kind() == "source_file");
    }

    #[test]
    fn parses_typescript_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.ts");
        std::fs::write(&path, "export const x: number = 42;").unwrap();
        let parsed = parse_file(&path, Language::TypeScript).unwrap();
        assert_eq!(parsed.language, Language::TypeScript);
    }

    #[test]
    fn parses_python_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.py");
        std::fs::write(&path, "def hello() -> int:\n    return 42\n").unwrap();
        let parsed = parse_file(&path, Language::Python).unwrap();
        assert_eq!(parsed.language, Language::Python);
    }

    #[test]
    fn cache_memoizes_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.rs");
        std::fs::write(&path, "fn a() {}").unwrap();
        let cache = SharedAstCache::new();
        let a = cache.get_or_parse(&path, Language::Rust).unwrap();
        let b = cache.get_or_parse(&path, Language::Rust).unwrap();
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn unsupported_language_errors_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.bin");
        std::fs::write(&path, "\0\0").unwrap();
        match parse_file(&path, Language::Unknown) {
            Err(ParseError::UnsupportedLanguage(_)) => {}
            Err(other) => panic!("expected UnsupportedLanguage, got {other:?}"),
            Ok(_) => panic!("expected UnsupportedLanguage error, got Ok"),
        }
    }
}
