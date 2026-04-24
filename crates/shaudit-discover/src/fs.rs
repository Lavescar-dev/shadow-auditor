//! Filesystem walker using the `ignore` crate (same as ripgrep).

use ignore::WalkBuilder;
use shaudit_core::{Candidate, Language};

use crate::{looks_binary, make_candidate, DiscoverError, DiscoverOpts, Result};

pub fn discover_fs(opts: &DiscoverOpts) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();

    for root in &opts.roots {
        if !root.exists() {
            return Err(DiscoverError::RootMissing(root.clone()));
        }

        let mut builder = WalkBuilder::new(root);
        builder
            .git_ignore(opts.respect_gitignore)
            .git_exclude(opts.respect_gitignore)
            .git_global(opts.respect_gitignore)
            .hidden(false)
            // .shauditignore is honored the same way .gitignore is.
            .add_custom_ignore_filename(".shauditignore")
            .follow_links(false);

        for result in builder.build() {
            let entry = match result {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!(error = %err, "walk error");
                    continue;
                }
            };
            if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                continue;
            }
            let path = entry.into_path();
            if !matches_language_filter(&path, opts) {
                continue;
            }
            if is_excluded(&path, opts) {
                continue;
            }
            if looks_binary(&path) {
                continue;
            }
            candidates.push(make_candidate(path, None, None));
        }
    }

    Ok(candidates)
}

fn matches_language_filter(path: &std::path::Path, opts: &DiscoverOpts) -> bool {
    let Some(filter) = &opts.languages else {
        return language_is_known(path);
    };
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let lang = Language::from_extension(ext);
    filter.contains(&lang)
}

fn language_is_known(path: &std::path::Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    !matches!(Language::from_extension(ext), Language::Unknown)
}

fn is_excluded(path: &std::path::Path, opts: &DiscoverOpts) -> bool {
    let path_str = path.to_string_lossy();
    opts.exclude.iter().any(|pattern| {
        if let Ok(compiled) = glob::Pattern::new(pattern) {
            compiled.matches(&path_str)
        } else {
            path_str.contains(pattern)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("lib.py"), "print('hi')").unwrap();
        fs::write(root.join("app.ts"), "export const x = 1;").unwrap();
        fs::write(root.join("notes.md"), "# hi").unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/util.rs"), "pub fn ok() {}").unwrap();
        dir
    }

    #[test]
    fn walks_files_with_known_extensions() {
        let dir = fixture();
        let opts = DiscoverOpts {
            roots: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let cands = discover_fs(&opts).unwrap();
        let paths: Vec<_> = cands
            .iter()
            .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(paths.contains(&"main.rs".to_string()));
        assert!(paths.contains(&"lib.py".to_string()));
        assert!(paths.contains(&"app.ts".to_string()));
        assert!(paths.contains(&"util.rs".to_string()));
        // notes.md has unknown language — skipped by default
        assert!(!paths.contains(&"notes.md".to_string()));
    }

    #[test]
    fn language_filter_restricts_results() {
        let dir = fixture();
        let opts = DiscoverOpts {
            roots: vec![dir.path().to_path_buf()],
            languages: Some(vec![Language::Rust]),
            ..Default::default()
        };
        let cands = discover_fs(&opts).unwrap();
        for c in &cands {
            assert_eq!(c.language, Language::Rust);
        }
        assert_eq!(cands.len(), 2); // main.rs + sub/util.rs
    }

    #[test]
    fn missing_root_fails_cleanly() {
        let opts = DiscoverOpts {
            roots: vec![PathBuf::from("/nonexistent-shaudit-root-xyz")],
            ..Default::default()
        };
        let err = discover_fs(&opts).unwrap_err();
        matches!(err, DiscoverError::RootMissing(_));
    }

    #[test]
    fn shauditignore_excludes_files() {
        let dir = fixture();
        fs::write(dir.path().join(".shauditignore"), "*.py\n").unwrap();
        let opts = DiscoverOpts {
            roots: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let cands = discover_fs(&opts).unwrap();
        assert!(!cands
            .iter()
            .any(|c| c.path.extension().and_then(|e| e.to_str()) == Some("py")));
    }

    #[test]
    fn binary_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("blob.rs");
        // Write a buffer with a NUL byte in the first 8 KB.
        let mut buf = vec![b'a'; 100];
        buf[50] = 0;
        fs::write(&bin_path, &buf).unwrap();
        let opts = DiscoverOpts {
            roots: vec![dir.path().to_path_buf()],
            ..Default::default()
        };
        let cands = discover_fs(&opts).unwrap();
        assert!(cands.is_empty(), "expected binary file to be skipped");
    }
}
