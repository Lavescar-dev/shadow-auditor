//! Git diff-mode discovery (plan §3.1 Week 2 work).
//!
//! TODO(hafta-3+): gix 0.82's tree-diff API is verbose and churns across
//! versions; we shell out to the `git` binary for now. The static-link
//! benefit of pure-Rust `gix` only matters for end-user distribution
//! (Week 7+), so this is acceptable for the MVP and integration tests.
//! Swap this module to `gix::Repository::diff_tree_to_tree` when the API
//! stabilizes or when we need the feature on systems without `git` on PATH.

use std::path::PathBuf;
use std::process::Command;

use shaudit_core::Candidate;

use crate::{looks_binary, make_candidate, DiscoverError, DiscoverOpts, Result};

pub fn discover_diff(opts: &DiscoverOpts, diff_ref: &str) -> Result<Vec<Candidate>> {
    let root = opts
        .roots
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));

    let work_dir = git_toplevel(&root)?;

    let changed_files = if opts.staged {
        collect_staged(&work_dir)?
    } else {
        collect_diff(&work_dir, diff_ref)?
    };

    let mut candidates = Vec::with_capacity(changed_files.len());
    for rel_path in changed_files {
        let abs = work_dir.join(&rel_path);
        if !abs.exists() {
            continue; // deleted — skip
        }
        if !abs.is_file() {
            continue;
        }
        if looks_binary(&abs) {
            continue;
        }
        candidates.push(make_candidate(abs, None, None));
    }
    Ok(candidates)
}

fn git_toplevel(path: &std::path::Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .map_err(|e| DiscoverError::Git(format!("git invocation failed: {e}")))?;
    if !out.status.success() {
        return Err(DiscoverError::Git(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(PathBuf::from(top))
}

fn collect_diff(work_dir: &std::path::Path, diff_ref: &str) -> Result<Vec<PathBuf>> {
    // --diff-filter=ACMR → Added, Copied, Modified, Renamed (skip Deleted).
    let out = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "--no-renames",
            diff_ref,
        ])
        .current_dir(work_dir)
        .output()
        .map_err(|e| DiscoverError::Git(format!("git diff failed: {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        tracing::warn!(diff_ref, %stderr, "git diff rejected ref — falling back to tracked files");
        return list_tracked(work_dir);
    }

    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect())
}

fn collect_staged(work_dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "--cached",
            "--diff-filter=ACMR",
            "--no-renames",
        ])
        .current_dir(work_dir)
        .output()
        .map_err(|e| DiscoverError::Git(format!("git diff --cached failed: {e}")))?;
    if !out.status.success() {
        return list_tracked(work_dir);
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect())
}

fn list_tracked(work_dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(work_dir)
        .output()
        .map_err(|e| DiscoverError::Git(format!("git ls-files failed: {e}")))?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_repo_with_commit() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let sh = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .output()
                .expect("git");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        sh(&["init", "-b", "main"]);
        sh(&["config", "user.email", "test@example.com"]);
        sh(&["config", "user.name", "test"]);
        std::fs::write(dir.path().join("a.rs"), "fn a() {}").unwrap();
        std::fs::write(dir.path().join("b.rs"), "fn b() {}").unwrap();
        sh(&["add", "."]);
        sh(&["commit", "-m", "initial"]);

        // second commit: modify a.rs, add c.rs
        std::fs::write(dir.path().join("a.rs"), "fn a() { /* edited */ }").unwrap();
        std::fs::write(dir.path().join("c.rs"), "fn c() {}").unwrap();
        sh(&["add", "."]);
        sh(&["commit", "-m", "edits"]);
        dir
    }

    #[test]
    fn diff_head_minus_one_returns_changed_files() {
        let dir = init_repo_with_commit();
        let opts = DiscoverOpts {
            roots: vec![dir.path().to_path_buf()],
            diff_ref: Some("HEAD~1".into()),
            ..Default::default()
        };
        let cands = discover_diff(&opts, "HEAD~1").unwrap();
        let names: Vec<String> = cands
            .iter()
            .map(|c| c.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.rs".to_string()));
        assert!(names.contains(&"c.rs".to_string()));
        assert!(!names.contains(&"b.rs".to_string()));
    }

    #[test]
    fn invalid_ref_falls_back_to_tracked_files() {
        let dir = init_repo_with_commit();
        let opts = DiscoverOpts {
            roots: vec![dir.path().to_path_buf()],
            diff_ref: Some("nonexistent-ref-xyz".into()),
            ..Default::default()
        };
        let cands = discover_diff(&opts, "nonexistent-ref-xyz").unwrap();
        assert!(
            !cands.is_empty(),
            "fallback should return all tracked files"
        );
    }
}
