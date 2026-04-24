//! Shadow Auditor — discovery phase.
//!
//! Two modes (plan §3.1):
//!
//! - **fs walk**: scan all tracked files under `roots`, honoring `.gitignore`
//!   and `.shauditignore`.
//! - **diff**: scan only files changed since a given ref.

use std::path::{Path, PathBuf};

use shaudit_core::{Candidate, Language, RangeSet};

mod diff;
mod fs;

#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("root `{0}` does not exist")]
    RootMissing(PathBuf),

    #[error("failed to walk `{path}`: {source}")]
    Walk {
        path: PathBuf,
        #[source]
        source: ignore::Error,
    },

    #[error("git error: {0}")]
    Git(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DiscoverError>;

#[derive(Debug, Clone)]
pub struct DiscoverOpts {
    pub roots: Vec<PathBuf>,
    pub diff_ref: Option<String>,
    pub staged: bool,
    pub languages: Option<Vec<Language>>,
    pub exclude: Vec<String>,
    pub respect_gitignore: bool,
    pub include_submodules: bool,
}

impl Default for DiscoverOpts {
    fn default() -> Self {
        Self {
            roots: vec![PathBuf::from(".")],
            diff_ref: None,
            staged: false,
            languages: None,
            exclude: Vec::new(),
            respect_gitignore: true,
            include_submodules: false,
        }
    }
}

pub trait Discoverer {
    fn discover(&self, opts: &DiscoverOpts) -> Result<Vec<Candidate>>;
}

pub struct DefaultDiscoverer;

impl Discoverer for DefaultDiscoverer {
    fn discover(&self, opts: &DiscoverOpts) -> Result<Vec<Candidate>> {
        if let Some(diff_ref) = &opts.diff_ref {
            diff::discover_diff(opts, diff_ref)
        } else {
            fs::discover_fs(opts)
        }
    }
}

/// Heuristic: is this file binary? Checks the first 8 KB for a NUL byte.
pub fn looks_binary(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 8 * 1024];
    use std::io::Read;
    match f.read(&mut buf) {
        Ok(0) => false,
        Ok(n) => buf[..n].contains(&0),
        Err(_) => false,
    }
}

/// Build a Candidate from a path, detecting language from extension.
pub(crate) fn make_candidate(
    path: PathBuf,
    changed_lines: Option<RangeSet>,
    commit_sha: Option<String>,
) -> Candidate {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_owned();
    let language = Language::from_extension(&ext);
    Candidate {
        path,
        language,
        changed_lines,
        commit_sha,
        provenance_score: None,
    }
}
