//! Lockfile parsers: extract `{name, version, ecosystem}` triples.

pub mod go;
pub mod node;
pub mod python;

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Package {
    pub name: String,
    pub version: String,
}

pub fn detect_and_parse(workspace_root: &Path) -> EcosystemFindings {
    EcosystemFindings {
        node: node::collect(workspace_root),
        python: python::collect(workspace_root),
        go: go::collect(workspace_root),
    }
}

pub struct EcosystemFindings {
    pub node: Option<(std::path::PathBuf, Vec<Package>)>,
    pub python: Option<(std::path::PathBuf, Vec<Package>)>,
    pub go: Option<(std::path::PathBuf, Vec<Package>)>,
}
