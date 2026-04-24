//! Go lockfile parser: `go.sum`.

use std::path::{Path, PathBuf};

use super::Package;

pub fn collect(workspace_root: &Path) -> Option<(PathBuf, Vec<Package>)> {
    let path = workspace_root.join("go.sum");
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    let pkgs = parse_go_sum(&content);
    if pkgs.is_empty() {
        return None;
    }
    Some((path, pkgs))
}

fn parse_go_sum(content: &str) -> Vec<Package> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        // Format: "<module> <version>[/go.mod] h1:<hash>="
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let module = parts[0];
        // Strip "/go.mod" suffix if present
        let version = parts[1].trim_end_matches("/go.mod");
        let key = format!("{module}@{version}");
        if seen.insert(key) {
            out.push(Package {
                name: module.to_string(),
                version: version.to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_sum() {
        let content = "\
github.com/foo/bar v1.2.3 h1:abc=
github.com/foo/bar v1.2.3/go.mod h1:def=
golang.org/x/net v0.15.0 h1:xyz=
";
        let pkgs = parse_go_sum(content);
        // Duplicate bar line collapses to one entry.
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "github.com/foo/bar" && p.version == "v1.2.3"));
    }
}
