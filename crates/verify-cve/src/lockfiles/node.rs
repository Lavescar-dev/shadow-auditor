//! Node lockfile parsers: `package-lock.json` + `pnpm-lock.yaml` + `yarn.lock`.
//!
//! Supports the common shapes. Heavily typed locks (workspace protocols,
//! alias installs) are approximated and may over-report; CVE queries are
//! resilient to extra packages.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::Package;

pub fn collect(workspace_root: &Path) -> Option<(PathBuf, Vec<Package>)> {
    for name in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"] {
        let path = workspace_root.join(name);
        if !path.exists() {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(path = %path.display(), %e, "read failed");
                continue;
            }
        };
        let pkgs = match name {
            "package-lock.json" => parse_npm_lock(&content),
            "pnpm-lock.yaml" => parse_pnpm_lock(&content),
            "yarn.lock" => parse_yarn_lock(&content),
            _ => Vec::new(),
        };
        if !pkgs.is_empty() {
            return Some((path, pkgs));
        }
    }
    None
}

#[derive(Deserialize)]
struct NpmLockV2 {
    #[serde(default)]
    packages: std::collections::HashMap<String, NpmPackageEntry>,
}

#[derive(Deserialize)]
struct NpmPackageEntry {
    #[serde(default)]
    version: Option<String>,
}

fn parse_npm_lock(content: &str) -> Vec<Package> {
    let Ok(lock) = serde_json::from_str::<NpmLockV2>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, entry) in lock.packages {
        if key.is_empty() {
            continue; // root
        }
        // Keys look like "node_modules/<name>" possibly nested; take last segment.
        let name = match key.rsplit("node_modules/").next() {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let Some(version) = entry.version else {
            continue;
        };
        out.push(Package {
            name: name.to_string(),
            version,
        });
    }
    out
}

fn parse_pnpm_lock(content: &str) -> Vec<Package> {
    // pnpm-lock.yaml is YAML; we avoid an extra dep and parse keys heuristically.
    // Look for lines like `  /@scope/name@1.2.3:` or `  /name@1.2.3:` under `packages:`
    let mut out = Vec::new();
    let mut in_packages = false;
    for line in content.lines() {
        if line.starts_with("packages:") {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }
        // Top-level key reset
        if !line.starts_with("  ") && !line.is_empty() {
            in_packages = false;
            continue;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with("/") || !trimmed.ends_with(':') {
            continue;
        }
        let key = &trimmed[1..trimmed.len() - 1];
        // Cut off any peer-dependency suffix like `(peer@1.0.0)`.
        let key = key.split('(').next().unwrap_or(key);
        // Find the `@` that separates name from version. Scoped names start
        // with `@`, so skip index 0 when searching.
        let search_start = if key.starts_with('@') { 1 } else { 0 };
        let Some(at_idx) = key[search_start..].find('@').map(|i| i + search_start) else {
            continue;
        };
        let name = &key[..at_idx];
        let version = &key[at_idx + 1..];
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Package {
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    out
}

fn parse_yarn_lock(content: &str) -> Vec<Package> {
    // Yarn v1 format:
    //   "pkg@^1.0.0", "pkg@^1.2.0":
    //     version "1.2.5"
    let mut out = Vec::new();
    let mut pending_name: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if line.starts_with(char::is_alphanumeric) || line.starts_with('"') {
            // Descriptor line: "name@range", "name@range", ...
            let first = line.trim_end_matches(':').split(',').next().unwrap_or("");
            let first = first.trim().trim_matches('"');
            if let Some(at_idx) = first.rfind('@') {
                pending_name = Some(first[..at_idx].to_string());
            }
        } else if trimmed.starts_with("version ") {
            if let Some(name) = pending_name.take() {
                let ver = trimmed
                    .trim_start_matches("version ")
                    .trim()
                    .trim_matches('"');
                out.push(Package {
                    name,
                    version: ver.to_string(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_lock_v2_extracts_packages() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/lodash": { "version": "4.17.20" },
                "node_modules/@scope/pkg": { "version": "1.0.0" }
            }
        }"#;
        let pkgs = parse_npm_lock(content);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.20"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "@scope/pkg" && p.version == "1.0.0"));
    }

    #[test]
    fn pnpm_lock_extracts_packages() {
        let content = r#"
lockfileVersion: '6.0'

packages:

  /lodash@4.17.20:
    resolution: {}
  /@scope/pkg@1.0.0(peer@1.0.0):
    resolution: {}
"#;
        let pkgs = parse_pnpm_lock(content);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.20"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "@scope/pkg" && p.version == "1.0.0"));
    }

    #[test]
    fn yarn_lock_extracts_packages() {
        let content = r#"
lodash@^4.17.15:
  version "4.17.20"
  resolved "https://..."

"@scope/pkg@^1.0.0":
  version "1.0.0"
"#;
        let pkgs = parse_yarn_lock(content);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "lodash" && p.version == "4.17.20"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "@scope/pkg" && p.version == "1.0.0"));
    }
}
