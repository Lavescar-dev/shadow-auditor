//! Python lockfile parsers: `poetry.lock` + `requirements.txt`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::Package;

pub fn collect(workspace_root: &Path) -> Option<(PathBuf, Vec<Package>)> {
    let poetry = workspace_root.join("poetry.lock");
    if poetry.exists() {
        if let Ok(content) = std::fs::read_to_string(&poetry) {
            let pkgs = parse_poetry_lock(&content);
            if !pkgs.is_empty() {
                return Some((poetry, pkgs));
            }
        }
    }

    let requirements = workspace_root.join("requirements.txt");
    if requirements.exists() {
        if let Ok(content) = std::fs::read_to_string(&requirements) {
            let pkgs = parse_requirements(&content);
            if !pkgs.is_empty() {
                return Some((requirements, pkgs));
            }
        }
    }

    None
}

#[derive(Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
}

fn parse_poetry_lock(content: &str) -> Vec<Package> {
    let Ok(lock) = toml::from_str::<PoetryLock>(content) else {
        return Vec::new();
    };
    lock.package
        .into_iter()
        .map(|p| Package {
            name: p.name,
            version: p.version,
        })
        .collect()
}

fn parse_requirements(content: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-r ") {
            continue;
        }
        // pkg==1.2.3 ; pkg~=1.0 ; pkg>=1.0,<2.0
        let name_version: Vec<&str> = line.splitn(2, "==").collect();
        if name_version.len() != 2 {
            continue;
        }
        let name = name_version[0].trim();
        let version = name_version[1]
            .split([';', ',', ' '])
            .next()
            .unwrap_or("")
            .trim();
        if !name.is_empty() && !version.is_empty() {
            out.push(Package {
                name: name.to_string(),
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
    fn parses_poetry_lock() {
        let content = r#"
[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "urllib3"
version = "1.26.9"
"#;
        let pkgs = parse_poetry_lock(content);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "requests" && p.version == "2.28.0"));
    }

    #[test]
    fn parses_pinned_requirements() {
        let content = "\
requests==2.28.0
urllib3==1.26.9 ; python_version < '3.11'
# a comment
django>=4.0,<5.0
";
        let pkgs = parse_requirements(content);
        assert!(pkgs
            .iter()
            .any(|p| p.name == "requests" && p.version == "2.28.0"));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "urllib3" && p.version == "1.26.9"));
        // django line is not pinned → skipped
        assert!(!pkgs.iter().any(|p| p.name == "django"));
    }
}
