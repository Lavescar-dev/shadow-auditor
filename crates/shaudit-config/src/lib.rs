//! Shadow Auditor configuration schema and loader.
//!
//! Config precedence (plan §5.2):
//!
//! 1. CLI flags
//! 2. Environment variables (`SHAUDIT_*`) — not yet wired
//! 3. `.shaudit.toml` in current dir
//! 4. `shaudit.toml` in workspace root
//! 5. `~/.config/shaudit/config.toml`
//! 6. Built-in defaults

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("failed to serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub discover: DiscoverConfig,
    #[serde(default)]
    pub detect: DetectConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub verifiers: VerifiersConfig,
    #[serde(default)]
    pub ci: CiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeneralConfig {
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,
    #[serde(default = "default_fail_on_severity")]
    pub fail_on_severity: String,
    #[serde(default = "true_")]
    pub respect_gitignore: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            languages: default_languages(),
            fail_on_severity: default_fail_on_severity(),
            respect_gitignore: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoverConfig {
    #[serde(default = "default_roots")]
    pub roots: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Default for DiscoverConfig {
    fn default() -> Self {
        Self {
            roots: default_roots(),
            exclude: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectConfig {
    #[serde(default = "true_")]
    pub enabled: bool,
    #[serde(default = "default_detect_threshold")]
    pub threshold: f32,
    #[serde(default = "default_detect_mode")]
    pub mode: String,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 0.5,
            mode: "tag".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_sarif_version")]
    pub sarif_version: String,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "terminal".to_string(),
            sarif_version: "2.1.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct VerifiersConfig {
    #[serde(default)]
    pub secrets: SecretsCfg,
    #[serde(default)]
    pub cve: CveCfg,
    #[serde(default)]
    pub hallucination: ToggleCfg,
    #[serde(default)]
    pub deadcode: ToggleCfg,
    #[serde(default)]
    pub mutation: MutationCfg,
    #[serde(default)]
    pub property: PropertyCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretsCfg {
    #[serde(default = "true_")]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f32,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for SecretsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: 4.5,
            allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CveCfg {
    #[serde(default = "true_")]
    pub enabled: bool,
    #[serde(default = "default_cache_ttl_hours")]
    pub cache_ttl_hours: u32,
}

impl Default for CveCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToggleCfg {
    #[serde(default = "true_")]
    pub enabled: bool,
}

impl Default for ToggleCfg {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MutationCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "true_")]
    pub ai_only: bool,
}

impl Default for MutationCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            ai_only: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PropertyCfg {
    #[serde(default = "true_")]
    pub enabled: bool,
    #[serde(default = "true_")]
    pub ai_only: bool,
    #[serde(default = "default_generated_dir")]
    pub generated_dir: String,
}

impl Default for PropertyCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            ai_only: true,
            generated_dir: "target/shaudit-generated".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CiConfig {
    #[serde(default = "default_ci_fail_on")]
    pub fail_on_severity: String,
    #[serde(default = "default_ci_format")]
    pub format: String,
    #[serde(default = "default_ci_output")]
    pub output_path: String,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            fail_on_severity: "medium".to_string(),
            format: "sarif".to_string(),
            output_path: "shaudit-results.sarif".to_string(),
        }
    }
}

fn default_languages() -> Vec<String> {
    vec!["rust".into(), "typescript".into(), "python".into()]
}
fn default_fail_on_severity() -> String {
    "high".into()
}
fn default_roots() -> Vec<String> {
    vec![".".into()]
}
fn default_detect_threshold() -> f32 {
    0.5
}
fn default_detect_mode() -> String {
    "tag".into()
}
fn default_format() -> String {
    "terminal".into()
}
fn default_sarif_version() -> String {
    "2.1.0".into()
}
fn default_entropy_threshold() -> f32 {
    4.5
}
fn default_cache_ttl_hours() -> u32 {
    24
}
fn default_generated_dir() -> String {
    "target/shaudit-generated".into()
}
fn default_ci_fail_on() -> String {
    "medium".into()
}
fn default_ci_format() -> String {
    "sarif".into()
}
fn default_ci_output() -> String {
    "shaudit-results.sarif".into()
}
fn true_() -> bool {
    true
}

impl Config {
    /// Load config following the precedence in plan §5.2.
    ///
    /// Checks (lowest → highest): user global → workspace root → cwd override.
    /// CLI and env overrides are applied by the caller.
    pub fn load(workspace_root: &Path) -> Result<Self> {
        let mut config = Self::default();

        if let Some(user_cfg) = user_config_path() {
            if user_cfg.exists() {
                config = merge_file(config, &user_cfg)?;
            }
        }

        let ws_cfg = workspace_root.join("shaudit.toml");
        if ws_cfg.exists() {
            config = merge_file(config, &ws_cfg)?;
        }

        let cwd_cfg = std::env::current_dir()
            .map(|cwd| cwd.join(".shaudit.toml"))
            .ok();
        if let Some(cwd_cfg) = cwd_cfg {
            if cwd_cfg.exists() && cwd_cfg != ws_cfg {
                config = merge_file(config, &cwd_cfg)?;
            }
        }

        Ok(config)
    }

    /// Parse a config from a TOML string without filesystem access.
    pub fn from_toml(s: &str) -> std::result::Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Serialize this config as commented TOML for `shaudit init`.
    pub fn to_toml_commented(&self) -> Result<String> {
        let raw = toml::to_string_pretty(self)?;
        Ok(format!("{}{}", INIT_HEADER, raw))
    }
}

fn merge_file(mut base: Config, path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let overlay: Config = toml::from_str(&content).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    merge(&mut base, overlay);
    Ok(base)
}

fn merge(base: &mut Config, overlay: Config) {
    // Shallow merge: overlay fields replace base fields wholesale.
    // This matches the "later file wins" semantics of §5.2.
    *base = overlay;
}

fn user_config_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                let mut p = PathBuf::from(home);
                p.push(".config");
                p
            })
        })
        .map(|mut p| {
            p.push("shaudit");
            p.push("config.toml");
            p
        })
}

const INIT_HEADER: &str = r#"# shaudit.toml — Shadow Auditor configuration
# Docs: https://audit.lavescar.com.tr/docs/configuration
# All keys shown below are defaults; remove lines you don't want to override.

"#;

pub const SHAUDITIGNORE_TEMPLATE: &str = r#"# .shauditignore — paths excluded from shaudit scans (same syntax as .gitignore)
# target/
# node_modules/
# vendor/
# **/*.generated.ts
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips_through_toml() {
        let c = Config::default();
        let s = toml::to_string(&c).expect("serialize");
        let parsed: Config = toml::from_str(&s).expect("parse");
        assert_eq!(c, parsed);
    }

    #[test]
    fn empty_toml_produces_defaults() {
        let parsed: Config = toml::from_str("").expect("parse empty");
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn partial_toml_keeps_defaults_elsewhere() {
        let input = r#"
[general]
fail_on_severity = "critical"
"#;
        let parsed: Config = toml::from_str(input).expect("parse partial");
        assert_eq!(parsed.general.fail_on_severity, "critical");
        assert_eq!(parsed.verifiers.secrets.entropy_threshold, 4.5);
    }

    #[test]
    fn init_commented_output_starts_with_header() {
        let out = Config::default().to_toml_commented().unwrap();
        assert!(out.starts_with("# shaudit.toml"));
    }

    #[test]
    fn load_workspace_config_overrides_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("shaudit.toml");
        std::fs::write(
            &cfg_path,
            r#"
[general]
fail_on_severity = "low"
"#,
        )
        .unwrap();
        let cfg = Config::load(dir.path()).unwrap();
        assert_eq!(cfg.general.fail_on_severity, "low");
    }
}
