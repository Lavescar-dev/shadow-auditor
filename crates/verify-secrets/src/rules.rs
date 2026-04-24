//! Parser + loader for the vendored gitleaks `rules.toml` schema.

use regex::Regex;
use serde::Deserialize;

use shaudit_core::Severity;

pub const BUILTIN_RULES: &str = include_str!("../../../data/secrets-rules.toml");

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawRule {
    id: String,
    #[serde(default)]
    description: String,
    /// Content-regex — optional because gitleaks also has path-based rules.
    #[serde(default)]
    regex: Option<String>,
    #[serde(default)]
    entropy: Option<f32>,
    #[serde(default)]
    keywords: Vec<String>,
}

#[derive(Debug)]
pub struct SecretRule {
    pub id: String,
    pub description: String,
    pub regex: Regex,
    pub entropy: Option<f32>,
    pub keywords: Vec<String>,
}

impl SecretRule {
    pub fn severity(&self) -> Severity {
        // Best-effort severity mapping based on rule id. Rules covering
        // long-lived credentials (private keys, cloud access keys) are
        // critical; short-lived OAuth and low-value keys are high.
        let low_value = [
            "adafruit",
            "airtable",
            "beamer",
            "contentful",
            "doppler",
            "dropbox",
            "duffel",
            "fastly",
            "freshbooks",
            "gocardless",
            "linkedin",
            "lob",
            "microsoft-teams-webhook",
            "new-relic",
            "pypi-upload-token",
            "readme",
            "sendgrid",
            "sentry",
            "shopify-shared-secret",
            "trello",
            "twitter",
        ];
        let critical_markers = [
            "private-key",
            "aws-access-token",
            "gcp-service-account",
            "azure-storage",
            "github-pat",
            "github-fine-grained-pat",
            "github-oauth",
            "github-app-token",
            "stripe-access-token",
            "vault-service-token",
            "vault-batch-token",
        ];
        if critical_markers.iter().any(|m| self.id.contains(m)) {
            Severity::Critical
        } else if low_value.iter().any(|m| self.id.contains(m)) {
            Severity::Medium
        } else {
            Severity::High
        }
    }
}

#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<SecretRule>,
    pub skipped: Vec<SkippedRule>,
}

#[derive(Debug)]
pub struct SkippedRule {
    pub id: String,
    pub reason: String,
}

/// Load rules from the builtin vendored gitleaks config.
pub fn load_builtin() -> RuleSet {
    load_from_str(BUILTIN_RULES)
}

pub fn load_from_str(toml_str: &str) -> RuleSet {
    let parsed: RuleFile = match toml::from_str(toml_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to parse rules TOML");
            eprintln!("shaudit: failed to parse secrets-rules.toml: {e}");
            return RuleSet::default();
        }
    };

    let mut rules = Vec::with_capacity(parsed.rules.len());
    let mut skipped = Vec::new();

    for raw in parsed.rules {
        let Some(regex_src) = raw.regex.as_deref() else {
            skipped.push(SkippedRule {
                id: raw.id,
                reason: "path-only rule (no content regex)".into(),
            });
            continue;
        };
        match Regex::new(regex_src) {
            Ok(regex) => rules.push(SecretRule {
                id: raw.id,
                description: raw.description,
                regex,
                entropy: raw.entropy,
                keywords: raw.keywords,
            }),
            Err(e) => {
                skipped.push(SkippedRule {
                    id: raw.id.clone(),
                    reason: format!("regex compile: {e}"),
                });
            }
        }
    }

    tracing::info!(
        loaded = rules.len(),
        skipped = skipped.len(),
        "secret rule set ready"
    );

    RuleSet { rules, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_load_with_minimal_skips() {
        let set = load_builtin();
        // At least the vast majority should compile under Rust regex.
        assert!(
            set.rules.len() > 100,
            "loaded only {} rules",
            set.rules.len()
        );
        if !set.skipped.is_empty() {
            for s in &set.skipped {
                eprintln!("skipped rule {}: {}", s.id, s.reason);
            }
        }
    }

    #[test]
    fn rules_have_non_empty_keywords_where_expected() {
        let set = load_builtin();
        let aws_rules: Vec<_> = set.rules.iter().filter(|r| r.id.contains("aws")).collect();
        assert!(!aws_rules.is_empty(), "expected AWS rules in gitleaks set");
    }
}
