//! SARIF v2.1.0 renderer (plan §7.1).
//!
//! Emits a schema-conformant document with a `rules[]` descriptor table
//! (so GitHub Code Scanning renders rule names) and per-result provenance
//! metadata under `properties.shaudit`.

use std::io::Write;

use serde::Serialize;
use serde_json::Value as JsonValue;
use shaudit_core::{Finding, Severity};

use crate::{Renderer, Result, RuleDescriptor, RunMeta};

pub struct SarifRenderer {
    rules: Vec<RuleDescriptor>,
}

impl SarifRenderer {
    pub fn new(rules: Vec<RuleDescriptor>) -> Self {
        Self { rules }
    }
}

impl Default for SarifRenderer {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[derive(Serialize)]
struct SarifDoc<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    version: &'a str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'a str,
    version: &'a str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "fullDescription")]
    full_description: SarifText,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

#[derive(Serialize)]
struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    rule_id: &'a str,
    level: &'static str,
    message: SarifMessage<'a>,
    locations: Vec<SarifLocation<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifProperties>,
}

#[derive(Serialize)]
struct SarifMessage<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct SarifLocation<'a> {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysical<'a>,
}

#[derive(Serialize)]
struct SarifPhysical<'a> {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifact<'a>,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifact<'a> {
    uri: &'a str,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startColumn")]
    start_column: u32,
    #[serde(rename = "endLine")]
    end_line: u32,
    #[serde(rename = "endColumn")]
    end_column: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<SarifSnippet>,
}

#[derive(Serialize)]
struct SarifSnippet {
    text: String,
}

#[derive(Serialize)]
struct SarifProperties {
    shaudit: ShauditProperties,
}

#[derive(Serialize)]
struct ShauditProperties {
    verifier_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance_score: Option<f32>,
    ai_likely: bool,
    #[serde(skip_serializing_if = "is_null_or_empty")]
    metadata: JsonValue,
}

fn is_null_or_empty(v: &JsonValue) -> bool {
    v.is_null() || matches!(v, JsonValue::Object(m) if m.is_empty())
}

impl Renderer for SarifRenderer {
    fn render(&self, findings: &[Finding], meta: &RunMeta, w: &mut dyn Write) -> Result<()> {
        let path_strings: Vec<String> = findings
            .iter()
            .map(|f| f.location.path.to_string_lossy().into_owned())
            .collect();

        let results: Vec<SarifResult> = findings
            .iter()
            .zip(path_strings.iter())
            .map(|(f, path)| {
                let ai_likely = f.provenance_score.is_some_and(|s| s >= 0.5);
                SarifResult {
                    rule_id: &f.rule_id,
                    level: severity_to_level(f.severity),
                    message: SarifMessage { text: &f.message },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysical {
                            artifact_location: SarifArtifact { uri: path.as_str() },
                            region: SarifRegion {
                                start_line: f.location.start_line,
                                start_column: f.location.start_col,
                                end_line: f.location.end_line,
                                end_column: f.location.end_col,
                                snippet: f
                                    .location
                                    .snippet
                                    .clone()
                                    .map(|text| SarifSnippet { text }),
                            },
                        },
                    }],
                    properties: Some(SarifProperties {
                        shaudit: ShauditProperties {
                            verifier_id: f.verifier_id.clone(),
                            provenance_score: f.provenance_score,
                            ai_likely,
                            metadata: f.metadata.clone(),
                        },
                    }),
                }
            })
            .collect();

        // Deduplicate rule ids since a single verifier may emit many rule_ids
        // and the CLI passes only verifier-level descriptors. We still synthesize
        // one rule entry per verifier.
        let mut sarif_rules: Vec<SarifRule> = self
            .rules
            .iter()
            .map(|r| SarifRule {
                id: r.verifier_id.clone(),
                short_description: SarifText {
                    text: r.description.clone(),
                },
                full_description: SarifText {
                    text: r.description.clone(),
                },
            })
            .collect();

        // Also include every distinct rule_id seen in findings (so downstream
        // tools can filter by rule id even without a pre-registered descriptor).
        let mut seen: std::collections::HashSet<String> =
            self.rules.iter().map(|r| r.verifier_id.clone()).collect();
        for f in findings {
            if seen.insert(f.rule_id.clone()) {
                sarif_rules.push(SarifRule {
                    id: f.rule_id.clone(),
                    short_description: SarifText {
                        text: f.rule_id.clone(),
                    },
                    full_description: SarifText {
                        text: f.message.clone(),
                    },
                });
            }
        }

        let doc = SarifDoc {
            schema: "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "shaudit",
                        information_uri: "https://audit.lavescar.com.tr",
                        version: meta.tool_version,
                        rules: sarif_rules,
                    },
                },
                results,
            }],
        };
        serde_json::to_writer_pretty(w, &doc)?;
        Ok(())
    }
}

fn severity_to_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
