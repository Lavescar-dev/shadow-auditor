//! SARIF v2.1.0 renderer — minimal scaffolding (full schema compliance Hafta 3+).

use std::io::Write;

use serde::Serialize;
use shaudit_core::{Finding, Severity};

use crate::{Renderer, Result, RunMeta};

pub struct SarifRenderer;

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
}

#[derive(Serialize)]
struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    rule_id: &'a str,
    level: &'static str,
    message: SarifMessage<'a>,
    locations: Vec<SarifLocation<'a>>,
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
            .map(|(f, path)| SarifResult {
                rule_id: &f.rule_id,
                level: severity_to_level(f.severity),
                message: SarifMessage { text: &f.message },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysical {
                        artifact_location: SarifArtifact { uri: path.as_str() },
                        region: SarifRegion {
                            start_line: f.location.start_line,
                            start_column: f.location.start_col,
                        },
                    },
                }],
            })
            .collect();

        let doc = SarifDoc {
            schema: "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "shaudit",
                        information_uri: "https://audit.lavescar.com.tr",
                        version: meta.tool_version,
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
