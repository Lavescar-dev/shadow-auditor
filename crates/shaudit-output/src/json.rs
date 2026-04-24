//! JSON renderer — self-defined schema (plan §7.2).

use std::io::Write;

use serde::Serialize;
use shaudit_core::Finding;

use crate::{Renderer, Result, RunMeta};

pub struct JsonRenderer;

#[derive(Serialize)]
struct Payload<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    version: &'a str,
    run: RunSummary<'a>,
    findings: &'a [Finding],
}

#[derive(Serialize)]
struct RunSummary<'a> {
    tool_version: &'a str,
    duration_ms: u128,
    candidates_scanned: usize,
    verifiers_run: &'a [String],
}

impl Renderer for JsonRenderer {
    fn render(&self, findings: &[Finding], meta: &RunMeta, w: &mut dyn Write) -> Result<()> {
        let payload = Payload {
            schema: "https://audit.lavescar.com.tr/schema/v1.json",
            version: meta.tool_version,
            run: RunSummary {
                tool_version: meta.tool_version,
                duration_ms: meta.duration.as_millis(),
                candidates_scanned: meta.candidates_scanned,
                verifiers_run: &meta.verifiers_run,
            },
            findings,
        };
        serde_json::to_writer_pretty(w, &payload)?;
        Ok(())
    }
}
