//! Minimal terminal renderer. Full color/table output ships with Hafta 3.

use std::io::Write;

use owo_colors::OwoColorize;
use shaudit_core::{Finding, Severity};

use crate::{counts_by_severity, Renderer, Result, RunMeta};

pub struct TerminalRenderer {
    pub color: bool,
}

impl Default for TerminalRenderer {
    fn default() -> Self {
        Self { color: true }
    }
}

impl TerminalRenderer {
    pub fn new(color: bool) -> Self {
        Self { color }
    }
}

impl Renderer for TerminalRenderer {
    fn render(&self, findings: &[Finding], meta: &RunMeta, w: &mut dyn Write) -> Result<()> {
        writeln!(
            w,
            "Shadow Auditor v{}  ·  scanned {} file(s) in {:.2}s",
            meta.tool_version,
            meta.candidates_scanned,
            meta.duration.as_secs_f32()
        )?;
        writeln!(w)?;

        if findings.is_empty() {
            writeln!(w, "{}", "0 findings".bold())?;
            return Ok(());
        }

        for f in findings {
            let tag = severity_tag(f.severity, self.color);
            writeln!(
                w,
                "{tag:<9} {path}:{line:<5}  {rule}",
                path = f.location.path.display(),
                line = f.location.start_line,
                rule = f.rule_id,
            )?;
            writeln!(w, "          {}", f.message)?;
        }
        writeln!(w)?;

        let c = counts_by_severity(findings);
        writeln!(
            w,
            "{} critical · {} high · {} medium · {} low · {} info",
            c[0], c[1], c[2], c[3], c[4]
        )?;
        Ok(())
    }
}

fn severity_tag(s: Severity, color: bool) -> String {
    let label = s.as_str().to_ascii_uppercase();
    if !color {
        return label;
    }
    match s {
        Severity::Critical => label.red().bold().to_string(),
        Severity::High => label.red().to_string(),
        Severity::Medium => label.yellow().to_string(),
        Severity::Low => label.cyan().to_string(),
        Severity::Info => label.dimmed().to_string(),
    }
}
