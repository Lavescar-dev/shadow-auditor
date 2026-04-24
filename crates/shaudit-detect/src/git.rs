//! Git metadata collection for AI provenance signals.
//!
//! Pragmatic: shells out to `git` CLI (matches `shaudit-discover`'s approach).

use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct GitContext {
    pub commit_sha: Option<String>,
    pub commit_message: String,
    pub author_date_hour: Option<u32>,
    pub additions: u32,
}

pub fn context_for_file(repo: &Path, path: &Path) -> GitContext {
    let mut ctx = GitContext::default();
    let rel = path.strip_prefix(repo).unwrap_or(path);

    let log_out = Command::new("git")
        .args([
            "log",
            "-1",
            "--format=%H%n%ad%n%B",
            "--date=format:%H",
            "--",
        ])
        .arg(rel)
        .current_dir(repo)
        .output();

    let Ok(out) = log_out else {
        return ctx;
    };
    if !out.status.success() {
        return ctx;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();

    if let Some(sha) = lines.next() {
        if !sha.is_empty() {
            ctx.commit_sha = Some(sha.to_string());
        }
    }
    if let Some(hour_str) = lines.next() {
        if let Ok(h) = hour_str.parse::<u32>() {
            ctx.author_date_hour = Some(h);
        }
    }
    let msg_lines: Vec<&str> = lines.collect();
    ctx.commit_message = msg_lines.join("\n");

    // Additions via --numstat on the same commit.
    if let Some(sha) = &ctx.commit_sha {
        if let Ok(stats) = Command::new("git")
            .args(["show", "--numstat", "--format="])
            .arg(sha)
            .arg("--")
            .arg(rel)
            .current_dir(repo)
            .output()
        {
            if stats.status.success() {
                let stats_text = String::from_utf8_lossy(&stats.stdout);
                for line in stats_text.lines() {
                    // "<added>\t<removed>\t<path>"
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(a) = parts[0].parse::<u32>() {
                            ctx.additions += a;
                        }
                    }
                }
            }
        }
    }

    ctx
}
