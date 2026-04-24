//! Shadow Auditor CLI entry point.
//!
//! Subcommand surface matches plan §6.1. `scan`, `init`, `verifiers`, and
//! `version` are fully wired; `detect` + `cache` are minimal stubs.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use clap::{Parser, Subcommand};
use futures::future::join_all;

use shaudit_config::{Config, SHAUDITIGNORE_TEMPLATE};
use shaudit_core::{Finding, Severity, Verifier, VerifyContext};
use shaudit_discover::{DefaultDiscoverer, DiscoverOpts, Discoverer};
use shaudit_output::{JsonRenderer, Renderer, RunMeta, SarifRenderer, TerminalRenderer};
use verify_cve::CveVerifier;
use verify_secrets::SecretsVerifier;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "shaudit", version = TOOL_VERSION, about = "Verify what your AI just wrote")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,

    /// Use this config file instead of the precedence chain.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Enable detailed tracing output to stderr.
    #[arg(long, global = true)]
    verbose: bool,

    /// Suppress progress output (only errors).
    #[arg(long, global = true)]
    quiet: bool,

    /// Disable colored terminal output.
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan files for AI-related issues.
    Scan(ScanArgs),

    /// Initialize shaudit.toml and .shauditignore in the current directory.
    Init,

    /// List available verifiers.
    Verifiers,

    /// Run only AI provenance detection (no verification). Stub.
    Detect(ScanArgs),

    /// Manage local caches (CVE, AST). Stub.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Show version information.
    Version,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Paths to scan. Default: workspace roots from config.
    paths: Vec<PathBuf>,

    // Discovery
    /// Scan only files changed since this ref (default: HEAD~1 if flag given alone).
    #[arg(long, value_name = "REF", num_args = 0..=1, default_missing_value = "HEAD~1")]
    diff: Option<String>,

    /// Scan only staged changes.
    #[arg(long)]
    staged: bool,

    /// Comma-separated language filter (rust,typescript,python,javascript,go).
    #[arg(long, value_delimiter = ',')]
    languages: Option<Vec<String>>,

    /// Include git submodules (default: skip).
    #[arg(long)]
    include_submodules: bool,

    // Detection
    /// Scan only AI-tagged commits.
    #[arg(long)]
    ai_only: bool,

    /// Sort AI-tagged findings first (default).
    #[arg(long)]
    ai_priority: bool,

    /// Skip AI provenance detection.
    #[arg(long)]
    no_detect: bool,

    // Verifiers
    /// Comma-separated verifier IDs to run.
    #[arg(long, value_delimiter = ',')]
    verifiers: Option<Vec<String>>,

    /// Verifier IDs to skip.
    #[arg(long, value_delimiter = ',')]
    skip: Option<Vec<String>>,

    /// Enable mutation/property on all files (slow).
    #[arg(long)]
    deep: bool,

    // Output
    /// Output format: terminal | sarif | json.
    #[arg(short = 'f', long, value_name = "FMT")]
    format: Option<String>,

    /// Write output to path instead of stdout.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Filter findings below this severity.
    #[arg(long)]
    severity: Option<String>,

    /// Exit non-zero if findings at or above this severity.
    #[arg(long)]
    fail_on: Option<String>,

    /// Per-verifier timeout in seconds.
    #[arg(long)]
    timeout: Option<u64>,

    /// Parallelism (default: num_cpus).
    #[arg(long)]
    jobs: Option<usize>,
}

#[derive(Subcommand)]
enum CacheAction {
    /// Show cache locations and sizes.
    Info,
    /// Refresh a named cache (e.g., `cve`).
    Refresh { name: String },
    /// Clear a named cache.
    Clear { name: String },
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.quiet);

    let exit_code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            3
        }
    };
    std::process::exit(exit_code);
}

fn init_tracing(verbose: bool, quiet: bool) {
    let level = if verbose {
        tracing::Level::DEBUG
    } else if quiet {
        tracing::Level::ERROR
    } else {
        tracing::Level::INFO
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .try_init();
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Cmd::Scan(args) => cmd_scan(&args, cli.config.as_deref(), cli.no_color),
        Cmd::Init => cmd_init(),
        Cmd::Verifiers => {
            cmd_verifiers();
            Ok(0)
        }
        Cmd::Detect(_args) => {
            println!("shaudit detect: AI provenance scoring lands in Hafta 4.");
            Ok(0)
        }
        Cmd::Cache { action } => cmd_cache(action),
        Cmd::Version => {
            cmd_version();
            Ok(0)
        }
    }
}

fn cmd_scan(
    args: &ScanArgs,
    config_override: Option<&std::path::Path>,
    no_color: bool,
) -> anyhow::Result<i32> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(run_scan(args, config_override, no_color))
}

async fn run_scan(
    args: &ScanArgs,
    config_override: Option<&std::path::Path>,
    no_color: bool,
) -> anyhow::Result<i32> {
    let workspace_root = std::env::current_dir().context("cwd")?;

    let config = match config_override {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?;
            Config::from_toml(&content)
                .with_context(|| format!("parse config {}", path.display()))?
        }
        None => Config::load(&workspace_root).context("load config")?,
    };

    let roots = if args.paths.is_empty() {
        config
            .discover
            .roots
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>()
    } else {
        args.paths.clone()
    };

    let opts = DiscoverOpts {
        roots,
        diff_ref: args.diff.clone(),
        staged: args.staged,
        languages: None,
        exclude: config.discover.exclude.clone(),
        respect_gitignore: config.general.respect_gitignore,
        include_submodules: args.include_submodules,
    };

    let started = Instant::now();
    let discoverer = DefaultDiscoverer;
    let mut candidates = discoverer.discover(&opts).context("discover candidates")?;

    tracing::info!(count = candidates.len(), "candidates discovered");

    // --- AI provenance detection ---
    let detect_enabled = config.detect.enabled && !args.no_detect;
    if detect_enabled {
        score_candidates(&mut candidates, &workspace_root);
    }

    if args.ai_only {
        let threshold = config.detect.threshold;
        let before = candidates.len();
        candidates.retain(|c| c.provenance_score.is_some_and(|s| s >= threshold));
        tracing::info!(
            before,
            after = candidates.len(),
            threshold,
            "--ai-only filter applied"
        );
    }

    let verifiers = build_verifier_registry(args, &config);
    let verifier_ids: Vec<String> = verifiers.iter().map(|v| v.id().to_string()).collect();

    tracing::info!(
        verifiers = ?verifier_ids,
        "dispatching verifiers"
    );

    let mut findings = dispatch_verifiers(&candidates, &verifiers, &workspace_root).await;
    attach_provenance_to_findings(&mut findings, &candidates);
    sort_findings(&mut findings, args.ai_priority);

    let meta = RunMeta {
        tool_version: TOOL_VERSION,
        candidates_scanned: candidates.len(),
        verifiers_run: verifier_ids,
        duration: started.elapsed(),
    };

    render_findings(&findings, &meta, &verifiers, args, no_color)?;

    Ok(compute_exit_code(
        &findings,
        args.fail_on.as_deref(),
        &config,
    ))
}

fn build_verifier_registry(args: &ScanArgs, config: &Config) -> Vec<Arc<dyn Verifier>> {
    let mut registry: Vec<Arc<dyn Verifier>> = Vec::new();

    let secrets_enabled = config.verifiers.secrets.enabled;
    let cve_enabled = config.verifiers.cve.enabled;

    let explicit = args.verifiers.as_ref();
    let skip: std::collections::HashSet<&str> = args
        .skip
        .as_ref()
        .map(|s| s.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let want = |id: &str, config_enabled: bool| -> bool {
        if skip.contains(id) {
            return false;
        }
        match explicit {
            Some(ids) => ids.iter().any(|s| s == id),
            None => config_enabled,
        }
    };

    if want("secrets", secrets_enabled) {
        registry.push(Arc::new(SecretsVerifier::with_builtin_rules()));
    }
    if want("cve", cve_enabled) {
        registry.push(Arc::new(CveVerifier::new()));
    }

    registry
}

async fn dispatch_verifiers(
    candidates: &[shaudit_core::Candidate],
    verifiers: &[Arc<dyn Verifier>],
    workspace_root: &std::path::Path,
) -> Vec<Finding> {
    let mut tasks = Vec::new();
    for cand in candidates {
        for verifier in verifiers {
            if !verifier.supported_languages().contains(&cand.language) {
                continue;
            }
            let verifier = verifier.clone();
            let cand = cand.clone();
            let root = workspace_root.to_path_buf();
            tasks.push(tokio::spawn(async move {
                let ctx = VerifyContext {
                    workspace_root: &root,
                    provenance: cand.provenance_score,
                };
                match verifier.verify(&cand, &ctx).await {
                    Ok(findings) => findings,
                    Err(e) => {
                        tracing::warn!(
                            verifier = verifier.id(),
                            path = %cand.path.display(),
                            error = %e,
                            "verifier failed"
                        );
                        Vec::new()
                    }
                }
            }));
        }
    }
    let all = join_all(tasks).await;
    let mut out = Vec::new();
    for mut findings in all.into_iter().flatten() {
        out.append(&mut findings);
    }
    out
}

fn sort_findings(findings: &mut [Finding], ai_priority: bool) {
    findings.sort_by(|a, b| {
        if ai_priority {
            let a_score = a.provenance_score.unwrap_or(0.0);
            let b_score = b.provenance_score.unwrap_or(0.0);
            let ord = b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal);
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.location.path.cmp(&b.location.path))
            .then_with(|| a.location.start_line.cmp(&b.location.start_line))
    });
}

fn score_candidates(candidates: &mut [shaudit_core::Candidate], workspace_root: &std::path::Path) {
    for c in candidates.iter_mut() {
        // Inline override markers take precedence over heuristic scoring.
        if let Ok(source) = std::fs::read_to_string(&c.path) {
            if let Some(forced) = shaudit_detect::inline_override(&source) {
                c.provenance_score = Some(forced);
                continue;
            }
        }
        if let Some(report) = shaudit_detect::score_candidate(c, workspace_root) {
            c.provenance_score = Some(report.score);
        }
    }
}

fn attach_provenance_to_findings(findings: &mut [Finding], candidates: &[shaudit_core::Candidate]) {
    use std::collections::HashMap;
    let scores: HashMap<std::path::PathBuf, f32> = candidates
        .iter()
        .filter_map(|c| c.provenance_score.map(|s| (c.path.clone(), s)))
        .collect();
    for f in findings.iter_mut() {
        if f.provenance_score.is_none() {
            if let Some(&s) = scores.get(&f.location.path) {
                f.provenance_score = Some(s);
            }
        }
    }
}

fn render_findings(
    findings: &[Finding],
    meta: &RunMeta,
    verifiers: &[Arc<dyn Verifier>],
    args: &ScanArgs,
    no_color: bool,
) -> anyhow::Result<()> {
    let format = args
        .format
        .clone()
        .unwrap_or_else(|| default_format(args.output.is_some()));

    let mut out: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(std::fs::File::create(path)?),
        None => Box::new(io::stdout().lock()),
    };

    // Rule descriptors for SARIF rules[] array (SARIF only needs them; other
    // renderers ignore the arg).
    let rule_descriptors: Vec<shaudit_output::RuleDescriptor> = verifiers
        .iter()
        .map(|v| shaudit_output::RuleDescriptor {
            verifier_id: v.id().to_string(),
            description: v.description().to_string(),
        })
        .collect();

    match format.as_str() {
        "sarif" => SarifRenderer::new(rule_descriptors).render(findings, meta, &mut out)?,
        "json" => JsonRenderer.render(findings, meta, &mut out)?,
        "terminal" | "auto" => TerminalRenderer::new(!no_color).render(findings, meta, &mut out)?,
        other => anyhow::bail!("unknown format `{other}` — use terminal|sarif|json"),
    }
    writeln!(out)?;
    Ok(())
}

fn default_format(writing_to_file: bool) -> String {
    // TTY detection is deferred; use heuristic: file output → json, else terminal.
    if writing_to_file {
        "json".into()
    } else {
        "terminal".into()
    }
}

fn compute_exit_code(findings: &[Finding], fail_on: Option<&str>, config: &Config) -> i32 {
    let threshold = fail_on
        .or(Some(config.general.fail_on_severity.as_str()))
        .and_then(Severity::from_str_ci)
        .unwrap_or(Severity::High);

    if findings
        .iter()
        .any(|f| f.severity.rank() >= threshold.rank())
    {
        1
    } else {
        0
    }
}

fn cmd_init() -> anyhow::Result<i32> {
    let cfg_path = PathBuf::from("shaudit.toml");
    let ignore_path = PathBuf::from(".shauditignore");

    if cfg_path.exists() {
        anyhow::bail!("shaudit.toml already exists — refusing to overwrite");
    }
    let commented = Config::default().to_toml_commented()?;
    std::fs::write(&cfg_path, commented)?;

    if !ignore_path.exists() {
        std::fs::write(&ignore_path, SHAUDITIGNORE_TEMPLATE)?;
    }
    println!("Wrote {} and {}", cfg_path.display(), ignore_path.display());
    Ok(0)
}

fn cmd_verifiers() {
    println!("Shadow Auditor verifiers:\n");
    for (id, status, desc) in VERIFIER_CATALOG {
        println!("  {id:<16} {status:<10} {desc}");
    }
    println!();
}

const VERIFIER_CATALOG: &[(&str, &str, &str)] = &[
    (
        "secrets",
        "Hafta 3",
        "Secret/API key detection via regex + entropy + AST context",
    ),
    (
        "cve",
        "Hafta 4",
        "Vulnerable dependency scanning (rustsec + OSV.dev)",
    ),
    (
        "hallucination",
        "Hafta 5",
        "Unresolved imports and nonexistent symbols",
    ),
    (
        "deadcode",
        "Hafta 5",
        "Functions/branches defined but never referenced",
    ),
    (
        "mutation",
        "Hafta 6",
        "Mutation testing via cargo-mutants (AI-tagged files only by default)",
    ),
    (
        "property",
        "Hafta 6",
        "Auto-generated property tests via proptest",
    ),
];

fn cmd_cache(action: CacheAction) -> anyhow::Result<i32> {
    match action {
        CacheAction::Info => {
            println!("Cache management lands in Hafta 4 alongside the CVE verifier.")
        }
        CacheAction::Refresh { name } => println!("cache refresh `{name}` — Hafta 4."),
        CacheAction::Clear { name } => println!("cache clear `{name}` — Hafta 4."),
    }
    Ok(0)
}

fn cmd_version() {
    println!("shaudit {TOOL_VERSION}");
    println!("homepage: https://audit.lavescar.com.tr");
    println!("repo:     https://github.com/Lavescar-dev/shadow-auditor");
}
