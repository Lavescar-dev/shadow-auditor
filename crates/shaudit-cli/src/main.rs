//! Shadow Auditor CLI entry point.
//!
//! Subcommand surface matches plan §6.1. Only `scan`, `init`, `verifiers`, and
//! `version` do meaningful work in Hafta 1-2; `detect` and `cache` are stubs.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context;
use clap::{Parser, Subcommand};

use shaudit_config::{Config, SHAUDITIGNORE_TEMPLATE};
use shaudit_core::{Finding, Severity};
use shaudit_discover::{DefaultDiscoverer, DiscoverOpts, Discoverer};
use shaudit_output::{JsonRenderer, Renderer, RunMeta, SarifRenderer, TerminalRenderer};
use shaudit_parse::SharedAstCache;

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
        languages: None, // language-name → Language enum mapping lands with the secrets verifier
        exclude: config.discover.exclude.clone(),
        respect_gitignore: config.general.respect_gitignore,
        include_submodules: args.include_submodules,
    };

    let started = Instant::now();
    let discoverer = DefaultDiscoverer;
    let candidates = discoverer.discover(&opts).context("discover candidates")?;

    tracing::info!(count = candidates.len(), "candidates discovered");

    // Parse each file into the AST cache. Errors become Info findings.
    let ast_cache = SharedAstCache::new();
    let findings: Vec<Finding> = Vec::new();
    for c in &candidates {
        match ast_cache.get_or_parse(&c.path, c.language) {
            Ok(_) => {}
            Err(shaudit_parse::ParseError::UnsupportedLanguage(_)) => {
                // Unknown-language files slip past the fs filter (e.g., via
                // `--languages` override). Silently skip until the language
                // list matures.
            }
            Err(err) => {
                tracing::warn!(path = %c.path.display(), %err, "parse failed");
            }
        }
    }

    let meta = RunMeta {
        tool_version: TOOL_VERSION,
        candidates_scanned: candidates.len(),
        verifiers_run: Vec::new(), // verifiers land in Hafta 3-6
        duration: started.elapsed(),
    };

    render_findings(&findings, &meta, args, no_color)?;

    let exit_code = compute_exit_code(&findings, args.fail_on.as_deref(), &config);
    // Keep `findings` borrowed above; suppress unused-warning for the length.
    let _ = findings.len();
    Ok(exit_code)
}

fn render_findings(
    findings: &[Finding],
    meta: &RunMeta,
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

    match format.as_str() {
        "sarif" => SarifRenderer.render(findings, meta, &mut out)?,
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
