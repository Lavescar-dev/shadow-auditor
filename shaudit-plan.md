# Shadow Auditor — Master Implementation Plan

> Verify what your AI just wrote.
> Bug detection, security scanning, and property tests for AI-generated code.

**Status**: Draft v1.0 · **Owner**: Lavescar · **Target launch**: T+90 days

---

## 0. Project Identity

| Field | Value |
|---|---|
| Project name | Shadow Auditor |
| Crate / package name | `shadow-auditor` (workspace), `shaudit` (CLI binary crate) |
| Binary name | `shaudit` |
| Repo | `github.com/lavescar/shadow-auditor` |
| Domain | `shaudit.dev` (primary) or `shadowauditor.dev` (fallback) |
| License | MIT OR Apache-2.0 (dual) |
| Language | Rust (MSRV: stable - 2 versions, currently 1.78) |
| Tagline | "The shadow that audits your AI." |
| One-liner | "A static analysis CLI that verifies AI-generated code: detects hallucinated imports, scans for secrets and CVEs, generates property tests, and runs mutation analysis — all in a single Rust binary, SARIF-native, GitHub Action-ready." |

### Naming rationale

`shaudit` as binary because:

- Three syllables, type-friendly.
- No collision with common Unix utilities (`sha256sum`, `shred`, `sh` are clear).
- `shadow` alone overloaded with `/etc/shadow`, `shadow-cljs`, etc.
- `sa` as a short alias is rejected — collides with `sysadmin` muscle memory and unhelpful in shell history.

### Day 0 verification tasks (do before first commit)

- [ ] `crates.io` availability for `shadow-auditor` and `shaudit`
- [ ] `npmjs.com` availability for `@shaudit/action` (CI wrapper if we ever publish there)
- [ ] GitHub org/repo `lavescar/shadow-auditor` available
- [ ] Domain `shaudit.dev` and `shadowauditor.dev` WHOIS check
- [ ] Twitter/X handle `@shaudit_dev` or `@shadowauditor`
- [ ] Search GitHub for "shadow auditor" — confirm no active competing project

If any critical conflict, fallback names in priority order: `aiverify`, `aichk`, `audishadow`, `verifai`.

---

## 1. Strategic Positioning

### Problem statement

AI coding assistants (Claude Code, Cursor, Copilot, Windsurf, Aider) ship code at unprecedented speed. The bottleneck has shifted from *writing* to *verifying*. AI-generated code exhibits characteristic failure modes:

1. **Hallucinated imports**: references to nonexistent functions/modules that look plausible.
2. **Defensive overcoding**: redundant null checks, try/catch blocks around safe operations, dead branches.
3. **Subtle invariant violations**: code that compiles, passes happy-path tests, but breaks on edge cases.
4. **Secret leakage**: example code with real-looking API keys, hardcoded credentials in "demo" sections.
5. **CVE-laden suggestions**: dependencies suggested without version pinning or vulnerability awareness.
6. **Test theater**: tests that exercise the happy path, claim coverage, but do not actually verify behavior.

Existing tooling addresses pieces but not the AI-specific composite:

| Tool | Covers | Misses |
|---|---|---|
| `gitleaks` | Secrets | No AI context, regex-only, no AST awareness |
| `cargo-audit` | Rust CVEs | Single-language, no other verification |
| `Codium` / `Qodo` | Test generation | Generates tests, doesn't verify what AI wrote |
| `Snyk` | CVEs + some IaC | SaaS-first, expensive, no AI focus |
| `cargo-mutants` | Mutation testing | Manual, no AI tie-in, opt-in friction |
| `eslint` / `clippy` | Style/lint | No AI awareness, no security/property focus |

**Shadow Auditor's wedge**: a single binary that knows it's looking at AI output, applies AI-specific heuristics, and chains existing best-of-breed verifiers (mutation, property, CVE) into one pipeline with one output format (SARIF).

### Positioning statement

> For developers who use AI coding assistants and need to verify the output before merging, Shadow Auditor is a Rust CLI that runs alongside your AI workflow to catch hallucinations, secrets, vulnerabilities, and untested invariants. Unlike linters that treat AI output as ordinary code, Shadow Auditor applies AI-specific detection and property generation. Unlike SaaS scanners, it runs locally, ships as a single binary, and integrates with GitHub Code Scanning via SARIF.

### Audience layers

1. **Solo developers using AI assistants** — Cursor/Claude Code/Copilot users who ship to GitHub. Free, install via `cargo install` or `brew`. Drives adoption.
2. **Open source maintainers receiving AI-generated PRs** — the contribution-quality crisis. PR comment integration is high-value here.
3. **Engineering teams with AI mandates** — companies pushing AI coding tools, need governance. Paid CI tier targets this.
4. **Security teams** — SARIF integration with GitHub Advanced Security, GitLab, Sonar makes this a checkbox tool for AppSec procurement. Enterprise deal layer (V2+).

### Competitive moat

- **AI provenance detection**: nobody else explicitly tags and prioritizes AI-generated code paths.
- **Composition over reinvention**: wrap `cargo-mutants`, vendor gitleaks rules, use `rustsec` — focus on integration polish, not building from scratch.
- **Single binary, zero config defaults**: runs in 30 seconds on a 50K-LOC repo with no setup.
- **SARIF-first output**: enterprise-ready from day one, not retrofitted.

---

## 2. Technical Architecture

### 2.1 High-level overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         shaudit CLI (Rust)                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   discover → detect → schedule → run verifiers → aggregate       │
│      │         │          │            │              │          │
│      ▼         ▼          ▼            ▼              ▼          │
│   git/fs    AI tag    parallelize    secrets         SARIF       │
│   walker    layer     by file        cve             JSON        │
│             (provenance)             hallucination   terminal    │
│                                      deadcode                    │
│                                      mutation                    │
│                                      property                    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Data flow

1. **Discover**: gather candidate files. Two modes:
   - `--full`: all tracked files matching language filter
   - `--diff [REF]`: only files changed since REF (default: `HEAD~1`); also extract changed line ranges per file.
2. **Detect**: tag each commit/file with AI provenance score (0.0–1.0) using heuristics from §3.2.
3. **Parse**: tree-sitter parse each file once, cache AST in memory.
4. **Schedule**: build a DAG of (file, verifier) tasks. Parallelize via `rayon`. Some verifiers (mutation) require exclusive cargo lock — these run on a serial queue.
5. **Run verifiers**: each emits zero or more `Finding` structs.
6. **Aggregate**: deduplicate, apply severity filters, sort by file/line.
7. **Render**: format output per `--format` flag.
8. **Exit**: status code per §6.4.

### 2.3 Workspace & crate structure

```
shadow-auditor/
├── Cargo.toml                    # workspace root
├── Cargo.lock
├── README.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── CHANGELOG.md
├── rust-toolchain.toml           # pin stable
├── .cargo/config.toml            # build profiles
├── deny.toml                     # cargo-deny config
├── crates/
│   ├── shaudit-cli/              # binary entry point (clap)
│   ├── shaudit-core/             # orchestration, Finding type, Verifier trait
│   ├── shaudit-discover/         # git diff + fs walker
│   ├── shaudit-detect/           # AI provenance
│   ├── shaudit-parse/            # tree-sitter wrappers, AST cache
│   ├── shaudit-config/           # config schema, loader, defaults
│   ├── shaudit-output/           # SARIF, JSON, terminal renderers
│   ├── verify-secrets/           # secret scanning
│   ├── verify-cve/               # vulnerability scanning
│   ├── verify-hallucination/     # nonexistent symbol/import detection
│   ├── verify-deadcode/          # unused function/branch detection
│   ├── verify-mutation/          # cargo-mutants wrapper
│   └── verify-property/          # proptest harness generator
├── data/
│   ├── secrets-rules.toml        # vendored gitleaks rules
│   └── ai-signatures.toml        # AI detection patterns
├── tests/
│   ├── integration/              # assert_cmd-based
│   ├── snapshots/                # insta snapshots
│   └── fixtures/                 # known-bad sample repos
├── docs/                         # mdbook source (or astro/starlight)
├── action/                       # GitHub Action composite
│   └── action.yml
└── .github/
    ├── workflows/
    │   ├── ci.yml
    │   ├── release.yml           # cargo-dist generated
    │   └── nightly.yml           # CVE db refresh
    └── ISSUE_TEMPLATE/
```

### 2.4 Dependency choices with justifications

| Category | Crate | Why |
|---|---|---|
| CLI | `clap` v4 (derive) | De facto standard; rich help/completion; alternatives (argh, gumdrop) lose on plugins. |
| Async | `tokio` | Required by `gix`, `reqwest`. Alternatives fragment ecosystem. |
| Parallel | `rayon` | Best for CPU-bound parallelism (file scanning). |
| Errors | `anyhow` (binary), `thiserror` (libs) | Standard split. |
| Logging | `tracing` + `tracing-subscriber` | Structured spans essential for audit tool dogfooding. |
| Config | `serde` + `toml` | TOML is the Rust ecosystem default; users already know `Cargo.toml`. |
| Serialization | `serde_json`, `postcard` | JSON for output; postcard for binary cache (compact, fast). |
| Git | `gix` (gitoxide) | Pure Rust → static musl link → single binary distribution. |
| Filesystem walk | `ignore` | Same crate ripgrep uses; honors `.gitignore`. |
| Parser | `tree-sitter` + grammar crates | Multi-language, incremental, GitHub-grade. |
| HTTP | `reqwest` (with `rustls`) | For OSV.dev API; avoid OpenSSL dep. |
| Terminal | `owo-colors`, `tabled`, `indicatif` | Color, tables, progress bars. No emoji defaults. |
| Testing | `cargo test`, `insta`, `assert_cmd`, `predicates`, `proptest` | Standard Rust CLI test stack. |
| SARIF | `serde_sarif` | Don't hand-roll v2.1.0 schema; the crate exists. |
| CVE | `rustsec`, OSV.dev REST | Native for Rust, REST for everything else. |
| Mutation | `cargo-mutants` (subprocess) | Don't reinvent; it's mature. |
| Property | `proptest` (generated harness) | We emit code that calls it, not depend at runtime. |
| Cross-compile | `cargo-zigbuild` | Zig-as-linker; better than `cross` (no Docker). |
| Release | `cargo-dist` | Saves 2–3 weeks of release engineering. |
| Lint/quality | `clippy`, `rustfmt`, `cargo-deny`, `cargo-audit` | Standard hygiene; eat your own dogfood. |

**Explicitly avoided**:

- `git2` (libgit2 binding — C dep complicates static linking)
- `cross` (Docker dep, slower than zigbuild for our matrix)
- `serde_yaml` (deprecated; we use TOML)
- `sled` (maintenance issues; if KV needed later, use `redb`)
- `actix`, `axum`, `tower-http` (no HTTP server in V1)
- `sqlx`, `diesel`, `rusqlite` (no DB in V1)

---

## 3. Core Subsystems

### 3.1 Discovery (`shaudit-discover`)

**Responsibilities**:

- Resolve paths from CLI args (`shaudit scan src/ tests/`)
- If `--diff [REF]`: invoke `gix` to compute changed paths and per-file line ranges
- Walk filesystem honoring `.gitignore`, `.shauditignore`, and config-level `exclude` patterns
- Filter by language (extension and shebang detection)
- Return `Vec<Candidate>` where `Candidate { path, language, changed_lines: Option<RangeSet> }`

**Key API**:

```rust
pub struct Candidate {
    pub path: PathBuf,
    pub language: Language,
    pub changed_lines: Option<RangeSet>, // None = full file
    pub commit_sha: Option<String>,      // last commit touching this file
}

pub trait Discoverer {
    fn discover(&self, opts: &DiscoverOpts) -> Result<Vec<Candidate>>;
}

pub struct DiscoverOpts {
    pub roots: Vec<PathBuf>,
    pub diff_ref: Option<String>,
    pub languages: Option<Vec<Language>>,
    pub exclude: Vec<glob::Pattern>,
    pub respect_gitignore: bool,
}
```

**Edge cases**:

- Detached HEAD: use working-tree-only diff
- Submodules: skip by default, opt-in via `--include-submodules`
- Symlinks: follow only if inside repo root
- Binary files: skip via content sniff (first 8KB heuristic)

### 3.2 Detection (`shaudit-detect`)

**Responsibilities**: assign each commit a `provenance_score: f32` ∈ [0, 1] indicating likelihood of AI authorship.

**Signal sources** (each contributes weighted score):

| Signal | Weight | Implementation |
|---|---|---|
| Commit message contains AI marker (`Generated with Claude`, `Co-Authored-By: Claude <noreply@anthropic.com>`, `Cursor`, `Copilot`) | 0.40 | Regex on commit message + trailers |
| Commit size > 500 LOC additions in single commit | 0.10 | gix log analysis |
| Time-of-day cluster anomaly (commits outside user's typical pattern) | 0.05 | Histogram of past 100 commits |
| Verbose docstring ratio > threshold | 0.10 | tree-sitter doc comment density |
| Defensive null check density > threshold | 0.10 | AST pattern match |
| "Comprehensive"/"robust"/"production-ready" comment frequency | 0.05 | String search in comments |
| Unused import ratio > threshold | 0.10 | AST symbol resolution |
| Function length distribution variance (AI tends to write longer, more uniform functions) | 0.10 | Statistical |

Weights sum to 1.0. Threshold for "AI-likely": `score >= 0.5`. Configurable.

**Mode**:

- `--ai-only`: scan only files in commits with `score >= threshold`
- `--ai-priority`: scan all but tag findings with provenance metadata; AI-tagged findings sorted first
- Default: tag and report, no filtering

**Limitations** (document explicitly):

- Cannot detect human-edited AI code with high confidence
- Heuristics will have ~70-80% recall, ~85-90% precision target
- Users can override per-file via `// shaudit:ai` or `// shaudit:human` markers

### 3.3 Verification pipeline (`shaudit-core`)

**The Verifier trait**:

```rust
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Stable identifier, e.g., "secrets", "cve", "hallucination"
    fn id(&self) -> &'static str;

    /// Human-readable description for help/docs
    fn description(&self) -> &'static str;

    /// Languages this verifier supports
    fn supported_languages(&self) -> &[Language];

    /// Concurrency hint: parallel-safe or serial-required
    fn concurrency(&self) -> Concurrency {
        Concurrency::Parallel
    }

    /// Run verifier on a candidate; return findings
    async fn verify(
        &self,
        candidate: &Candidate,
        ctx: &VerifyContext,
    ) -> Result<Vec<Finding>>;
}

pub enum Concurrency {
    Parallel,           // can run in parallel with anything
    SerialPerWorkspace, // requires exclusive cargo lock (e.g., mutation)
    SerialGlobal,       // requires exclusive process (rare)
}

pub struct VerifyContext<'a> {
    pub workspace_root: &'a Path,
    pub config: &'a Config,
    pub ast_cache: &'a AstCache,
    pub provenance: Option<f32>,
}

pub struct Finding {
    pub verifier_id: &'static str,
    pub rule_id: String,             // e.g., "secrets.aws-key"
    pub severity: Severity,
    pub message: String,
    pub location: Location,
    pub fix: Option<Fix>,            // optional autofix suggestion
    pub provenance_tag: Option<f32>, // AI score of the containing commit
    pub metadata: serde_json::Value,
}

pub enum Severity { Critical, High, Medium, Low, Info }

pub struct Location {
    pub path: PathBuf,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub snippet: Option<String>,
}
```

**Scheduler**:

- Build a list of `(Candidate, Box<dyn Verifier>)` pairs
- Group by `Concurrency` policy
- Parallel group → `rayon::join` or `futures::join_all` over a tokio runtime
- Serial groups → mutex-protected queue
- Per-verifier timeout (default 60s, configurable)

### 3.4 Output generation (`shaudit-output`)

Three renderers, each implementing:

```rust
pub trait Renderer {
    fn render(&self, findings: &[Finding], meta: &RunMeta, w: &mut dyn Write) -> Result<()>;
}
```

- `SarifRenderer` (default for CI)
- `JsonRenderer` (for tooling integration)
- `TerminalRenderer` (default for interactive use; auto-detects TTY)

Renderer choice via `--format sarif|json|terminal`, with auto-detection: if `stdout` is not a TTY and no flag, default to `json`.

---

## 4. Verifier Catalog

### 4.1 `secrets`

**Goal**: detect hardcoded secrets (API keys, tokens, private keys, credentials).

**Approach**:

- Vendor gitleaks `rules.toml` (MIT licensed, well-maintained)
- Apply regex per file
- AST context check: is the match inside a string literal? a comment? actual code?
- Shannon entropy threshold for high-entropy strings even without rule match (entropy > 4.5 over 20+ chars)
- Allowlist support via `.shauditignore` and inline `// shaudit:allow secrets`

**Why this beats raw gitleaks**:

- Tree-sitter context filters out 80%+ of false positives (e.g., `"AKIAIOSFODNN7EXAMPLE"` in a markdown code block is fine; in actual code it's a finding)
- AI-aware: AI tends to use plausible-looking demo keys that pass naive regex; entropy + context catches these

**Output**: `Finding` with `rule_id` like `secrets.aws-access-key`, severity `Critical` for confirmed credential patterns.

**Performance target**: 50K LOC in < 5 seconds.

### 4.2 `cve`

**Goal**: detect known-vulnerable dependencies.

**Approach**:

- For Rust: parse `Cargo.lock`, query `rustsec` advisory database (vendored, refreshed nightly via release pipeline)
- For Node: parse `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`, query OSV.dev REST API
- For Python: parse `requirements.txt`, `pyproject.toml`, `poetry.lock`, query OSV.dev
- For Go: parse `go.sum`, query OSV.dev
- Cache responses 24h locally in `.shaudit/cache/cve/`

**Output**: `Finding` per vulnerable dependency with CVE ID, fixed version, severity from advisory.

**AI-relevance**: AI assistants frequently suggest outdated dependency versions or fail to pin versions; this catches that drift.

### 4.3 `hallucination`

**Goal**: detect references to nonexistent symbols, imports, or APIs — a hallmark of AI hallucination.

**Approach** (Rust v1, others v1.1):

- Parse imports via tree-sitter
- For Rust: invoke `cargo check --message-format=json`, parse errors of kind `unresolved import` or `cannot find type/function`
- Cross-reference with `Cargo.toml` declared deps
- Flag any "use" or "::" path that doesn't resolve

For TypeScript/JavaScript:

- Use `tsc --noEmit --pretty false` and parse errors (V1.1)

For Python:

- Static AST walk + `importlib.util.find_spec` (V1.1)

**Output**: `Finding` with high severity; `rule_id` like `hallucination.unresolved-import`.

**Caveat**: this overlaps with the compiler. Value-add: groups errors by AI-attribution, surfaces them in SARIF with provenance tags, and runs even if `cargo check` is not in CI.

### 4.4 `deadcode`

**Goal**: identify code that is defined but never called/used — frequent AI artifact.

**Approach**:

- For Rust: parse `cargo check` warnings filtered for `dead_code` lint
- AST analysis for: defined-but-never-referenced functions, unreachable branches after `return`/`panic`, unused struct fields with `#[derive(...)]` artifacts
- Excludes pub items (public API can be unused internally)

**Output**: `Finding` severity `Low`. Not all dead code is bad; tagged for review.

### 4.5 `mutation`

**Goal**: identify weak test coverage by mutating code and checking if tests catch it.

**Approach**:

- Wrap `cargo-mutants` as subprocess
- Limit scope: only run on AI-tagged files by default (mutation is expensive)
- Parse JSON output, convert to `Finding` per surviving mutant
- Concurrency: `SerialPerWorkspace`

**Output**: `Finding` with `rule_id` like `mutation.surviving-mutant`, severity `Medium`. Include the mutated diff as `metadata`.

**Performance**: opt-in via `--deep` flag for non-AI files. Default: AI-tagged files only.

### 4.6 `property`

**Goal**: generate property-based tests for AI-generated functions and run them.

**Approach** (V1: Rust pure functions only):

- Identify pure-function candidates (no `&mut self`, no `unsafe`, no obvious IO)
- Generate `proptest` harness:
  - "Function does not panic on arbitrary input"
  - For functions returning `Option`/`Result`: "Function does not return ambiguous error/panic on common edge cases"
  - For `impl PartialEq + Clone`: "Cloning preserves equality"
  - For `Vec` operations: length-related invariants
- Write generated tests to `target/shaudit-generated/`
- Invoke `cargo test --test shaudit_generated`
- Parse failures, emit Findings

**Output**: `Finding` with `rule_id` like `property.panic-on-input`, severity `High` if panic found.

**V1.1 expansions**:

- TypeScript via `fast-check`
- Python via `hypothesis`
- More invariant categories (idempotence, monotonicity)

### Verifier backlog (post-V1)

- `complexity`: cyclomatic/cognitive complexity scoring of AI functions
- `license-compat`: SPDX license compatibility check across deps
- `iac-misconfig`: scan Terraform/Helm/Dockerfile for common misconfigurations
- `prompt-leak`: detect leaked system prompts in code (rare but high-impact)
- `model-versioning`: flag hardcoded model version aliases like `claude-3-5-sonnet-latest` in production code

---

## 5. Configuration System

### 5.1 Config file: `shaudit.toml`

```toml
# shaudit.toml — Shadow Auditor configuration

[general]
# Languages to scan
languages = ["rust", "typescript", "python"]

# Exit code behavior
fail_on_severity = "high"  # critical | high | medium | low | none
respect_gitignore = true

[discover]
# Paths to scan; default = ["."]
roots = ["src", "lib", "tests"]
exclude = ["**/vendor/**", "**/node_modules/**", "**/target/**"]

[detect]
# AI provenance detection
enabled = true
threshold = 0.5
mode = "tag"  # tag | filter | priority

[output]
# Default output format
format = "terminal"  # terminal | sarif | json
sarif_version = "2.1.0"

[verifiers.secrets]
enabled = true
entropy_threshold = 4.5
allowlist = []

[verifiers.cve]
enabled = true
cache_ttl_hours = 24

[verifiers.hallucination]
enabled = true

[verifiers.deadcode]
enabled = true

[verifiers.mutation]
enabled = false  # opt-in; expensive
ai_only = true   # only mutate AI-tagged files even when enabled

[verifiers.property]
enabled = true
ai_only = true
generated_dir = "target/shaudit-generated"

[ci]
# CI-specific overrides applied when CI=true env var detected
fail_on_severity = "medium"
format = "sarif"
output_path = "shaudit-results.sarif"
```

### 5.2 Config resolution precedence

1. CLI flags (highest)
2. Environment variables (`SHAUDIT_*`)
3. `.shaudit.toml` in current dir
4. `shaudit.toml` in workspace root
5. `~/.config/shaudit/config.toml` (user global)
6. Built-in defaults (lowest)

### 5.3 Init command

`shaudit init` writes a commented `shaudit.toml` with defaults, and a `.shauditignore` template.

---

## 6. CLI Specification

### 6.1 Command structure

```
shaudit [OPTIONS] <COMMAND>

Commands:
  scan      Scan files for AI-related issues (primary command)
  init      Initialize shaudit.toml and .shauditignore
  verifiers List available verifiers
  detect    Run only AI provenance detection (no verification)
  cache     Manage local caches (CVE, AST)
  version   Show version, build info, verifier versions
  help      Show help
```

### 6.2 `shaudit scan` flags

```
shaudit scan [OPTIONS] [PATHS]...

Discovery:
  --diff [REF]              Scan only files changed since REF (default HEAD~1)
  --staged                  Scan only staged changes
  --languages <LANGS>       Comma-separated language list
  --include-submodules      Include git submodules

Detection:
  --ai-only                 Scan only AI-tagged commits
  --ai-priority             Sort AI-tagged findings first (default)
  --no-detect               Skip AI provenance detection

Verifiers:
  --verifiers <IDS>         Comma-separated verifier IDs to run
  --skip <IDS>              Verifier IDs to skip
  --deep                    Enable mutation/property on all files (slow)

Output:
  -f, --format <FMT>        terminal | sarif | json [default: auto]
  -o, --output <PATH>       Write to file instead of stdout
  --severity <LEVEL>        Filter findings below severity
  --no-color                Disable terminal colors
  --quiet                   Only errors
  --verbose                 Detailed progress

Behavior:
  --fail-on <SEVERITY>      Exit non-zero if findings >= severity
  --timeout <SECONDS>       Per-verifier timeout
  --jobs <N>                Parallelism (default: num_cpus)
  --config <PATH>           Use specific config file
```

### 6.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no findings above `fail_on_severity` |
| 1 | Findings above `fail_on_severity` |
| 2 | Configuration error |
| 3 | Internal error (panic, unexpected I/O failure) |
| 4 | Verifier error (one or more verifiers crashed) |
| 130 | Interrupted (SIGINT) |

### 6.4 UX principles

- **No telemetry, ever** (V1). Documented in README and `--help`.
- **Progress bar** via `indicatif`, only when TTY and `--quiet` not set.
- **No interactive prompts** in `scan`. The tool is for CI; interactivity breaks pipelines.
- **Predictable output**: terminal output is structured (sections, tables); never log-vomit.
- **First-run experience**: if no config exists, run with sensible defaults and print a one-line hint about `shaudit init`.

---

## 7. Output Formats

### 7.1 SARIF v2.1.0

Primary CI format. Compliant with OASIS SARIF 2.1.0 spec. Each `Finding` maps to a SARIF `result`. The tool itself maps to `tool.driver` with semantic version. Each verifier is a `rule` under `tool.driver.rules`.

**Custom properties** under `result.properties`:

```json
{
  "shaudit": {
    "verifier_id": "secrets",
    "provenance_score": 0.85,
    "ai_likely": true,
    "commit_sha": "abc123..."
  }
}
```

This survives SARIF round-trips and is queryable in GitHub Code Scanning UI via filters.

### 7.2 JSON

Self-defined schema, semver-versioned via `$schema` field. More compact than SARIF, intended for `jq` / scripting.

```json
{
  "$schema": "https://shaudit.dev/schema/v1.json",
  "version": "1.0.0",
  "run": {
    "started_at": "2026-04-24T10:00:00Z",
    "duration_ms": 4523,
    "verifiers_run": ["secrets", "cve", "hallucination"],
    "candidates_scanned": 142
  },
  "findings": [
    {
      "verifier_id": "secrets",
      "rule_id": "secrets.aws-access-key",
      "severity": "critical",
      "message": "Possible AWS access key detected",
      "location": {
        "path": "src/config.rs",
        "start_line": 42,
        "end_line": 42,
        "snippet": "let key = \"AKIA...\";"
      },
      "provenance": { "score": 0.78, "ai_likely": true }
    }
  ]
}
```

### 7.3 Terminal

```
Shadow Auditor v0.1.0  ·  scanned 142 files in 4.5s

CRITICAL  src/config.rs:42        secrets.aws-access-key
          Possible AWS access key detected
          AI provenance: 78% (commit abc123)
          → let key = "AKIA...";

HIGH      src/parser.rs:89        hallucination.unresolved-import
          Cannot resolve `serde_yaml::from_str` — crate not in Cargo.toml
          AI provenance: 92% (commit def456)

MEDIUM    src/lib.rs:234          property.panic-on-input
          Generated property test failed: panic on empty input
          AI provenance: 88% (commit ghi789)

────────────────────────────────────────────────────────────
1 critical · 1 high · 1 medium · 0 low

Run with --verbose for full snippets, or --format sarif for CI.
```

---

## 8. Distribution

### 8.1 Channels

| Channel | Mechanism | Audience |
|---|---|---|
| `cargo install shaudit` | crates.io | Rust users, fastest |
| GitHub Releases (binaries) | cargo-dist | All users |
| Install script `curl shaudit.dev/install.sh \| sh` | bash | Generic Linux/macOS |
| Homebrew tap `lavescar/tap` | cargo-dist | macOS users |
| AUR package | Manual (you're a CachyOS user) | Arch/CachyOS |
| Nix flake | Manual | Nix users (vocal community) |
| Docker image | Multi-stage Dockerfile | CI users not on GitHub |
| GitHub Action `lavescar/shadow-auditor-action` | Composite action | GitHub CI users (default path) |

### 8.2 Build matrix

| Triple | Notes |
|---|---|
| `x86_64-unknown-linux-musl` | Primary Linux; static binary |
| `x86_64-unknown-linux-gnu` | Glibc fallback |
| `aarch64-unknown-linux-musl` | ARM Linux (Graviton, Pi 4+) |
| `x86_64-apple-darwin` | Intel Mac |
| `aarch64-apple-darwin` | Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows |

Built via `cargo-zigbuild` for Linux, native for macOS/Windows.

### 8.3 Versioning

- Semantic versioning strictly
- v0.x while pre-1.0 (CLI surface may change)
- v1.0 declared when:
  - 1000+ GitHub stars
  - 50+ active CI users
  - All planned V1 verifiers shipped
  - 6 months without breaking config changes

### 8.4 Release cadence

- Patch releases: as needed (bug fixes)
- Minor releases: every 4-6 weeks
- Nightly: built but not promoted, available via install script flag
- Yanked releases: documented in `CHANGELOG.md`

---

## 9. CI Integration (GitHub Action)

### 9.1 Composite action

`action/action.yml`:

```yaml
name: 'Shadow Auditor'
description: 'Verify what your AI just wrote'
branding:
  icon: 'shield'
  color: 'gray-dark'

inputs:
  version:
    description: 'shaudit version (default: latest)'
    default: 'latest'
  args:
    description: 'arguments passed to shaudit scan'
    default: '--diff --format sarif --output shaudit.sarif'
  upload-sarif:
    description: 'upload SARIF to GitHub Code Scanning'
    default: 'true'
  fail-on-findings:
    description: 'fail the workflow if findings above severity threshold'
    default: 'true'

runs:
  using: 'composite'
  steps:
    - name: Cache shaudit binary
      id: cache
      uses: actions/cache@v4
      with:
        path: ~/.shaudit/bin
        key: shaudit-${{ runner.os }}-${{ inputs.version }}

    - name: Install shaudit
      if: steps.cache.outputs.cache-hit != 'true'
      shell: bash
      run: |
        curl -fsSL https://shaudit.dev/install.sh | sh -s -- --version ${{ inputs.version }}

    - name: Run shaudit
      shell: bash
      run: shaudit scan ${{ inputs.args }}

    - name: Upload SARIF
      if: inputs.upload-sarif == 'true' && always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: shaudit.sarif
```

### 9.2 Example consumer workflow

```yaml
name: Shadow Auditor
on: [pull_request]

permissions:
  contents: read
  security-events: write  # for SARIF upload

jobs:
  shaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for diff
      - uses: lavescar/shadow-auditor-action@v1
        with:
          args: '--diff origin/main --ai-priority --format sarif --output shaudit.sarif'
```

### 9.3 PR comment integration (V1.1)

A separate optional step that reads the SARIF and posts a sticky PR comment summarizing findings. Useful where Code Scanning isn't enabled.

---

## 10. Landing & Documentation

### 10.1 Site stack

- **Astro 5+ with Starlight** — sub-10KB initial JS, MDX content, search built-in, dark mode default
- **Tailwind v4** — utility CSS, no design system to maintain
- **Hosting**: Cloudflare Pages (free, global edge, Git-deploy)
- **Analytics**: none in V1; if desired later, Plausible self-hosted on existing Hetzner

### 10.2 Site information architecture

```
shaudit.dev/
├── /                          # landing
├── /install                   # installation methods
├── /docs/                     # Starlight docs root
│   ├── getting-started/
│   ├── configuration/
│   ├── verifiers/
│   │   ├── secrets
│   │   ├── cve
│   │   ├── hallucination
│   │   ├── deadcode
│   │   ├── mutation
│   │   └── property
│   ├── ci/
│   │   ├── github-actions
│   │   ├── gitlab-ci
│   │   └── self-hosted
│   ├── output-formats/
│   ├── ai-detection/
│   └── reference/
├── /blog/                     # technical posts (launch + monthly)
├── /changelog                 # auto-generated from CHANGELOG.md
└── /sponsors                  # GitHub Sponsors link (V1.1+)
```

### 10.3 Landing page structure

1. **Hero**: tagline + 30-second screencast (asciinema or vhs)
2. **Install command** (one line, copy button)
3. **3-pillar feature row**: AI detection · Security verification · Property generation
4. **Code sample**: `before` (raw AI output with hidden bug) → `shaudit scan` → `after` (annotated finding)
5. **Comparison table**: Shadow Auditor vs gitleaks vs Codium vs cargo-audit (with "+ Shadow Auditor" framing — composes, doesn't replace)
6. **Community/social proof** (deferred to v1.1; populate as it grows)
7. **Footer**: GitHub, docs, blog, sponsor

### 10.4 Doc principles

- Every verifier page shows: what it detects, example finding, false-positive guidance, how to disable
- Every CLI flag documented with example
- Recipes section: "How to use with Claude Code", "How to use in monorepo", etc.
- Search-friendly headings (h2/h3 hierarchy)

---

## 11. 12-Week Implementation Schedule

> Hours assume 25 hr/week dedicated to shaudit alongside freelance work. Adjust if your % allocation is different (see Risk §13).

### Week 1 — Scaffolding (25h)

**Goal**: project compiles, `shaudit scan .` runs and prints "0 findings".

- Day 1 (4h): Day-0 verification tasks (§0). Reserve names. Domain purchase.
- Day 2 (4h): Workspace `Cargo.toml`, all crate skeletons with `lib.rs`/`main.rs` placeholders. CI: `ci.yml` with `cargo check`, `cargo test`, `clippy --deny warnings`, `rustfmt --check`.
- Day 3 (4h): `shaudit-cli` clap structure, all top-level commands stubbed.
- Day 4 (5h): `shaudit-config` schema + loader + tests with `insta` snapshots.
- Day 5 (4h): `shaudit-discover` filesystem walking with `ignore` crate; tests with fixture repos.
- Weekend (4h): write `README.md` skeleton (positioning, install placeholder, usage example, verifiers list).

**Deliverable**: `cargo run -- scan .` discovers files and prints count. CI green.

### Week 2 — Discovery + git diff (25h)

**Goal**: `shaudit scan --diff HEAD~1` returns correct changed files with line ranges.

- Day 1-2 (8h): `gix` integration; `Discoverer::discover` with diff support.
- Day 3 (4h): Edge cases (detached HEAD, no commits, fresh repo).
- Day 4 (4h): Tree-sitter setup for Rust, TypeScript, Python; `shaudit-parse` with AST cache.
- Day 5 (5h): Wire discover → parse → empty pipeline → output stub.
- Weekend (4h): integration tests with real-git fixtures via `gix-testtools`.

**Deliverable**: `shaudit scan --diff HEAD~3 --verbose` shows file list + AST parse success per file.

### Week 3 — secrets verifier + SARIF (25h)

**Goal**: first real value — secret detection with SARIF output.

- Day 1 (4h): Vendor gitleaks rules, build `verify-secrets` crate.
- Day 2 (4h): Regex matching + AST-context filter (string literal vs comment vs code).
- Day 3 (5h): Shannon entropy detector for high-entropy strings.
- Day 4 (4h): `Finding` type finalized; `serde_sarif` integration; SARIF renderer.
- Day 5 (4h): JSON renderer; terminal renderer with `owo-colors`.
- Weekend (4h): test against fixtures with known secrets; tune false positive rate.

**Deliverable**: `shaudit scan --format sarif --output report.sarif src/` works end-to-end. Manually upload to a test repo's GitHub Code Scanning; verify it renders correctly.

### Week 4 — CVE verifier + AI detection (25h)

**Goal**: vulnerability scanning across Rust/Node/Python; AI provenance tagging functional.

- Day 1-2 (8h): `verify-cve` — `rustsec` for Rust, OSV.dev REST for others. Cache in `~/.cache/shaudit/cve/`.
- Day 3 (4h): `shaudit-detect` — commit message parsing, time-of-day analysis, basic heuristics.
- Day 4 (4h): AST-based AI signal detection (verbose docstrings, defensive null patterns).
- Day 5 (5h): Provenance scoring aggregation; `--ai-only` and `--ai-priority` flags wired.
- Weekend (4h): test on real repos — your own LAVESCAR-TUI commits (mix of human and AI), validate detection accuracy.

**Deliverable**: `shaudit scan --ai-only --diff HEAD~10` correctly identifies AI commits and runs verifiers only on those.

### Week 5 — hallucination + deadcode (25h)

**Goal**: AI-specific verifiers that exploit cargo/tsc.

- Day 1-2 (8h): `verify-hallucination` for Rust — `cargo check --message-format=json` parsing, error categorization.
- Day 3 (4h): `verify-deadcode` for Rust — same source, different filter (`dead_code` lint).
- Day 4 (4h): Tree-sitter-based fallback hallucination detection (when cargo unavailable).
- Day 5 (5h): Cross-language stubs for hallucination (TypeScript via `tsc`, Python via `importlib`) — V1.1 detail flag.
- Weekend (4h): integration tests; tune severity defaults.

**Deliverable**: `shaudit scan` on a Rust repo with intentional unresolved imports flags them with high severity.

### Week 6 — mutation + property (25h)

**Goal**: the differentiator verifiers.

- Day 1-2 (8h): `verify-mutation` — wrap `cargo-mutants`, parse output, JSON conversion. Concurrency policy (SerialPerWorkspace).
- Day 3-4 (9h): `verify-property` — function signature analysis, `proptest` harness generation, run via `cargo test`.
- Day 5 (4h): `--deep` flag, performance budgets, timeout handling.
- Weekend (4h): self-test — run against shaudit's own codebase. Fix what it finds.

**Deliverable**: shaudit can find a real bug in its own code via its own verifiers. This is the dogfooding milestone.

### Week 7 — Release pipeline (25h)

**Goal**: distributable v0.1.0.

- Day 1 (4h): `cargo-dist init`, configure target matrix.
- Day 2 (4h): `cargo-zigbuild` for musl targets, test cross-compile locally.
- Day 3 (5h): Install script (`install.sh`), test on fresh Linux/macOS VMs.
- Day 4 (4h): Homebrew tap setup, AUR `PKGBUILD`, Nix flake.
- Day 5 (4h): First release: `v0.1.0`. Verify all install paths work.
- Weekend (4h): Documentation pass — every `--help` accurate, error messages clear.

**Deliverable**: `curl -fsSL https://shaudit.dev/install.sh | sh` installs working binary on Linux + macOS.

### Week 8 — GitHub Action (25h)

**Goal**: zero-config CI integration.

- Day 1 (4h): Composite action `action.yml`, input/output schema.
- Day 2 (4h): SARIF upload step, permissions documented.
- Day 3 (5h): Marketplace listing — icon, branding, README.
- Day 4 (4h): Test against 5 real public repos (small open-source Rust projects).
- Day 5 (4h): PR comment fallback prototype (for repos without Code Scanning).
- Weekend (4h): Action documentation, recipe page in docs.

**Deliverable**: Action published to Marketplace, working in 3 demo workflows in your own repos.

### Week 9 — Landing + docs (25h)

**Goal**: marketing-ready website.

- Day 1 (4h): Astro + Starlight setup, Cloudflare Pages deploy, domain bind.
- Day 2 (4h): Landing page hero + install + features.
- Day 3 (4h): Comparison table, code samples, `vhs`-recorded screencast.
- Day 4-5 (9h): Docs — every verifier page, configuration reference, getting started.
- Weekend (4h): SEO basics (meta tags, sitemap, robots.txt), accessibility check (axe).

**Deliverable**: shaudit.dev live, mobile-responsive, Lighthouse 95+ on all pages.

### Week 10 — Dogfooding + polish (25h)

**Goal**: 2 weeks of running in production-like conditions before launch.

- Run shaudit on every project you touch this week:
  - Lavescar-OS components
  - LAVESCAR-TUI
  - Ahmet Bey CRM (Symfony 6.4 — TypeScript Angular frontend gets scan)
  - Recai Bey kod tabanı
- Log every false positive, false negative, performance issue, UX paper cut
- Fix critical issues, defer minor to backlog
- Send beta builds to 5 trusted developers, collect feedback
- Begin building-in-public posts (X/Twitter, Mastodon, dev.to) — daily during week 10

**Deliverable**: v0.1.5 shipped with dogfood-driven fixes; 5 external beta testers giving feedback.

### Week 11 — Launch prep (25h)

**Goal**: everything aligned for launch day.

- Day 1 (4h): HN Show post draft. Title: "Show HN: Shadow Auditor — verify what your AI just wrote (Rust)". Body: problem statement (3 paragraphs), what it does (2 paragraphs), what's next (1 paragraph). Link to repo.
- Day 2 (5h): dev.to post: "I built Shadow Auditor because AI writes code faster than I can audit it" — narrative + technical deep dive + roadmap.
- Day 3 (4h): Lobste.rs post (technical, careful framing — that community is sensitive to self-promotion).
- Day 4 (4h): Reddit posts — r/rust, r/programming, r/devops. Different framing per sub.
- Day 5 (4h): Mastodon (#rust, #ai), Bluesky, X/Twitter thread.
- Weekend (4h): Final UAT pass; CHANGELOG.md polish; v0.2.0 release tagged.

**Deliverable**: All launch assets staged. Repo polished. README excellent.

### Week 12 — Launch & response (25h)

**Goal**: ship and respond.

- Tuesday or Wednesday, 9:00 ET (14:00 TR): HN Show submission.
- Stagger other channels 2-4 hours apart through the day.
- First 6 hours: triage every comment, every issue, every email.
  - Reply to every HN comment, even negative ones, with substance.
  - Issues filed → label, acknowledge, fix the easy ones same-day with patch releases (v0.2.1, v0.2.2).
- Day 2-3: blog posts go live; respond to dev.to comments.
- Day 4-5: post-mortem analysis — what hit, what didn't.
- Weekend: Plan v0.3.0 based on launch feedback.

**Deliverable**: Launch executed; first wave of users; backlog informed by real usage.

---

## 12. Success Metrics & Kill Criteria

### Tier 1 (must-hit by T+30 post-launch)

- 50+ GitHub stars
- 5+ external GitHub issues filed (signals real users, not just stars)
- 3+ blog/social mentions outside your own channels

If Tier 1 not hit at T+30: not catastrophe; extend launch push, refine positioning. Reassess at T+45.

### Tier 2 (should-hit by T+90 post-launch)

- 500+ GitHub stars
- 30+ active GitHub issues (signal of community pull)
- 10+ external repos using the GitHub Action (visible via dependency graph)
- 5+ unsolicited blog mentions
- 50+ email signups for V2 paid tier (proves monetization potential)

### Kill criteria (T+90)

If at T+90 you have:

- < 200 stars AND < 5 external CI users AND < 1 blog mention

…then the wedge isn't working. Options:

1. **Pivot positioning**: same tool, reposition as "modern multi-language linter". Drop the AI angle if it's not resonating. Retain the verifier engine.
2. **Pivot audience**: target enterprise AppSec teams directly (cold outreach, design partner program). Skip the developer-grassroots motion.
3. **Sunset**: open-source maintenance mode, harvest the engineering value into your portfolio, move to next idea. The plan was designed to make this option non-catastrophic — you'll have a published Rust tool, a production GitHub Action, a content site, and 90 days of building-in-public material regardless of outcome.

---

## 13. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Time allocation < 25h/week due to freelance load | High | High | Front-load Week 1-3 critical path; hold Week 10-12 sacred (no new client work). |
| Naming collision discovered post-Week 2 | Low | High | Day 0 verification mandatory before first commit. |
| `cargo-mutants` API breaks between versions | Medium | Medium | Pin specific version; regression test suite. |
| AI detection accuracy < 70% recall | Medium | Medium | Ship with explicit "best-effort" framing; manual override markers. |
| SARIF schema misimplementation rejected by GitHub | Low | High | Use `serde_sarif` (don't hand-roll); test upload Week 3 with throwaway repo. |
| Cross-compile failures on aarch64 | Medium | Low | `cargo-zigbuild` known-good; fallback to native runners. |
| Burnout by Week 8-10 | Medium | High | Weekly check-in with self; force days off; reduce scope before sacrificing quality. |
| Major competitor launches similar tool during development | Low | Medium | Monitor weekly; differentiator is composition (mutation+property+detect), hard to clone fast. |
| AI assistants change behavior, invalidating detection heuristics | Medium | Low | Heuristics modular; ship as data files, hot-updatable without binary release. |
| Launch-day HN front page miss | Medium | High | Stagger posts; have backup channels ready; product itself is the moat regardless of one launch. |

---

## 14. Open Decisions Log

These need explicit yes/no calls before execution:

1. **Final name**: `Shadow Auditor` confirmed; binary `shaudit` confirmed pending Day-0 availability check.
2. **License**: dual MIT/Apache-2.0 (Rust ecosystem norm; permissive enables adoption; V2 paid tier is a separate hosted service, not relicensing).
3. **MSRV**: stable - 2 versions. Today: 1.78. Reassess each minor release.
4. **Telemetry**: zero in V1, full stop. Documented prominently.
5. **First language coverage**: Rust + TypeScript + Python at v0.1.0. Go + Java added at v0.3.0+.
6. **Community channels**: GitHub Discussions for V1; consider Discord/Matrix only at 100+ active users.
7. **Funding model**: open-core. CLI + verifiers MIT/Apache forever. V2 hosted dashboard + enterprise audit pack as paid tier (unaffected by license).
8. **Time allocation commit**: you need to declare this. 25h/week target → 90-day plan. 15h/week → 150-day plan. Lower → reconsider scope.

---

## 15. V2 Roadmap (Post-Launch Monetization)

**Triggered when**: Tier 2 metrics hit at T+90, and email signups indicate willingness to pay.

### V2.0 — Hosted dashboard (T+120 to T+180)

- Web dashboard aggregating SARIF results across multiple repos
- Trend analysis: "AI-related findings per week, per repo"
- Team management, roles, single sign-on
- Stack: Axum + SQLite + Cloudflare Tunnel on existing Hetzner; Stripe billing; minimal SvelteKit/Qwik frontend
- Pricing: $19/mo solo, $99/mo team (5 seats), $499/mo org (25 seats)

### V2.1 — Enterprise on-prem (T+180+)

- Self-hosted Docker compose package
- Audit log immutability (signed log, append-only)
- LDAP/SAML SSO
- Air-gapped CVE database updates
- Pricing: annual contract, $5K-$50K depending on seats and support tier

### V2.2 — IDE plugins (parallel track)

- VS Code extension
- JetBrains plugin
- Neovim integration via LSP-like bridge
- Real-time inline annotations from same engine

### V2.3 — Specialized verifier marketplace

- Allow third-party verifiers as external binaries with a stable plugin protocol
- Curated list on shaudit.dev/verifiers
- Revenue share for premium verifiers (e.g., specialized industry compliance checks)

---

## 16. Appendix

### A. Workspace `Cargo.toml` template

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.78"
authors = ["Lavescar (Efe Aras) <efe@lavescar.com.tr>"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/lavescar/shadow-auditor"
homepage = "https://shaudit.dev"

[workspace.dependencies]
anyhow = "1"
thiserror = "2"
clap = { version = "4", features = ["derive", "env"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "fs", "process"] }
rayon = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
postcard = { version = "1", features = ["use-std"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
gix = { version = "0.66", default-features = false, features = ["max-performance-safe", "blocking-network-client"] }
ignore = "0.4"
tree-sitter = "0.22"
tree-sitter-rust = "0.21"
tree-sitter-typescript = "0.21"
tree-sitter-python = "0.21"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
owo-colors = "4"
tabled = "0.16"
indicatif = "0.17"
serde_sarif = "0.6"
rustsec = "0.30"
async-trait = "0.1"
glob = "0.3"

[workspace.dependencies.dev]
insta = { version = "1", features = ["yaml"] }
assert_cmd = "2"
predicates = "3"
proptest = "1"
tempfile = "3"

[profile.release]
lto = "fat"
codegen-units = 1
strip = true
opt-level = 3

[profile.dev.package."*"]
opt-level = 2  # speed up debug builds for tree-sitter etc.
```

### B. CLI cheatsheet (printable reference)

```
# Initialize in a new repo
shaudit init

# Scan everything (default verifiers, terminal output)
shaudit scan

# Scan only changes in current PR
shaudit scan --diff origin/main

# AI-tagged files only, prioritized output
shaudit scan --ai-only

# Full deep scan (mutation + property on everything)
shaudit scan --deep

# CI mode (SARIF, fail on high)
shaudit scan --format sarif --output report.sarif --fail-on high

# Specific verifiers
shaudit scan --verifiers secrets,cve

# Skip the slow ones
shaudit scan --skip mutation,property

# Just detect AI provenance, no verification
shaudit detect --diff HEAD~10

# Refresh CVE cache
shaudit cache refresh cve

# Check installation and verifier versions
shaudit version --verbose
```

### C. Useful crates reference (bookmarks for development)

- `clap`: <https://docs.rs/clap>
- `tree-sitter` Rust bindings: <https://docs.rs/tree-sitter>
- `gix`: <https://docs.rs/gix>
- `serde_sarif`: <https://docs.rs/serde_sarif>
- `rustsec`: <https://docs.rs/rustsec>
- `cargo-mutants`: <https://github.com/sourcefrog/cargo-mutants>
- `proptest` book: <https://proptest-rs.github.io/proptest/>
- SARIF v2.1.0 spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- OSV.dev API: <https://google.github.io/osv.dev/api/>
- gitleaks rules source: <https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml>
- cargo-dist: <https://opensource.axo.dev/cargo-dist/>
- cargo-zigbuild: <https://github.com/rust-cross/cargo-zigbuild>

### D. Daily standup template (for solo accountability)

```
date: YYYY-MM-DD
yesterday:
  - what shipped (commit SHAs or PR links)
today:
  - top 3 tasks, time-boxed
blockers:
  - anything stuck > 4h
mood: 1-10
energy: 1-10
freelance load this week: low | medium | high
```

Keep this in a `journal/` directory in the repo (gitignored), one file per day. At end of each week, scan for patterns. Mood/energy < 5 for 3+ days = enforced rest day.

---

## End of Plan

This document is a contract with future-you. Every architectural choice has a stated rationale. Every week has a deliverable. Every metric has a kill threshold.

**Three things to do before next conversation**:

1. Run the Day-0 name verification checklist.
2. Declare your weekly hour commitment honestly.
3. Skim §11 and flag any week where the scope feels unrealistic given known constraints (existing client deadlines, planned travel, etc.).

The next conversation produces: Week 1 task breakdown by hour, the actual `Cargo.toml` workspace file, scaffold for `shaudit-cli` and `shaudit-core`, and the first commit.
