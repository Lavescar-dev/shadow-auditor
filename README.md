# Shadow Auditor

> Verify what your AI just wrote.

[![CI](https://github.com/Lavescar-dev/shadow-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Lavescar-dev/shadow-auditor/actions/workflows/ci.yml)

Shadow Auditor is a Rust CLI that audits AI-generated code. It detects
hallucinated imports, hardcoded secrets, known-vulnerable dependencies, and
untested invariants — in one static binary, with SARIF output for GitHub Code
Scanning.

**Status:** `v0.1.0-wip`. Hafta 1–4 complete: workspace scaffold, discovery
+ tree-sitter parsing, **secrets verifier** (218 gitleaks rules + AST context
+ entropy), **CVE verifier** (rustsec + OSV.dev across Rust/Node/Python/Go),
**AI provenance scoring** (8 signals, weighted sum). Remaining verifiers
(hallucination, deadcode, mutation, property) land in Hafta 5–6. See
[`shaudit-plan.md`](./shaudit-plan.md) for the full 12-week plan.

### Third-party attributions

- Vendored gitleaks default rules (MIT) — see [`LICENSE-GITLEAKS`](./LICENSE-GITLEAKS).

## Why another audit tool?

AI coding assistants ship code at unprecedented speed. The bottleneck has
shifted from *writing* to *verifying*. Generic linters and secret scanners
don't know they're looking at AI output — Shadow Auditor does:

- **Hallucination detection** — unresolved imports and nonexistent symbols,
  with cross-ref against declared dependencies.
- **Secret + CVE scanning** — vendored gitleaks rules with AST context, OSV.dev
  and `rustsec` for dependency advisories.
- **Property + mutation testing** — auto-generated `proptest` harnesses and a
  `cargo-mutants` integration for AI-tagged files.
- **AI provenance scoring** — commit- and file-level scoring to prioritize
  findings in AI-authored code.

## Install (planned)

```bash
# Rust users
cargo install shaudit

# Generic Linux / macOS
curl -fsSL https://audit.lavescar.com.tr/install.sh | sh
```

v0.1.0 is not yet published to crates.io — follow the repo for the first
release.

## Usage

```bash
# Scan everything under the current directory
shaudit scan

# Scan only files changed since origin/main
shaudit scan --diff origin/main

# AI-tagged files only, SARIF output for CI
shaudit scan --ai-only --format sarif --output shaudit.sarif

# Specific verifiers
shaudit scan --verifiers secrets,cve

# Initialize a config file
shaudit init
```

See `shaudit scan --help` for the full flag reference.

## Layout

```
crates/
├── shaudit-cli/          # binary entry point (clap)
├── shaudit-core/         # Finding, Verifier trait, Severity
├── shaudit-discover/     # fs walker + git diff (gix)
├── shaudit-detect/       # AI provenance scoring (Hafta 4)
├── shaudit-parse/        # tree-sitter + AST cache
├── shaudit-config/       # shaudit.toml schema + loader
└── shaudit-output/       # terminal, JSON, SARIF renderers
```

## Development

```bash
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

CI runs all four on every push and PR.

## License

Dual-licensed under MIT or Apache-2.0. See [`LICENSE-MIT`](./LICENSE-MIT) and
[`LICENSE-APACHE`](./LICENSE-APACHE).
