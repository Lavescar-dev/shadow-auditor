# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Hafta 3 (secrets verifier + output finalization)

- `verify-secrets` crate: 218 gitleaks rules vendored (MIT attribution),
  tree-sitter AST context classifier (string-literal vs comment), Shannon
  entropy detector for strings not matching any rule, prose-filtering
  heuristic to avoid false positives on multi-line templates.
- Inline allowlist markers: `// shaudit:allow secrets` (wildcard) or
  `// shaudit:allow secrets.aws-access-token` (rule-specific).
- Async `Verifier` pipeline with tokio runtime and `futures::join_all`
  dispatch; `--verifiers <ids>` / `--skip <ids>` filtering; findings
  sorted by severity desc and path.
- SARIF v2.1.0 renderer upgrade: `tool.driver.rules[]` descriptor table,
  `result.properties.shaudit` with `verifier_id` / `provenance_score` /
  `ai_likely` / `metadata` fields, fully populated region / snippet.

### Added — Hafta 4 (CVE verifier + AI detection)

- `verify-cve` crate:
  - Rust: `rustsec` advisory-db + `Cargo.lock` parser, CVSS-based severity.
  - Node: `package-lock.json` (v2/v3) + `pnpm-lock.yaml` + `yarn.lock`.
  - Python: `poetry.lock` + `requirements.txt`.
  - Go: `go.sum`.
  - OSV.dev REST batch queries (up to 500 packages/chunk) with 24h
    filesystem cache at `~/.cache/shaudit/cve/<ecosystem>.json`.
- `shaudit-detect` full eight-signal provenance scoring (plan §3.2):
  commit message regex (0.40), commit size (0.10), time-of-day (0.05),
  verbose docstring ratio (0.10), defensive null density (0.10),
  marketing-comment aho-corasick (0.05), unused-import heuristic (0.10),
  function length variance (0.10). Weights sum to 1.0.
- Inline override markers: `// shaudit:ai` forces 1.0, `// shaudit:human`
  forces 0.0.
- CLI flags wired to detection:
  - `--no-detect` skips scoring entirely.
  - `--ai-only` filters candidates below `detect.threshold` before verify.
  - `--ai-priority` sorts findings by provenance score descending.

### Added — Hafta 1-2 (discover + parse)

- Workspace scaffold with seven crates: `shaudit-cli`, `shaudit-core`,
  `shaudit-discover`, `shaudit-detect`, `shaudit-parse`, `shaudit-config`,
  `shaudit-output`.
- Filesystem discovery via the `ignore` crate, honoring `.gitignore` and
  `.shauditignore`.
- Git diff-mode discovery (`shaudit scan --diff HEAD~1`) via `git`
  subprocess (pure-Rust gix swap deferred to a later milestone).
- Tree-sitter parsing for Rust, TypeScript, and Python, with a shared
  per-run AST cache.
- Configuration schema (`shaudit.toml`) with precedence loader and
  `shaudit init` to generate a commented template.
- CLI subcommands: `scan`, `init`, `verifiers`, `detect`, `cache`,
  `version`.
- GitHub Actions CI: `check`, `test`, `fmt`, `clippy`.

### Pending (Hafta 5–12)

- Verifiers: hallucination, deadcode, mutation, property.
- Release pipeline via `cargo-dist` + `cargo-zigbuild`.
- GitHub Action composite.
- Landing site at `audit.lavescar.com.tr`.
