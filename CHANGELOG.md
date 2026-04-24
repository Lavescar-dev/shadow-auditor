# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Workspace scaffold with seven crates: `shaudit-cli`, `shaudit-core`,
  `shaudit-discover`, `shaudit-detect`, `shaudit-parse`, `shaudit-config`,
  `shaudit-output`.
- Filesystem discovery via the `ignore` crate, honoring `.gitignore` and
  `.shauditignore`.
- Git diff-mode discovery via `gix` (`shaudit scan --diff HEAD~1`).
- Tree-sitter parsing for Rust, TypeScript, and Python, with a shared
  per-run AST cache.
- Configuration schema (`shaudit.toml`) with precedence loader and
  `shaudit init` to generate a commented template.
- Rendering scaffolds for terminal, JSON, and SARIF v2.1.0 output.
- CLI subcommands: `scan`, `init`, `verifiers`, `detect` (stub), `cache`
  (stub), `version`.
- GitHub Actions CI: `check`, `test`, `fmt`, `clippy`.

### Pending (Hafta 3–12)

- Verifiers: secrets, cve, hallucination, deadcode, mutation, property.
- AI provenance scoring with 8 signal sources.
- Release pipeline via `cargo-dist` + `cargo-zigbuild`.
- GitHub Action composite.
- Landing site at `audit.lavescar.com.tr`.
