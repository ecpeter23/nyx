# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-alpha] - 2025-06-28

### Added
- Experimental intra‑procedural CFG + taint analysis for Rust. Nyx now builds a control‑flow graph, applies data‑flow rules, and flags unsanitised Source → Sink paths (e.g. env::var → Command::new).
- O(1) node‑kind lookup via per‑language PHF tables for zero‑cost dispatch.
- Six unit tests covering conditionals, loops, sanitizers, and multiple sources.
- Debug channel target=cfg (use RUST_LOG=nyx::cfg=debug) to inspect generated graphs.

### Fixed
- Fixed a bug in the release pipeline where Windows was trying to call the zip, PowerShell doesn't have a zip command

## [0.1.1-alpha] - 2025-06-25

### Fixed
- Fixed a bug where the `scan --no-index` command would not respect the `max_results` config setting (#1)

### Added
- Integration tests covering indexing and scanning pipelines (#3, #4, #5, #8)

## [0.1.0-alpha] - 2025-06-25

### Added
- Initial alpha release of **Nyx** CLI tool
- Multi-language AST pattern scanning via `tree-sitter` for Rust, C/C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript
- `scan` command: filesystem walker, pattern execution, console output
- `index` command: build, rebuild, and status reporting of SQLite-backed index
- `list` command: list indexed projects with optional verbosity
- `clean` command: remove one or all project indexes
- Configuration system with `nyx.conf` (generated) and `nyx.local` (user overrides)
- Default severity levels: High, Medium, Low
- Unit tests for core modules (config, ext, project utils)
