# Changelog

All notable changes to agent-certify are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- License switched from BUSL-1.1 to Apache-2.0 (open source)

## [0.5.0] - 2026-10-27

Fixes for the security audit of 2026-10-27 (45 findings). Items marked
**breaking** change behaviour that scripts may rely on.

### Security
- MCP server: path arguments are confined to `~/.claude/projects` and the working directory after
  resolving symlinks and `..`; environment variables are never expanded; responses and errors no longer
  contain resolved paths, file contents or exception text (SEC-001, SEC-005)
- MCP server: no machine-wide fallback when no session is named; only the current project (PRV-001, **breaking**)
- MCP server: 30 s limit per request; failures logged on stderr with a correlation id (SEC-006, OBS-001)
- `verify` requires `--public-key`; unsigned certificates fail unless `--allow-unsigned` (warns); the key
  embedded in a certificate is never trusted (SEC-002, **breaking**)
- Certificates carry `not_before` / `not_after` (90 days by default, `--validity-days`) checked by `verify`
  (`--ignore-expiry`), and can be bound to a system with `--expect-system-id` (SEC-004)
- Signed bytes are domain-separated (`agent-certify/cert/v1\0`) with a fixed-point `fi_score`; pre-v0.5
  certificates still verify, reported as legacy (SEC-008)
- Strict type and range validation when loading certificates, baselines, policies and graphs; NaN and
  Infinity rejected; generic error messages (SEC-007, SEC-005)
- `keygen` creates the private key atomically with mode 600 and never follows a symlink; `certify` warns
  about a key readable by others (SEC-003)
- Parsers skip and count malformed, deeply nested (RecursionError) or oversized (> 10 MB) lines; directory
  scans are bounded in depth (5) and file count (1,000) (SEC-006)
- HTML report escapes `<`, `>` and `&` in its embedded JSON (SEC-009)
- `scripts/demo.py` writes its certificate to an unpredictable temporary file (SEC-010)

### Added
- `scan --fail-on critical|warning|never`: exit 2 on findings at or above the level; `critical` is the
  default (FUN-001, **breaking**: previously always 0)
- Policy evaluated per session for directory scans in every format, with a VIOLATIONS column (FUN-002)
- `skipped_records` in graphs, scan results, JSON, OTel spans and certificates, with a warning above 5%
  (OBS-002)
- `watch` reads every format the auto-detecting parser supports (FUN-005)
- CI: tests on Ubuntu and Windows × Python 3.10–3.12 with a 90% coverage floor, ruff (including the
  flake8-bandit `S` rules), pip-audit, wheel build and install check
- Release workflow: tag `vX.Y.Z` → tests, PyPI Trusted Publishing with attestations (API token fallback),
  GitHub Release with these notes; pre-release tags go to TestPyPI
- Issue templates, CONTRIBUTING, SECURITY (with a threat model), CODE_OF_CONDUCT, this changelog

### Changed
- Scanner: articulation points by Tarjan's algorithm and FI per removed node computed incrementally; a
  3,000-node graph scans in under a second (the previous algorithm made one full graph copy and one dense
  n×n matrix product per node), with identical results (PRF-001)
- Blast radius reuses the scan's triangle structure instead of a full scan per node (PRF-002)
- Graph edges indexed by (source, target) with adjacency sets (PRF-003)
- `verify` reports a reason whenever the topology hash differs, and detects nodes whose kind changed (FUN-003)
- Path handling centralised in `agent_certify.paths` (MNT-001); the version is defined once, in
  `agent_certify.__version__` (MNT-002)
- MCP `scan_topology` accepts the `classic` perspective in its schema (COD-001)
- SPDX identifier `BUSL-1.1` in every source file and in `pyproject.toml`; LICENSE covers all versions
  (LIC-002, LIC-003). The license itself is unchanged
- GitHub Actions pinned by commit SHA; CI tools pinned by version (CIC-002); TestPyPI installs never resolve
  dependencies from TestPyPI (CIC-003)
- `.agent-certify/` is created with a `.gitignore`; `*.html` reports are ignored by this repository (PRV-002)

### Known limitations
- `watch` re-parses the whole session on every change (PRF-004); incremental reading is planned
- Baselines and policies are not signed (ARC-001); private keys are stored unencrypted (see SECURITY.md)

## [0.4.0] - 2026-10-27

### Added
- MCP server: agent-certify exposes 5 tools via Model Context Protocol
  - scan_topology, check_anomalies, blast_radius, check_policy, topology_summary
  - Auto-detects current session via CLAUDE_CODE_SESSION_ID
  - Setup: `claude mcp add agent-certify -- agent-certify mcp`
- OTel export: emit OpenTelemetry spans for scans and anomalies (`--otel`)
- Cursor agent-trace parser (provenance graph from .agent-trace files)
- Auto-detect input format from the content (Claude Code transcript, Cursor Agent Trace, MCP log)
- SPDX license headers on all source files

## [0.3.0] - 2026-10-27

### Added
- `agent-certify watch`: live monitoring of active sessions
- `agent-certify suggest-policy`: auto-generate policy from baseline
- Policy engine: FORBIDDEN (tool, link), REQUIRED, MAX_SUB_AGENTS rules
- MCP logs parser: enrich graphs with MCP server tool calls (`--include-mcp`)
- `learn --include-mcp` for MCP-aware baselines

### Fixed
- Certificates now compare sub-agents by type, not by unique id

## [0.2.0] - 2026-10-27

### Added
- `agent-certify learn`: auto-generate statistical baseline from N sessions
- Anomaly detection: new tools, FI deviation, error rate, sub-agent count
- Perspective-based node classification (engineering, risk, compliance, monitoring)
- KEYSTONE / LOAD-BEARING / PERIPHERAL labels (engineering perspective)

## [0.1.0] - 2026-10-27

### Added
- Claude Code JSONL parser (sessions + sub-agents)
- AgentFIScanner: Fragility Index on agent communication graphs
- BlastRadiusAnalyzer: impact analysis per node
- AgentCertificate: Ed25519 signed structural baseline
- Drift detection (certify + verify)
- HTML visualization with interactive graph
- CLI: scan, blast, keygen, certify, verify

[Unreleased]: https://github.com/zeekmartin/agent-certify/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/zeekmartin/agent-certify/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/zeekmartin/agent-certify/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zeekmartin/agent-certify/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zeekmartin/agent-certify/compare/da44351...v0.2.0
[0.1.0]: https://github.com/zeekmartin/agent-certify/commit/da44351
