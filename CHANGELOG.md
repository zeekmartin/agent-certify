# Changelog

All notable changes to agent-certify are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- CI on GitHub Actions: tests on Ubuntu and Windows × Python 3.10–3.12, ruff, wheel build and install check
- Release workflow: tag `vX.Y.Z` → tests, PyPI upload, GitHub Release with these notes
- Pre-release workflow: tag `vX.Y.ZrcN` / `aN` / `bN` → TestPyPI, then an install check
- Issue templates, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, this changelog

### Changed
- `pyproject.toml` license metadata uses an SPDX expression (`LicenseRef-BSL-1.1`) and `license-files`;
  the license itself is unchanged

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

[Unreleased]: https://github.com/zeekmartin/agent-certify/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/zeekmartin/agent-certify/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zeekmartin/agent-certify/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zeekmartin/agent-certify/compare/da44351...v0.2.0
[0.1.0]: https://github.com/zeekmartin/agent-certify/commit/da44351
