# agent-certify — Roadmap

Structural verification of multiagent systems.

## Released

### v0.1.0 — MVP (Oct 2026)

- Claude Code JSONL parser (sessions + sub-agents)
- AgentFIScanner: Fragility Index on agent communication graphs
- BlastRadiusAnalyzer: impact analysis per node
- AgentCertificate: Ed25519-signed structural baseline
- Drift detection: PASS/FAIL against a certified baseline
- HTML visualization with interactive graph
- CLI: scan, blast, keygen, certify, verify
- 27 tests, 92% coverage

### v0.2.0 — Learn & Detect (Oct 2026)

- `agent-certify learn`: auto-generate statistical baseline from N sessions
- Anomaly detection: compare any session against the learned baseline
  - New tool never seen → CRITICAL
  - New communication link → WARNING
  - FI deviation (z-score) → WARNING/CRITICAL
  - Error rate deviation → WARNING/CRITICAL
  - Sub-agent count anomaly → WARNING/CRITICAL
- Perspective-based node classification:
  - Engineering: KEYSTONE / LOAD-BEARING / PERIPHERAL
  - Risk: HIGH RISK / MODERATE RISK / LOW RISK
  - Compliance: UNRESTRICTED / BOUNDED / LOGGED
  - Monitoring: WATCH / TRACK / IGNORE
- 64 tests, 94% coverage

### v0.3.0 — Live monitoring & policy (Oct 2026)

- `agent-certify watch`: live monitoring of active sessions
  - Follows a session JSONL (and its sub-agent transcripts) as it's written
  - Plain size polling every `--interval` seconds; rescans only when the session grew
  - Waits for a file that doesn't exist yet; skips half-written lines
  - Reports new nodes, baseline anomalies and policy violations once each, as they appear
  - `--scans N` / `--duration S` to stop on its own; given a directory, watches the newest session
- Policy engine: `forbidden_tool`, `forbidden_link`, `max_sub_agents`, `required_tool`
  - Glob patterns (`agent:* → *database*`), matched on node id, agent type or name
  - Reported separately from anomalies by `scan` and `watch`
- `agent-certify suggest-policy`: draft policy from the baseline (REQUIRED tools, sub-agent caps)
  - Human adds FORBIDDEN rules; never overwrites an edited policy without `--force`
- MCP logs parser: Claude Code's per-server logs (`claude-cli-nodejs/Cache/<project>/mcp-logs-*`)
  - `scan --include-mcp` / `learn --include-mcp`; joined to the session by `sessionId`
  - Surfaces calls Claude Code makes on its own (IDE `getDiagnostics`), absent from transcripts
- Certificates compare sub-agents by type (`agent:Explore`), not per-spawn id
  - Pre-v0.3 certificates keep id comparison and their signatures stay valid
- 114 tests, 94% coverage

### v0.4.0 — MCP server & self-scan (Oct 2026)

- agent-certify as an MCP server: any MCP-compatible agent can scan its own topology
  - `agent-certify mcp`; `claude mcp add agent-certify -- agent-certify mcp`
  - Bare stdio JSON-RPC 2.0 (protocol 2024-11-05 to 2025-06-18), no `mcp` package
  - Tools: `topology_summary` (plain language, written for the agent), `scan_topology`,
    `blast_radius`, `check_anomalies`, `check_policy`
  - Finds the current session itself (`CLAUDE_CODE_SESSION_ID`, then the cwd's project)
  - Tool failures come back as readable `isError` results; the server never crashes
- OTel export: one `agent_certify.scan` span per scan, anomalies and violations as events
  - OTLP/JSON lines (Collector `otlpjsonfile`-compatible), no OpenTelemetry SDK
  - `scan --otel`, `watch --otel` (span per cycle), `--otel-stdout` for piping
- Cursor Agent Trace parser (code provenance: models → files written)
- Format auto-detection from content (Claude Code transcript, Agent Trace, MCP log)
- License headers (SPDX) on every source file
- 154 tests, 94% coverage

## Planned

### v0.5.0 — Multi-framework parsers

- Carried over from v0.3.0 / v0.4.0:
  - OTel trace parser: import OpenInference/Arize format spans
  - Alert output: JSON webhook
  - Kill switch recommendation: "isolate node X, keep the rest running"
- CrewAI parser: task execution logs → AgentGraph
- LangGraph parser: graph state transitions → AgentGraph
- AutoGen parser: message history → AgentGraph
- Extend auto-detection to the new parsers
- Cross-session trending: FI over time, tool usage patterns

### v0.6.0 — Fleet & dashboard

- Fleet mode: scan multiple projects/systems, aggregate results
- Dashboard: HTML/web view of all monitored systems
- Alerting integrations: Slack, email, PagerDuty webhooks
- Baseline drift over time: is the system's topology evolving?

### v1.0.0 — Production-ready

- API frozen with semantic versioning
- Published on PyPI
- Comprehensive documentation
- Published benchmarks across agent frameworks
- Compliance reporting mapped to NIST AI RMF (MANAGE 1.3, 4.1)
- Integration guide for CI/CD pipelines
- HuggingFace Space: upload a trace, see your agent graph

## Research directions

- Correlation between FI and actual agent failures
- Optimal graph topology for resilient multiagent systems
- Structural signatures of compromised agents
- Triangle density as a measure of agent coordination quality
- Paper: "Structural Fragility of Multiagent Systems"

## Links

- [sal-torch](https://pypi.org/project/sal-torch/) — structural analysis of AI models
- [sal-certify](https://cognitive-engineering.dev/sal-certify) — structural AI certification
- [cognitive-engineering.dev](https://cognitive-engineering.dev)

Built by [Cognitive Engineering](https://cognitive-engineering.dev) (Switzerland).
License: BSL 1.1.
