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

## Planned

### v0.3.0 — Live monitoring & policy

- `agent-certify watch`: live monitoring of active sessions
  - Watch JSONL files as they're written
  - Recalculate graph topology every N seconds
  - Real-time anomaly alerts against baseline
  - Detect: new tool link, blast radius expansion, graph fragmentation
- `agent-certify suggest-policy`: auto-generate a draft policy from baseline
  - Human reviews and adds overrides: FORBIDDEN / REQUIRED
  - Policy violations → immediate CRITICAL alert
- MCP logs parser: aggregate logs from ~/.cache/claude-cli-nodejs/
- OTel trace parser: import OpenInference/Arize format spans
- Alert output: JSON webhook, stdout, file

### v0.4.0 — MCP server & self-scan

- agent-certify as an MCP server
  - Any MCP-compatible agent can scan its OWN topology
  - `claude mcp add agent-certify agent-certify mcp`
  - Tool: `scan_my_topology` → returns FI, anomalies, blast radius
  - Tool: `check_policy` → returns violations
- Kill switch recommendation: "isolate node X, keep the rest running"
- OTel export: emit spans for each scan/anomaly/violation
- Cursor agent-trace parser

### v0.5.0 — Multi-framework parsers

- CrewAI parser: task execution logs → AgentGraph
- LangGraph parser: graph state transitions → AgentGraph
- AutoGen parser: message history → AgentGraph
- Unified parser auto-detection: detect format, pick the right parser
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
