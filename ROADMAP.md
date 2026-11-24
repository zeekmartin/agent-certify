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

### v0.5.0 — Security audit fixes (Oct 2026)

Fixes the actionable findings of the 2026-10-27 security audit (45 findings: 3 high, 14 medium,
22 low, 6 info).

- MCP server hardened against untrusted (possibly prompt-injected) tool arguments
  - Paths confined to `~/.claude/projects` and the working directory; symlinks and `..` resolved first
  - Environment variables never expanded; no resolved path, file content or exception text in replies
  - No machine-wide session fallback; 30 s limit per tool call; failures logged with a correlation id
- Certificate trust model
  - `verify` requires the issuer's public key; unsigned certificates fail unless `--allow-unsigned`
  - Validity window (`not_before` / `not_after`, 90 days by default) and `--expect-system-id`
  - Domain-separated signed bytes, strict type validation, NaN rejected; older certificates still verify
  - `keygen` writes the private key atomically with mode 600, never through a symlink
- Hostile logs: malformed, deeply nested or oversized lines skipped and counted (`skipped_records`);
  directory scans bounded in depth and file count
- `scan --fail-on critical|warning|never` (exit 2); policy evaluated per session in every format
- Performance: Tarjan articulation points and incremental FI deltas (identical results; a 3,000-node
  graph in under a second), blast radius without per-node scans, indexed edges
- CI: SHA-pinned actions, pinned tools, pip-audit, ruff security rules, 90% coverage floor,
  Trusted Publishing with attestations (API token fallback)
- SPDX `Apache-2.0` everywhere; LICENSE covers all versions; SECURITY.md threat model
  - (v0.5.0 shipped BSL 1.1 headers; the project moved to Apache 2.0 before any release that
    distributed them, and `LICENSE`, `pyproject.toml` and every source header now agree)
- 279 tests, 95% coverage (Ubuntu and Windows, Python 3.10–3.12)

### v0.5.1 — Ergonomics (Oct 2026)

- Files with no readable records exit 1 with a clear message instead of an empty report
- One warning per file for unreadable records; `keygen` default file name; `verify` usage hint

### v0.6.0 — Baseline decisions (Nov 2026)

- `baseline accept/reject --tool`, scoped `accept --link "agent:A -> tool"`, `baseline show`
- Decisions survive `learn`; last write wins; rejection beats a scoped link
- `learn --forget-overrides` drops them on purpose

### v0.6.1 — Multi-framework parsers and anomaly injection benchmark (Nov 2026)

- CrewAI parser: execution logs and event bus → AgentGraph
- LangGraph parser: event stream, debug stream and plain transition records → AgentGraph
- Auto-detection extended to both, `.json` included
- Anomaly injection benchmark: detection rate, false positive rate, false negative rate and blind
  spots, per fault type; `python -m agent_certify.benchmark`
- Baseline learned from held-out sessions (`learn_holdout`), so the false positive rate means
  something
- Measured and published one blind spot rather than hiding it: no check read call *volume*

### v0.7.0 — Call volume and network destinations (Nov 2026)

- Call volume detection, per tool and per link — the blind spot the v0.6.1 benchmark measured and
  reported for a release
- Network destination monitoring: `seen_domains`, `accept`/`reject --domain`, `new_domain` and
  `rejected_domain` checks; `SECURITY.md` §6 states what is read, stored and transmitted
- Benchmark at seven fault types: 36/36 detected on the six covered ones, no false positives, and
  one blind spot still measured (`shell_domain`: a host named inside a shell command argument)
- Fixes the 2026-11-03 audit (33 findings: 3 high, 7 medium, the rest low or info)

### v0.8.0 — Egress (Nov 2026)

Where an agent's data goes, and how much of it. agent-certify itself still makes no network
connection: everything here is read from the logs and decided offline.

- Shell command egress: hosts named inside a shell command (`curl`, `wget`, `scp`, `ssh`, `nc` …)
  are destinations, including inside the command a shell wrapper or an `ssh` runs (INV-001) — the
  `shell_domain` blind spot v0.7.0 shipped and measured. Two blind spots take its place, both
  measured: `shell_var_domain` and `ssh_tunnel_domain`; reading either would mean evaluating the
  shell rather than parsing it
- Exfiltration: outbound volume per destination, learned in the baseline and compared like call
  volume (`egress_volume_spike`), with an absolute floor under both volume checks, and no scan
  limit dropping a destination in silence (`destination_scan_truncated`). A fourth blind spot is
  measured in its place: `file_upload_exfil`, a file whose size the log does not contain
- Region policy: `forbidden_region`, decided offline from the host name — the 249 assigned ccTLDs,
  7 exceptions and 61 internationalised ccTLDs — or from an optional local IP-geolocation
  database; no DNS lookup unless `--resolve-dns` says so, and never from the MCP server
- Certificates carry a signed `egress` section (`cert_format` 3), and `certify` refuses to sign a
  system that already breaks its own egress rules. Formats 1 and 2 keep their signed bytes
- Five classes of egress false negative the 2026-11-24 audit found, each of which produced no
  destination, no truncation and no warning at all: internationalised names (EGR-001), schemes and
  clients beyond the web, object storage, resolvers and database clients included (EGR-002),
  numeric address spellings (EGR-003) and commands substituted into an assignment (EGR-005). The
  filename-label list is pinned to the day it was last checked against the DNS root (EGR-004)
- The rest of the 2026-11-24 audit: a version that matches the format it writes (INT-001), a third
  `verify` exit code for egress coverage nobody can check (CRY-001), a certificate with no
  validity window refused (CRY-003), revocation named as a property of the trust model (CRY-002),
  an in-flight cap on the MCP server (MCP-001), `--hash-project` and the data a report carries
  named in the documents (PRV-001), a CI matrix of 3.10 – 3.14 with classifiers to match
  (CFG-001/002), tested dependency floors with a `lowest` CI job (SCA-002), Beta status (DOC-001)
  and GeoIP attribution (LIC-001)
- Benchmark at 22 fault types: detection 100.0% (108/108) among covered types; 85.7% (108/126) of
  all injected faults, the three blind spots in the denominator; 0 false positives. Both rates are
  reported together, never one alone (INT-002)
- `SECURITY.md` updated in the same change for every new category of input read

## Planned

### v0.9.0 — Provenance

- Benchmark against published traces of multi-step tool attacks, run before provenance ships so the
  number has a "before"
- **AgentDojo parser and benchmark**: AgentDojo's published attack traces as an input, and its
  suites run against the detectors, so the detection rate rests on traces this project did not
  write as well as on its own injections
- Provenance: link untrusted content (a fetched page, an e-mail, a document) to the actions it
  triggers — the prompt injection path
- **Revocation (CRY-002)**: a signed list of certificate ids an issuer no longer stands behind,
  read from disk like every other input — no endpoint, no network call. Today a signed certificate
  is valid until it expires and nothing can call it back; `SECURITY.md` §2 states that as a
  property of the trust model and gives the procedure until then (destroy the key, re-issue, and
  shorten `--validity-days` for anything that leaves the organisation)
- **Dependency pinning (SCA-002)**: a hash-pinned lock file for the development and CI
  environments. The other half of this finding shipped in v0.8.0: the `lowest` CI job installs the
  declared floors exactly under Python 3.10, runs the suite against them and runs `pip-audit` on
  that resolution (informational), so the floor is tested rather than asserted
- **Raising the floors is a release step (SCA-002)**: each release re-reads what the oldest
  tested versions should be — `cryptography` ships a major series every few months — and raises
  `numpy` and `cryptography` in `pyproject.toml` together with the `lowest` job that pins them.
  The floors are deliberately low enough to install on a frozen corporate image, which means they
  go stale by design unless someone moves them on purpose
- **Region determination, the deferred half of the region findings (REG-001, REG-002)**: a ccTLD
  is a registration and not a location, so a `.com` served from anywhere is `unknown` unless an
  address database places it, and the strength of a determination (`cctld`, `cctld_idn`, `geoip`,
  `dns+geoip`) is reported but never scored; and the region tables are dated snapshots
  (`NOT_HOSTS_CHECKED`, `IDN_CCTLD_CHECKED`, both 2026-11-24) that go stale unless something
  re-checks them against the IANA root zone. Both are declared limits today rather than fixed ones
- **Destination fingerprints in the certificate**: a certificate that has to leave the
  organisation can carry a salted hash of each observed destination instead of the host name, so
  `verify` keeps checking coverage — today the choice is the names or nothing
  (`--omit-observed-destinations`, which is what makes `verify` exit 3)
- **Cooperative cancellation in the MCP server**: the long analyses check a cancellation flag at
  their natural boundaries, so a timed-out or `notifications/cancelled` request stops instead of
  being abandoned to run to the end. v0.8.0 caps the damage (`MAX_INFLIGHT`) rather than fixing it:
  Python cannot kill a thread
- **Call volume normalised by session length**: 40 `Read` calls in a ten-minute session and in a
  six-hour one are not the same observation, and the baseline currently compares the raw count,
  which makes a long session look anomalous and a short one look quiet

### v0.10.0 — Standard telemetry input

- OTel trace parser: GenAI semantic conventions and OpenInference/Arize spans as an input, not only
  an export
- AutoGen parser: message history → AgentGraph

### Carried over

- Kill switch recommendation: "isolate node X, keep the rest running"
- Cross-session trending: FI over time, tool usage patterns, baseline drift
- Open items from the v0.5.0 audit:
  - Signed baselines and policies (ARC-001)
  - Encrypted private keys (passphrase, PKCS#8) and a revocation list (SEC-003, SEC-004)
  - Dependency lock / constraints for CI and releases (SCA-001, SCA-002)
  - Incremental `watch` from the last file offset (PRF-004)
  - Fuzz tests for the parsers; secret scanning in CI (TST-003, SCR-001)
- Open items from the 2026-11-03 audit:
  - Extract report formatting out of `cli.py` and `describe` out of `mcp_server.py` (MNT-003)
  - Version-counter invalidation for the edge index instead of `(id, len)` (COD-012)
- Dynamic coverage and test-count badges fed by the measurement, not written by hand (DOC-007)

### v1.0.0 — Production-ready

- API frozen with semantic versioning
- Comprehensive documentation
- Published benchmarks across agent frameworks
- Compliance reporting mapped to NIST AI RMF (MANAGE 1.3, 4.1)
- Integration guide for CI/CD pipelines
- HuggingFace Space: upload a trace, see your agent graph

## Paid editions

Fleet view, dashboard, alerting, advanced policies, compliance reports, SSO and
supported service belong to the Enterprise and Cloud editions, not to this
roadmap; see [Editions](README.md#editions). The open-source tool loses nothing
to them.

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
License: Apache 2.0.
