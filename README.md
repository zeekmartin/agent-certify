# agent-certify

[![CI](https://github.com/zeekmartin/agent-certify/actions/workflows/ci.yml/badge.svg)](https://github.com/zeekmartin/agent-certify/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-certify)](https://pypi.org/project/agent-certify/)
[![Python](https://img.shields.io/pypi/pyversions/agent-certify)](https://pypi.org/project/agent-certify/)
[![Downloads](https://img.shields.io/pypi/dm/agent-certify)](https://pypi.org/project/agent-certify/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-306%20passed-brightgreen)]()

Structural verification of multiagent systems.

Scan any multiagent system's communication topology.
Find structural single points of failure before they're exploited.

## Install

```bash
pip install agent-certify
```

The only dependencies are `numpy` and `cryptography`. The MCP server, the
OpenTelemetry export and the Cursor parser need nothing else (the `[mcp]`,
`[otel]`, `[cursor]` and `[all]` extras exist but are empty).

## Let your agent scan itself (MCP server)

agent-certify runs as an MCP server, so an agent can check its own structure
while it works:

```bash
claude mcp add agent-certify -- agent-certify mcp
```

or in an MCP client's settings:

```json
{
  "mcpServers": {
    "agent-certify": {"command": "agent-certify", "args": ["mcp"]}
  }
}
```

| Tool | What it returns |
|---|---|
| `topology_summary` | a plain-language health check, written for the agent to read about itself |
| `scan_topology` | FI, nodes, links, bridges, articulation points, every node's role (`perspective` picks the vocabulary) |
| `blast_radius` | what a compromised or failed `node` reaches, and whether the system fragments |
| `check_anomalies` | anomalies against `.agent-certify/baseline.json` (or `baseline_path`) |
| `check_policy` | violations of `.agent-certify/policy.json` (or `policy_path`) |

Every tool takes an optional `session_path`. Without it the server finds the
**current** session: `CLAUDE_CODE_SESSION_ID` (Claude Code sets it for the
processes it starts), then the newest session of the working directory's
project. It never falls back to another project's sessions. A real
`topology_summary` from this repository's own development session:

> Your current session has 12 nodes (1 orchestrator, 10 tools, the human) and
> 11 links. Fragility Index is 1.0 — every connection is a single point of
> failure with no backup path. The orchestrator (claude) is the sole keystone:
> if it fails, the system fragments into 11 isolated pieces. Most-used tool:
> Bash (97 calls, 8 failed). Overall 2.9% of 278 tool calls failed. No
> anomalies detected against the baseline of 25 sessions. No policy
> violations. This is the usual shape of a single-agent session — one
> orchestrator calling each tool directly; redundancy only appears when
> sub-agents share tools.

The server speaks MCP over stdio (newline-delimited JSON-RPC 2.0, protocol
versions 2024-11-05 to 2025-06-18) without the `mcp` package. A tool that
cannot run (no baseline yet, unknown node, missing session) returns a normal
result with `isError: true` and a message saying what to do; protocol errors
are JSON-RPC errors; nothing a request does stops the server.

Tool arguments come from an AI agent, which may be following injected
instructions, so the server treats them as untrusted. Path arguments
(`session_path`, `baseline_path`, `policy_path`) expand `~` but never
environment variables, are resolved (symlinks, `..`), and must lie inside
`~/.claude/projects` or the server's working directory; anything else gets
"Path not allowed". Responses and errors never contain a resolved path, file
contents or exception text: unexpected failures are logged with their
traceback on stderr and reported with a correlation id. Each request is limited
to 30 seconds.

## Quick start

```python
from agent_certify import ClaudeCodeParser, AgentFIScanner, BlastRadiusAnalyzer

# Parse a Claude Code session
parser = ClaudeCodeParser()
graph = parser.parse("~/.claude/projects/-home-user-project/session.jsonl")

# Scan structural fragility
scanner = AgentFIScanner(graph)
result = scanner.scan()
print(f"Fragility Index: {result.fi:.4f}")
print(f"Bridges: {len(result.bridges)}")
print(f"Critical nodes: {result.node_classifications}")

# Blast radius if 'bash' tool is compromised
blast = BlastRadiusAnalyzer(graph)
report = blast.analyze("bash")
print(f"Direct impact: {len(report.direct_impact)} nodes")
print(f"System fragmented: {report.system_fragmented}")
```

## CLI

```bash
agent-certify scan ~/.claude/projects/                       # every session, plus a merged graph
agent-certify scan ~/.claude/projects/<project>/<session>.jsonl
agent-certify scan <path> --format json|markdown|html [-o FILE]
agent-certify scan <path> --perspective engineering|risk|compliance|monitoring
agent-certify blast ~/.claude/projects/ --node bash

# Baseline and anomaly detection
agent-certify learn ~/.claude/projects/C--dev-myproject/     # writes .agent-certify/baseline.json
agent-certify learn s1.jsonl s2.jsonl s3.jsonl --output ./my-baseline.json
agent-certify scan session.jsonl                             # compares against ./.agent-certify/baseline.json if present
agent-certify scan session.jsonl --baseline path/to/baseline.json
agent-certify scan session.jsonl --no-baseline

# Policy: explicit rules, drafted from the baseline, edited by a human
agent-certify suggest-policy                                 # writes .agent-certify/policy.json
agent-certify scan session.jsonl                             # also checks ./.agent-certify/policy.json if present
agent-certify scan session.jsonl --policy path/to/policy.json   # or --no-policy

# Live monitoring
agent-certify watch ~/.claude/projects/C--dev-myproject/     # newest session in the project
agent-certify watch path/to/session.jsonl --interval 10 --perspective risk

# MCP server logs as a second data source
agent-certify scan session.jsonl --include-mcp

# OpenTelemetry spans (OTLP/JSON)
agent-certify scan session.jsonl --otel                      # appends to .agent-certify/traces.jsonl
agent-certify scan session.jsonl --otel-stdout | <collector> # spans on stdout, report on stderr
agent-certify watch ... --otel                               # one span per scan cycle

# Other formats are detected from the content
agent-certify scan path/to/repo/.agent-trace/                # Cursor Agent Trace

# Structural baseline and drift detection
agent-certify keygen ~/keys/signing.key                      # mode 600; keep it outside the repository
agent-certify certify <path> --key ~/keys/signing.key -o system.cert.json   # valid 90 days (--validity-days)
agent-certify verify system.cert.json <path> --public-key signing.key.pub   # exit 1 on drift
#   --public-key is required: it is the issuer's key, obtained out of band
#   --expect-system-id ID   --ignore-expiry   --allow-unsigned (skips the signature check; warns)

# In CI: scan exits 2 when a finding reaches --fail-on (critical by default)
agent-certify scan session.jsonl --fail-on warning           # or critical (default), never
```

Node names are matched case-insensitively: `--node bash` finds `tool:Bash`.

## What it measures

The **Fragility Index (FI)** measures the proportion of 
communication links in your multiagent system that have 
no structural backup path.

- **FI = 0**: Fully redundant — every path has an alternative
- **FI = 1**: Fully fragile — every link is a single point of failure
- **Bridges**: edges whose removal disconnects the system

FI is computed on the agent communication graph using triangle 
participation analysis. The same structural measure is used by 
[sal-torch](https://pypi.org/project/sal-torch/) on transformer 
attention graphs (published at PPAM 2026, Springer LNCS).

## Node classification and perspectives

Each node is removed in turn and FI recomputed. That gives every node one
structural **level**:

- **high**: removing this agent/tool raises system FI by ≥ 10% (relative), or
  the node is an articulation point (removing it disconnects the system)
- **medium**: raises FI by 2–10%
- **low**: raises FI by less than 2%, or lowers it

A **perspective** names the levels for the people reading the report. The
measurement is the same under every perspective; only the words (and the
colours in the HTML view) change.

| Perspective | high | medium | low | Use it when |
|---|---|---|---|---|
| `engineering` (CLI default) | KEYSTONE | LOAD-BEARING | PERIPHERAL | designing or refactoring the agent architecture |
| `risk` | HIGH RISK | MODERATE RISK | LOW RISK | threat modelling, security review |
| `compliance` | UNRESTRICTED | BOUNDED | LOGGED | audits, access reviews, regulatory reports |
| `monitoring` | WATCH | TRACK | IGNORE | deciding where to point runtime alerts |
| `classic` | CRITICAL | BUFFER | IMMUNE | v0.1 labels; the Python API default |

```python
result = AgentFIScanner(graph, perspective="risk").scan()
result.node_classifications        # {"claude": "HIGH RISK", ...}
result.node_levels                 # {"claude": "high", ...}
result.labels("compliance")        # same result, other vocabulary
```

## Baselines

`agent-certify learn` reads N past sessions and records what normal looks like:

- mean ± std of FI, node count, link count, bridge count, sub-agent count and
  error rate (errors / tool calls), plus FI's range and the most sub-agents seen
- every tool seen, and the fraction of sessions it appears in
- every invocation link seen (`source -> target`)

Sub-agent ids are unique per spawn, so links are recorded by role: a sub-agent
counts as `agent:<type>` (`agent:Explore`, `agent:general-purpose`). Standard
deviations are population deviations, so a baseline learned from one session
has std 0.

The baseline is saved to `.agent-certify/baseline.json` in the current
directory (`--output` to change). `scan` picks it up from there automatically.
The baseline is optional: without one, `scan` behaves exactly as without
anomaly detection.

```python
from agent_certify import AgentFIScanner, AnomalyDetector, BaselineLearner

learner = BaselineLearner()
baseline = learner.learn(["~/.claude/projects/C--dev-myproject/"])
learner.save(baseline)

report = AnomalyDetector(baseline).detect(graph, AgentFIScanner(graph).scan())
report.has_critical
print(report)
```

## Anomaly detection

| Check | Flags | Severity |
|---|---|---|
| `new_tool` | a tool never seen in the baseline | critical |
| `new_link` | an invocation path never seen (links to a new tool are not repeated) | warning |
| `fi_deviation` | FI more than 2σ from the mean | warning; critical past 3σ when FI *rose* |
| `error_rate` | error rate more than 2σ *above* the mean | warning; critical past 3σ |
| `sub_agents` | more sub-agents than ever seen, or 2σ above the mean | warning; critical when above the max *and* past 3σ |
| `node_count` | node count more than 2σ from the mean | info; warning past 3σ |

- **critical**: something structurally new or a large move toward fragility. Look now.
- **warning**: a structural change worth a look; often explained by the task.
- **info**: unusual but benign on its own.

A falling FI means added redundancy (usually sub-agents sharing tools). That is
a structural change, not a risk in itself, so it never goes past warning. When
the baseline never varied on a metric (std 0), z is undefined: any difference
is reported with no z-score at the lower severity.

For a directory, `scan` lists the anomaly count of each session in the
session table.

## Example workflow

```bash
# 1. Learn what normal looks like from the last few weeks of sessions
agent-certify learn ~/.claude/projects/C--dev-myproject/

# 2. Scan a new session; anomalies print above the node table
agent-certify scan ~/.claude/projects/C--dev-myproject/<new-session>.jsonl

# 3. Triage with the vocabulary your team uses
agent-certify scan <new-session>.jsonl --perspective monitoring --format html -o review.html
```

```
Fragility Index  0.3103   (9/29 links with tri(e)=0; baseline: 0.98 ± 0.09)

⚠  ANOMALIES DETECTED (8):

[CRITICAL] Sub-agents: 3 (baseline: 0.04 ± 0.20, max seen 1)
           Types: agent:Explore, agent:general-purpose

[WARNING]  New communication path: claude -> agent:Explore
           Baseline: not among 35 known links

[WARNING]  FI deviation: 0.31 (baseline: 0.98 ± 0.09, z = -7.8)
           Sub-agents detected — shared tools add triangles; structural change expected
...
```

## Blast radius

`BlastRadiusAnalyzer.analyze(node)` reports:

- **direct_impact**: 1-hop neighbours. A compromised tool can steer its caller
  through poisoned results, so spread is measured in both directions.
- **total_reachable**: everything within 3 hops (`hops=` to change).
- **accessible_tools**: tools the node can invoke itself or through the agents
  it spawns (follows call direction).
- **remaining_fi / system_fragmented**: structure after isolating the node.
  "Fragmented" means isolation splits the system into more pieces than it had.

## Certificates and drift

An `AgentCertificate` is a signed (Ed25519) structural baseline: the nodes, the
directed invocation links, FI and node roles. `graph_hash` covers the topology
only, not call counts. `verify(graph)` names each change: new agent types, new
tool links, links that disappeared, FI movement, role changes. A topology change
can be detected before the behaviour it enables shows up.

Sub-agents are compared by **type**, not by their per-spawn id: a session that
spawns a fresh `Explore` agent for the same tools matches a certificate issued
for another `Explore` agent. A different type is reported as such:

```
New agent type: agent:Research (not in certified baseline)
Missing agent type: agent:Explore (was in certified baseline)
```

Certificates issued before v0.3 have no `identity` field; they keep comparing
agents by id, and their signatures remain valid.

### Trust model

A signature proves something only when it is checked against a key you
already trust. `verify` therefore **requires** the issuer's public key
(`--public-key`, or `public_key=` in Python), obtained through a trusted
channel. The `signer_public_key` written inside a certificate is informational
only: whoever can edit the certificate can replace it. A certificate fails
verification when it is unsigned, signed by another key, edited after
signing, outside its validity window, or issued for another system
(`--expect-system-id`). `--allow-unsigned` skips the signature check
explicitly and prints a warning; use it only for local experiments.

Since v0.5 every certificate carries `not_before` / `not_after` (90 days by
default, `--validity-days`), so an older, more permissive certificate cannot be
replayed indefinitely. Certificates from earlier versions have no validity
window; they still verify, with a warning, and should be re-issued.

The signed bytes are `b"agent-certify/cert/v1\x00"` followed by the
certificate as JSON with sorted keys, compact separators, ASCII escaping and
`fi_score` written as a 10-place decimal string; see `certificate.py` for the
exact rules. Older certificates keep their original encoding, and the format
is part of what is signed, so a certificate cannot be downgraded.

Keys: `agent-certify keygen` creates the private key with mode 600 and refuses
to overwrite an existing file or follow a symlink. `certify` warns when the key
is readable by other users. On Windows the file inherits the folder's ACL, so
keep keys in a folder only you can read. Never commit a key; `*.key` is in
`.gitignore`.

## Policy

Anomalies say *this is unusual*. A policy says *this is not allowed* (or *this
must be there*), whatever the statistics. A session can have both, and `scan`
reports them separately.

```json
{
  "rules": [
    {"kind": "forbidden_tool", "target": "deploy_production", "severity": "critical", "message": "No agent may deploy to production"},
    {"kind": "forbidden_link", "target": "agent:* → *database*", "severity": "critical", "message": "Sub-agents may not reach the database"},
    {"kind": "max_sub_agents", "target": "5", "severity": "warning", "message": "More than 5 sub-agents is unusual"},
    {"kind": "required_tool", "target": "Bash", "severity": "warning", "message": "Bash is expected in every session"}
  ],
  "generated_from": "baseline (25 sessions)",
  "created_at": "2026-10-27T20:00:00Z"
}
```

| kind | target | violated when |
|---|---|---|
| `forbidden_tool` | tool pattern | a matching tool is used |
| `forbidden_link` | `"source → target"` (or `->`) | a matching invocation link exists |
| `max_sub_agents` | integer | more sub-agents than that |
| `required_tool` | tool pattern | no matching tool is used |

Patterns are shell-style globs (`*`, `?`), case-insensitive, matched against a
node's id (`tool:Bash`), type (`agent:Explore`) and name (`Bash`). `agent:*`
matches every sub-agent; a bare name matches exactly (`deploy` does not match
`deploy_production`; `deploy*` does).

`agent-certify suggest-policy` drafts a conservative policy from the baseline:
tools seen in every session become REQUIRED (warning), and the sub-agent count
is capped at the baseline maximum + 1 (warning) and + 3 (critical). FORBIDDEN
rules are an organisational decision, so the draft never contains any; add
them by hand. `suggest-policy` refuses to overwrite an existing policy file
(which may hold your edits) without `--force`.

## Live monitoring

`agent-certify watch` follows a session while Claude Code writes it. Given a
project directory it picks the most recently modified session. Every
`--interval` seconds (default 30) it checks whether the transcript or any of
its sub-agent transcripts grew; if so it re-parses, rescans and prints:

```
Watching C:\Users\me\.claude\projects\H--agent-certify\c603eabc-….jsonl (every 5s, Ctrl+C to stop)
Baseline: loaded (25 sessions)
Policy: loaded (4 rules)
────────────────────────────────────────────────────────────
[11:35:02] Nodes: 7   Links: 6   FI: 1.0000   Calls: 192
  [CRITICAL] POLICY VIOLATION: FORBIDDEN tool used: Edit
[11:35:07] Nodes: 7   Links: 6   FI: 1.0000   Calls: 192
[11:35:27] Nodes: 7   Links: 6   FI: 1.0000   Calls: 196
[11:35:37] Nodes: 7   Links: 6   FI: 1.0000   Calls: 197
[11:35:52] Nodes: 7   Links: 6   FI: 1.0000   Calls: 200
```

(A real run on this repository's own development session, with a demo policy
that forbids `Edit`.)

Each anomaly (critical and warning) and each policy violation is printed once,
when it first appears, and again only if its severity changes. A session file
that does not exist yet is waited for; a half-written last line is skipped
until it is complete. It uses plain size polling, no file-system notification
library. `--scans N` stops after N scans; in Python, `SessionWatcher(...)`
takes `on_anomaly` / `on_policy_violation` callbacks and has `stop()`.

## MCP server logs

Claude Code also logs every MCP server connection, one JSONL file per server
and process start:

| Platform | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\claude-cli-nodejs\Cache\<project>\mcp-logs-<server>\*.jsonl` |
| Linux | `~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/*.jsonl` |
| macOS | `~/Library/Caches/claude-cli-nodejs/<project>/mcp-logs-<server>/*.jsonl` |

Records are `{"timestamp", "sessionId", "cwd", "debug" | "error"}`; tool calls
appear as `Calling MCP tool: <tool>` and failures as `Tool '<tool>' failed …`.
These logs include calls Claude Code makes **on its own**, such as the IDE
server's `getDiagnostics` after an edit, which never appear in the transcript.

`--include-mcp` (or `MCPLogsParser().enrich(graph)`) adds the calls whose
`sessionId` matches the session, as `claude → tool:mcp__<server>__<tool>`. A
tool the transcript already shows keeps its node, and calls already counted
there are not counted twice. The logs do not say which agent made a call, so
all of them are attributed to the orchestrator. No logs (no MCP servers, or a
platform without the cache) is not an error: the graph is returned unchanged.

## OpenTelemetry

`--otel` turns every scan into one span, `agent_certify.scan`, with the
structural metrics as attributes (`agent_certify.fi`, `.node_count`,
`.edge_count`, `.bridge_count`, `.sub_agent_count`, `.anomaly_count`, ...).
Anomalies and policy violations become span events (`anomaly.new_tool`,
`policy_violation.forbidden_tool`, ...). A critical anomaly or any policy
violation sets the span status to ERROR.

Spans are OTLP/JSON, one `{"resourceSpans": [...]}` object per line: the
layout the OpenTelemetry Collector's `file` exporter writes and its
`otlpjsonfile` receiver reads, so a collector can forward them to Jaeger,
Grafana Tempo, Datadog and so on. All scans of one session share a trace id,
so a `watch` run appears as one trace with a span per cycle. No OpenTelemetry
SDK is needed.

## Cursor Agent Trace

[Agent Trace](https://agent-trace.dev) (github.com/cursor/agent-trace) records
**which code was written by AI and which by humans**: files, line ranges and
contributors (`human`, `ai` with a `model_id`, `mixed`, `unknown`), usually in
`.agent-trace/traces.jsonl`. It does not record tool calls, MCP servers or
sub-agents, so the graph is a provenance graph:

- the producing tool (`cursor`) is the orchestrator, linked to each model (`agent:<model_id>`)
- each contributor links to the files it wrote (`file:<path>`), weighted by lines

That graph is bipartite (contributors on one side, editor and files on the
other) and has no triangles, so **FI is always 1.0** for it. The useful views
are blast radius (which files a model touched), policy rules such as
`{"kind": "forbidden_link", "target": "agent:* → file:infra/*"}` and anomaly
detection (a new model, new files touched).

Formats are detected from the content, not only the extension:
`.agent-trace/traces.jsonl` is routed to the Cursor parser although it ends in
`.jsonl`. A directory is scanned for every supported format: Claude Code
sessions, `.agent-trace/` folders and `*.agent-trace` files (MCP server logs are
left out; they enrich sessions via `--include-mcp`).

## How Claude Code sessions map to graphs

| Log content | Graph |
|---|---|
| the main transcript's assistant | `claude` (orchestrator) |
| prompts typed by the person | `human` → `claude` |
| `tool_use` blocks | caller → `tool:<name>` (shared across agents) |
| `Agent` / `Task` calls (or any call with `subagent_type`) | caller → `agent:<id>` |
| `<session>/subagents/agent-<id>.jsonl` | that agent's own tool calls |
| `tool_result` with `is_error: true` | error count on the edge and the tool |

Streamed messages repeat `tool_use` blocks, so calls are de-duplicated by id.
Claude Code transcripts and MCP logs are read line by line; a Cursor
`.agent-trace` file of up to 50 MB is read whole (it may be a single JSON
document), larger ones line by line. Lines that cannot be read — malformed,
nested too deeply, or longer than 10 MB — are skipped and counted: the count
appears in the scan report, in JSON (`skipped_records`), in OTel spans and in
certificates, with a warning when more than 5% of a session's records were
skipped. A directory scan reads at most 1,000 session files and walks at most
5 folder levels.

A session without sub-agents is a star (one orchestrator, many tools) and has
FI = 1 by construction. Structure becomes informative once sub-agents share
tools: each shared tool closes a triangle with the orchestrator.

## Supported systems

- [x] Claude Code (JSONL logs from ~/.claude/)
- [x] Claude Code MCP server logs (`--include-mcp`)
- [x] Cursor Agent Trace (code provenance; `.agent-trace/`)
- [ ] CrewAI (planned)
- [ ] LangGraph (planned)
- [ ] AutoGen (planned)
- [ ] OTel traces (planned)

New sources subclass `agent_certify.parser.BaseParser` and return an `AgentGraph`.

## Links

- [sal-torch](https://pypi.org/project/sal-torch/) — structural analysis of AI models
- [sal-certify](https://cognitive-engineering.dev/sal-certify) — structural AI certification
- [cognitive-engineering.dev](https://cognitive-engineering.dev)

---

**agent-certify** is built by [Cognitive Engineering](https://cognitive-engineering.dev) (Switzerland).
License: [Apache 2.0](LICENSE).

[![sal-torch](https://img.shields.io/pypi/v/sal-torch?label=sal-torch)](https://pypi.org/project/sal-torch/)
[![sal-certify](https://img.shields.io/badge/sal--certify-cognitive--engineering.dev-ffbf00)](https://cognitive-engineering.dev/sal-certify)
