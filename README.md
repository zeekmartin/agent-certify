# agent-certify

Structural verification of multiagent systems.

Scan any multiagent system's communication topology.
Find structural single points of failure before they're exploited.

## Install

```bash
pip install agent-certify
```

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

# Structural baseline and drift detection
agent-certify keygen signing.key                             # writes signing.key and signing.key.pub
agent-certify certify <path> --key signing.key -o system.cert.json
agent-certify verify system.cert.json <path> --public-key signing.key.pub   # exit 1 on drift
```

Node names are matched case-insensitively: `--node bash` finds `tool:Bash`.

## What it measures

The **Fragility Index (FI)** measures the proportion of communication links
in your multiagent system that have no backup path (zero triangle participation).

- **FI = 0**: Fully redundant — every communication path has an alternative
- **FI = 1**: Fully fragile — every link is a single point of failure
- **Bridges**: edges whose removal disconnects the system

Formally, with `tri(e)` the number of triangles containing edge `e`,
`FI = |{e : tri(e) = 0}| / |E|`, computed on the undirected graph (two nodes are
linked if either ever invoked the other). Call counts do not affect FI. This is
the same measure sal-torch computes on transformer attention graphs. A graph
with no edges has FI 0.

Every bridge has `tri(e) = 0`, but not every fragile link is a bridge: a
4-cycle has FI 1 and no bridges.

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
only, not call counts. `verify(graph)` names each change: new agents, new tool
links, links that disappeared, FI movement, role changes. A topology change can
be detected before the behaviour it enables shows up.

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
Malformed lines are skipped with a warning. Files are streamed line by line.

A session without sub-agents is a star (one orchestrator, many tools) and has
FI = 1 by construction. Structure becomes informative once sub-agents share
tools: each shared tool closes a triangle with the orchestrator.

## Supported systems

- [x] Claude Code (JSONL logs from ~/.claude/)
- [ ] CrewAI (planned)
- [ ] LangGraph (planned)
- [ ] AutoGen (planned)
- [ ] OTel traces (planned)

New sources subclass `agent_certify.parser.BaseParser` and return an `AgentGraph`.

## Links

- [sal-torch](https://pypi.org/project/sal-torch/) — structural analysis of AI models
- [sal-certify](https://cognitive-engineering.dev/sal-certify) — structural AI certification
- [cognitive-engineering.dev](https://cognitive-engineering.dev)

Built by [Cognitive Engineering](https://cognitive-engineering.dev) (Switzerland).
License: BSL 1.1.
