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
agent-certify blast ~/.claude/projects/ --node bash

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

## Node classification

Each node is removed in turn and FI recomputed.

- **CRITICAL**: removing this agent/tool raises system FI by ≥ 10% (relative), or
  the node is an articulation point (removing it disconnects the system)
- **BUFFER**: raises FI by 2–10%
- **IMMUNE**: raises FI by less than 2%, or lowers it

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
