# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""Quick demo on this machine's Claude Code sessions.

Picks the session with the most sub-agents (ties broken by tool calls) under
~/.claude/projects/, scans it, shows the blast radius of its busiest tool,
issues a signed certificate and verifies the session against it.

    python scripts/demo.py [~/.claude/projects]
"""
import os
import sys
import tempfile
from pathlib import Path

from agent_certify import AgentCertificate, AgentFIScanner, BlastRadiusAnalyzer, ClaudeCodeParser, generate_keypair


def main(root: str = "~/.claude/projects") -> None:
    graphs = ClaudeCodeParser().parse_directory(root)
    if not graphs:
        sys.exit(f"no Claude Code sessions under {root}")
    g = max(graphs, key=lambda g: (sum(n.kind == "agent" for n in g.nodes.values()), g.total_tool_calls))
    print(f"{len(graphs)} sessions found; demo session {g.session_id} ({g.project})\n")

    result = AgentFIScanner(g).scan()
    print(result.summary())
    for nid in result.critical_nodes:
        print(f"  CRITICAL  {nid}  ({g.nodes[nid].name})")

    tools = [n for n in g.nodes.values() if n.kind == "tool"]
    if tools:
        busiest = max(tools, key=lambda n: n.call_count)
        print()
        print(BlastRadiusAnalyzer(g).analyze(busiest.id))

    priv, pub = generate_keypair()
    cert = AgentCertificate.create(g, system_id=f"demo-{g.session_id[:8]}", signing_key=priv)
    # A fresh, unpredictable name created atomically: no other user can pre-place a symlink there.
    fd, name = tempfile.mkstemp(prefix="agent-certify-demo-", suffix=".cert.json")
    os.close(fd)
    path = Path(name)
    cert.save(path)
    print(f"\ncertificate written to {path}")
    print(cert.verify(g, public_key=pub))


if __name__ == "__main__":
    main(*sys.argv[1:])
