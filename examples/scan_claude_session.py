# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
"""Scan one Claude Code session: FI, bridges, node roles, blast radius, HTML.

    python examples/scan_claude_session.py ~/.claude/projects/<project>/<session>.jsonl
"""
import sys
from pathlib import Path

from agent_certify import AgentFIScanner, BlastRadiusAnalyzer, ClaudeCodeParser
from agent_certify.viz import save_html


def main(path: str) -> None:
    graph = ClaudeCodeParser().parse(path)
    result = AgentFIScanner(graph).scan()
    print(result.summary())
    print(f"Bridges: {[f'{e.source} -> {e.target}' for e in result.bridges]}")
    print(f"Critical nodes: {result.critical_nodes}")

    blast = BlastRadiusAnalyzer(graph)
    for name in ("claude", "bash"):
        try:
            print()
            print(blast.analyze(name))
        except KeyError as exc:
            print(exc.args[0])

    out = save_html(graph, Path(path).stem + ".html", result)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
