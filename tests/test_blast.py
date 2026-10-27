# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
from agent_certify import AgentGraph, BlastRadiusAnalyzer


def test_star_center_fragments(star_graph):
    report = BlastRadiusAnalyzer(star_graph).analyze("claude")
    assert report.system_fragmented
    assert len(report.components_after) == 4
    assert all(len(c) == 1 for c in report.components_after)
    assert report.direct_impact == [f"tool:t{i}" for i in range(4)]
    assert report.accessible_tools == [f"tool:t{i}" for i in range(4)]
    assert report.remaining_fi == 0.0
    assert "Single point of failure" in report.isolation_recommendation


def test_star_leaf(star_graph):
    report = BlastRadiusAnalyzer(star_graph).analyze("t2")      # resolved by name
    assert report.compromised == "tool:t2"
    assert not report.system_fragmented
    assert report.direct_impact == ["claude"]
    assert report.reach_by_hop[2] == ["tool:t0", "tool:t1", "tool:t3"]
    assert report.accessible_tools == []


def test_tools_reached_through_subagent():
    g = AgentGraph()
    g.add_node("claude", "orchestrator")
    g.add_node("agent:a", "agent")
    g.add_node("tool:Bash", "tool", "Bash")
    g.add_node("tool:Web", "tool", "Web")
    g.add_call("claude", "agent:a")
    g.add_call("agent:a", "tool:Bash")
    g.add_call("agent:a", "tool:Web")
    g.add_call("claude", "tool:Bash")
    blast = BlastRadiusAnalyzer(g)
    assert blast.analyze("claude").accessible_tools == ["tool:Bash", "tool:Web"]
    assert blast.analyze("agent:a").system_fragmented          # Web hangs only off agent:a
    assert not blast.analyze("bash").system_fragmented
