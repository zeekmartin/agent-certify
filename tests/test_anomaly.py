# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
import json

import pytest
from conftest import session_graph

from agent_certify import AgentFIScanner, AnomalyDetector, Baseline, BaselineLearner
from agent_certify.cli import main


def make_baseline(**overrides) -> Baseline:
    """Baseline for a claude -> {Bash, Read, Write} star, with chosen spreads."""
    fields = {
        "learned_from": 10, "period_start": "2026-10-01T00:00:00Z", "period_end": "2026-10-27T00:00:00Z",
        "fi_mean": 1.0, "fi_std": 0.1, "node_count_mean": 4.0, "node_count_std": 1.0,
        "edge_count_mean": 3.0, "edge_count_std": 1.0,
        "known_tools": {"Bash", "Read", "Write"}, "tool_frequency": {"Bash": 1.0, "Read": 0.9, "Write": 0.8},
        "sub_agent_count_mean": 0.0, "sub_agent_count_std": 0.0, "max_sub_agents_seen": 0,
        "error_rate_mean": 0.05, "error_rate_std": 0.02,
        "known_links": {("claude", "tool:Bash"), ("claude", "tool:Read"), ("claude", "tool:Write")},
        "bridge_count_mean": 3.0, "bridge_count_std": 1.0, "created_at": "2026-10-27T00:00:00Z",
    }
    fields.update(overrides)
    return Baseline(**fields)


def _detect(baseline, graph):
    return AnomalyDetector(baseline).detect(graph, AgentFIScanner(graph).scan())


def _normal(**kw):
    # 20 calls, 1 error: 5% error rate, FI 1.0, 4 nodes. Matches make_baseline().
    return session_graph("normal", {"Bash": 10, "Read": 6, "Write": 4}, errors=1, **kw)


def test_normal_session_has_no_anomalies():
    report = _detect(make_baseline(), _normal())
    assert report.anomalies == []
    assert not report.has_critical
    assert report.summary.startswith("No anomalies")


def test_new_tool_is_critical():
    g = session_graph("deploy", {"Bash": 10, "Read": 6, "deploy": 4}, errors=1)
    report = _detect(make_baseline(), g)
    new_tools = [a for a in report.anomalies if a.category == "new_tool"]
    assert len(new_tools) == 1
    assert new_tools[0].severity == "critical" and new_tools[0].value == "deploy"
    assert new_tools[0].z_score is None
    assert report.has_critical
    # The new tool's link is not reported a second time.
    assert not any(a.category == "new_link" for a in report.anomalies)


def test_new_link_is_warning():
    g = _normal(cross_links=1)                      # tool:Bash -> tool:Read, never seen
    links = [a for a in _detect(make_baseline(fi_std=1.0), g).anomalies if a.category == "new_link"]
    assert [a.value for a in links] == ["tool:Bash -> tool:Read"]
    assert links[0].severity == "warning"


def test_fi_above_baseline_warning():
    # FI 1.0 against 0.7 ± 0.12: z = 2.5.
    report = _detect(make_baseline(fi_mean=0.7, fi_std=0.12), _normal())
    fi = [a for a in report.anomalies if a.category == "fi_deviation"]
    assert len(fi) == 1 and fi[0].severity == "warning"
    assert fi[0].z_score == pytest.approx(2.5)
    assert "Redundancy lost" in fi[0].detail


def test_fi_far_above_baseline_critical():
    report = _detect(make_baseline(fi_mean=0.6, fi_std=0.1), _normal())       # z = 4
    fi = next(a for a in report.anomalies if a.category == "fi_deviation")
    assert fi.severity == "critical" and fi.z_score == pytest.approx(4.0)


def test_fi_drop_with_subagents_is_warning_only():
    # A sub-agent sharing Bash closes triangle claude-agent-Bash: 3 of 5 links
    # supported, FI 0.4, far below a baseline of 1.0 ± 0.05 (z = -12).
    g = _normal(agents=1)
    assert AgentFIScanner(g).scan().fi == pytest.approx(0.4)
    links = {("claude", "tool:Bash"), ("claude", "tool:Read"), ("claude", "tool:Write"),
             ("claude", "agent:Explore"), ("agent:Explore", "tool:Bash")}
    report = _detect(make_baseline(fi_std=0.05, sub_agent_count_std=1.0, max_sub_agents_seen=3,
                                   known_links=links), g)
    fi = next(a for a in report.anomalies if a.category == "fi_deviation")
    assert fi.z_score == pytest.approx(-12.0)
    assert fi.severity == "warning"
    assert "Sub-agents detected" in fi.detail


def test_error_rate_5_sigma_is_critical():
    # 3 errors in 20 calls = 15%, baseline 5% ± 2%: z = 5.
    g = session_graph("errors", {"Bash": 10, "Read": 6, "Write": 4}, errors=3)
    err = next(a for a in _detect(make_baseline(), g).anomalies if a.category == "error_rate")
    assert err.severity == "critical"
    assert err.z_score == pytest.approx(5.0)
    assert err.value == pytest.approx(0.15)


def test_low_error_rate_is_not_flagged():
    g = session_graph("clean", {"Bash": 10, "Read": 6, "Write": 4}, errors=0)    # z = -2.5
    assert not any(a.category == "error_rate" for a in _detect(make_baseline(), g).anomalies)


def test_sub_agents_above_max():
    g = _normal(agents=2)
    base = make_baseline(sub_agent_count_mean=0.2, sub_agent_count_std=0.4, max_sub_agents_seen=1, fi_std=1.0)
    sub = next(a for a in _detect(base, g).anomalies if a.category == "sub_agents")
    assert sub.value == 2 and sub.z_score == pytest.approx(4.5)
    assert sub.severity == "critical"             # above max and > 3 sigma

    base = make_baseline(sub_agent_count_mean=1.0, sub_agent_count_std=1.0, max_sub_agents_seen=1, fi_std=1.0)
    sub = next(a for a in _detect(base, g).anomalies if a.category == "sub_agents")
    assert sub.severity == "warning"              # above max but only 1 sigma


def test_zero_variance_baseline():
    # Baseline never saw a sub-agent (std 0): any sub-agent is a warning with no z.
    g = _normal(agents=1)
    sub = next(a for a in _detect(make_baseline(fi_std=1.0), g).anomalies if a.category == "sub_agents")
    assert sub.severity == "warning" and sub.z_score is None


def test_node_count_info_then_warning():
    tools = ("Bash", "Read", "Write", "Grep", "Edit", "Glob", "LS")
    base = make_baseline(known_tools=set(tools), known_links={("claude", f"tool:{t}") for t in tools})
    # claude + 6 tools = 7 nodes against 4 ± 1: z = 3 -> info.
    g = session_graph("big", dict.fromkeys(tools[:6], 4), errors=1)
    nodes = next(a for a in _detect(base, g).anomalies if a.category == "node_count")
    assert nodes.severity == "info" and nodes.z_score == pytest.approx(3.0)
    # 8 nodes: z = 4 -> warning.
    g = session_graph("bigger", dict.fromkeys(tools, 4), errors=1)
    nodes = next(a for a in _detect(base, g).anomalies if a.category == "node_count")
    assert nodes.severity == "warning" and nodes.z_score == pytest.approx(4.0)


def test_report_order_and_json():
    g = session_graph("mix", {"Bash": 10, "deploy": 10}, errors=3)
    report = _detect(make_baseline(), g)
    severities = [a.severity for a in report.anomalies]
    assert severities == sorted(severities, key=["critical", "warning", "info"].index)
    data = json.loads(json.dumps(report.to_dict()))
    assert data["has_critical"] is True
    assert "ANOMALIES DETECTED" in str(report)


def test_learned_baseline_accepts_its_own_typical_session():
    graphs = [session_graph(f"s{i}", {"Bash": 10 + i, "Read": 5, "Write": 3}, errors=i % 2) for i in range(8)]
    baseline = BaselineLearner().learn_graphs(graphs)
    assert _detect(baseline, graphs[3]).anomalies == []


# ------------------------------------------------------------------------ cli
def test_cli_scan_with_baseline(session_dir, capsys):
    session = str(session_dir / "sess-1.jsonl")
    assert main(["learn", session]) == 0
    capsys.readouterr()

    # Auto-discovered from ./.agent-certify/baseline.json: the same session is normal.
    assert main(["scan", session]) == 0
    out = capsys.readouterr().out
    assert "No anomalies against baseline of 1 session" in out
    assert "baseline: 0.50 ± 0.00" in out

    # Explicit baseline vs a session with a new tool.
    other = session_dir / "other.jsonl"
    other.write_text(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "x", "name": "deploy_production", "input": {}}]}}) + "\n")
    assert main(["scan", str(other), "--baseline", ".agent-certify/baseline.json"]) == 2   # critical: exit 2
    out = capsys.readouterr().out
    assert "[CRITICAL] New tool never seen: deploy_production" in out

    assert main(["scan", str(other), "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["anomalies"]["has_critical"] is True

    # --no-baseline: v0.1 output, no anomaly section.
    assert main(["scan", str(other), "--no-baseline"]) == 0
    out = capsys.readouterr().out
    assert "ANOMALIES" not in out and "baseline" not in out.lower()


def test_cli_missing_baseline(session_dir):
    with pytest.raises(SystemExit, match="not found"):
        main(["scan", str(session_dir / "sess-1.jsonl"), "--baseline", "nope.json"])


def test_cli_directory_scan_lists_anomalies_per_session(session_dir, capsys):
    assert main(["learn", str(session_dir)]) == 0
    capsys.readouterr()
    (session_dir / "sess-2.jsonl").write_text(json.dumps({"type": "assistant", "message": {
        "role": "assistant", "content": [{"type": "tool_use", "id": "x", "name": "deploy", "input": {}}]}}) + "\n")
    assert main(["scan", str(session_dir)]) == 2                      # sess-2 has a critical anomaly
    table = capsys.readouterr().out.split("Merged graph")[0]
    assert "ANOMALIES" in table.splitlines()[0]
    rows = {line.split()[0]: line for line in table.splitlines()[1:] if line.strip()}
    assert rows["sess-1"].endswith(" 0")                 # evaluated, nothing found ("-" now means not evaluated)
    assert "1 critical" in rows["sess-2"]
