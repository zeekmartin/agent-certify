# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
import json

import pytest
from conftest import session_graph

from agent_certify import AgentGraph, Policy, PolicyRule
from agent_certify.cli import main


def _deploy_policy() -> Policy:
    return Policy(rules=[PolicyRule("forbidden_tool", "deploy", "critical", "No deploys from agents")])


def test_forbidden_tool():
    g = session_graph("s", {"Bash": 3, "deploy": 2})
    violations = _deploy_policy().check(g)
    assert len(violations) == 1
    v = violations[0]
    assert v.severity == "critical" and v.message == "FORBIDDEN tool used: deploy"
    assert v.observed == "Tool deploy was used (2 calls)"


def test_no_violation_without_the_tool():
    assert _deploy_policy().check(session_graph("s", {"Bash": 3, "Read": 1})) == []


def test_matching_is_by_name_id_or_glob_case_insensitive():
    g = session_graph("s", {"Bash": 1, "deploy_production": 1})
    for target in ("deploy_production", "tool:deploy_production", "DEPLOY_*", "*production"):
        rule = PolicyRule("forbidden_tool", target, "critical", "")
        assert len(Policy([rule]).check(g)) == 1, target
    assert Policy([PolicyRule("forbidden_tool", "deploy", "critical", "")]).check(g) == []   # exact, not substring


def test_wildcard_agent_link():
    g = session_graph("s", {"Bash": 2, "database": 1}, agents=2)      # each Explore agent calls Bash
    rule = PolicyRule("forbidden_link", "agent:* → Bash", "critical", "Sub-agents may not use the shell")
    violations = Policy([rule]).check(g)
    assert sorted(v.message for v in violations) == [
        "FORBIDDEN link: agent:s-0 → tool:Bash", "FORBIDDEN link: agent:s-1 → tool:Bash"]
    # by type, ASCII arrow, no match on claude's own Bash link
    assert len(Policy([PolicyRule("forbidden_link", "agent:Explore -> tool:Bash", "warning", "")]).check(g)) == 2
    assert Policy([PolicyRule("forbidden_link", "agent:* → database", "critical", "")]).check(g) == []
    assert len(Policy([PolicyRule("forbidden_link", "claude → database", "critical", "")]).check(g)) == 1


def test_max_sub_agents_and_required_tool():
    g = session_graph("s", {"Bash": 1}, agents=3)
    rules = [PolicyRule("max_sub_agents", "2", "warning", "keep it small"),
             PolicyRule("max_sub_agents", "5", "critical", "far too many"),
             PolicyRule("required_tool", "Read", "warning", "must read before writing"),
             PolicyRule("required_tool", "bash", "warning", "")]
    violations = Policy(rules).check(g)
    assert [(v.rule.kind, v.rule.target) for v in violations] == [("max_sub_agents", "2"), ("required_tool", "Read")]
    assert violations[0].message == "Too many sub-agents: 3 > 2"
    assert violations[1].message == "REQUIRED tool missing: Read"


def test_violations_sorted_critical_first():
    g = session_graph("s", {"Bash": 1, "deploy": 1})
    rules = [PolicyRule("required_tool", "Read", "warning", ""), PolicyRule("forbidden_tool", "deploy", "critical", "")]
    assert [v.severity for v in Policy(rules).check(g)] == ["critical", "warning"]


def test_save_load_roundtrip(tmp_path):
    policy = Policy(rules=[
        PolicyRule("forbidden_tool", "deploy_production", "critical", "No agent may deploy to production"),
        PolicyRule("forbidden_link", "agent:* → database", "critical", "Sub-agents may not access the database"),
        PolicyRule("max_sub_agents", "5", "warning", "More than 5 sub-agents is unusual"),
        PolicyRule("required_tool", "Bash", "warning", "Bash is expected in every session"),
    ], generated_from="baseline (25 sessions)", created_at="2026-10-27T20:00:00")
    path = policy.save(tmp_path / "p" / "policy.json")
    text = path.read_text(encoding="utf-8")
    assert "agent:* → database" in text                      # arrow stays readable for hand edits
    assert Policy.load(path) == policy


def test_default_path():
    path = _deploy_policy().save()
    assert path.as_posix() == ".agent-certify/policy.json" and path.is_file()


@pytest.mark.parametrize("bad", [
    {"kind": "forbidden_everything", "target": "x", "severity": "critical", "message": ""},
    {"kind": "forbidden_tool", "target": "x", "severity": "fatal", "message": ""},
    {"kind": "forbidden_link", "target": "no arrow here", "severity": "warning", "message": ""},
    {"kind": "max_sub_agents", "target": "lots", "severity": "warning", "message": ""},
])
def test_invalid_rules_rejected(tmp_path, bad):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"rules": [bad]}))
    with pytest.raises(ValueError):
        Policy.load(path)


def test_empty_graph():
    g = AgentGraph()
    g.add_node("claude", "orchestrator")
    assert len(Policy([PolicyRule("required_tool", "Bash", "warning", "")]).check(g)) == 1


def test_policy_and_anomalies_are_separate(session_dir, capsys):
    session = str(session_dir / "sess-1.jsonl")
    assert main(["learn", session]) == 0
    Policy(rules=[PolicyRule("forbidden_tool", "Grep", "critical", "no grepping"),
                  PolicyRule("required_tool", "Bash", "warning", "")]).save()
    capsys.readouterr()

    assert main(["scan", session]) == 2                       # both files auto-discovered; critical violation
    out = capsys.readouterr().out
    assert "No anomalies" in out                              # statistically normal...
    assert "⛔ POLICY VIOLATIONS (1):" in out                 # ...but not allowed
    assert "[CRITICAL] FORBIDDEN tool used: Grep" in out
    assert "Policy:   .agent-certify/policy.json (2 rules)" in out

    assert main(["scan", session, "--format", "json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert [v["message"] for v in data["policy_violations"]] == ["FORBIDDEN tool used: Grep"]

    assert main(["scan", session, "--no-policy"]) == 0
    assert "POLICY" not in capsys.readouterr().out


def test_cli_explicit_policy_missing(session_dir):
    with pytest.raises(SystemExit, match="not found"):
        main(["scan", str(session_dir / "sess-1.jsonl"), "--policy", "nope.json"])
