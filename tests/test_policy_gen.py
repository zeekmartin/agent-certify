# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
import json
from pathlib import Path

import pytest
from conftest import session_graph

from agent_certify import BaselineLearner, Policy, PolicyGenerator
from agent_certify.cli import main


@pytest.fixture
def baseline():
    # Bash in 4/4 sessions, Read in 4/4, Write in 2/4, WebSearch in 1/4; up to 2 sub-agents.
    graphs = [
        session_graph("a", {"Bash": 5, "Read": 2, "Write": 1}),
        session_graph("b", {"Bash": 3, "Read": 1, "Write": 1}, agents=2),
        session_graph("c", {"Bash": 2, "Read": 4}),
        session_graph("d", {"Bash": 9, "Read": 1, "WebSearch": 1}, agents=1),
    ]
    return BaselineLearner().learn_graphs(graphs)


def test_required_rules_for_tools_in_every_session(baseline):
    policy = PolicyGenerator().suggest(baseline)
    required = sorted(r.target for r in policy.rules if r.kind == "required_tool")
    assert required == ["Bash", "Read"]
    assert all(r.severity == "warning" for r in policy.rules if r.kind == "required_tool")


def test_max_sub_agent_rules(baseline):
    policy = PolicyGenerator().suggest(baseline)
    caps = {r.severity: int(r.target) for r in policy.rules if r.kind == "max_sub_agents"}
    assert caps == {"warning": 3, "critical": 5}             # baseline max 2: +1 and +3


def test_no_forbidden_rules_in_a_draft(baseline):
    kinds = {r.kind for r in PolicyGenerator().suggest(baseline).rules}
    assert kinds == {"required_tool", "max_sub_agents"}       # FORBIDDEN rules are a human decision


def test_draft_saves_as_valid_json(baseline, tmp_path):
    policy = PolicyGenerator().suggest(baseline)
    assert policy.generated_from == "baseline (4 sessions)" and policy.created_at.endswith("Z")
    path = policy.save(tmp_path / "policy.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert {r["kind"] for r in data["rules"]} == {"required_tool", "max_sub_agents"}
    assert Policy.load(path) == policy


def test_draft_passes_the_sessions_it_came_from(baseline):
    policy = PolicyGenerator().suggest(baseline)
    assert policy.check(session_graph("a", {"Bash": 5, "Read": 2, "Write": 1})) == []
    over = policy.check(session_graph("z", {"Bash": 1, "Read": 1}, agents=6))
    assert [v.severity for v in over] == ["critical", "warning"]


def test_cli_suggest_policy(baseline, capsys):
    BaselineLearner().save(baseline)                          # ./.agent-certify/baseline.json
    assert main(["suggest-policy"]) == 0
    out = capsys.readouterr().out
    assert "Generated policy from baseline (4 sessions):" in out
    assert "[WARNING]  REQUIRED: Bash (seen in 100% of sessions)" in out
    assert "[WARNING]  MAX SUB-AGENTS: 3 (Baseline max was 2)" in out
    assert "[CRITICAL] MAX SUB-AGENTS: 5" in out
    assert "Saved draft to .agent-certify/policy.json" in out
    assert Path(".agent-certify/policy.json").is_file()

    # A second run must not clobber a policy the human may have edited.
    with pytest.raises(SystemExit, match="--force"):
        main(["suggest-policy"])
    assert main(["suggest-policy", "--force"]) == 0
    assert main(["suggest-policy", "--output", "other.json"]) == 0
    assert Path("other.json").is_file()


def test_cli_suggest_policy_needs_baseline():
    with pytest.raises(SystemExit, match="agent-certify learn"):
        main(["suggest-policy"])
