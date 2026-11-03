# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""v0.6.0 baseline overrides: accept, reject, and scoped link acceptance.

What a baseline learned is a statistic; what an operator decided about it is
not. Re-learning recomputes every statistic and must leave the decisions
standing — otherwise a rejected tool becomes normal the moment it appears often
enough, which is the failure these tests exist to prevent.

Scoped link acceptance comes from a reader's note on LinkedIn: approving
``agent:Build -> deploy_staging`` must not approve ``agent:Test`` doing the
same thing.
"""
import json

import pytest
from conftest import session_graph, star

from agent_certify.anomaly import AnomalyDetector
from agent_certify.baseline import (
    BaselineLearner,
    carry_overrides,
    load_baseline,
    normalise_endpoint,
    normalise_tool,
    parse_link,
)
from agent_certify.cli import main
from agent_certify.graph import AgentGraph
from agent_certify.policy import PolicyGenerator
from agent_certify.scanner import AgentFIScanner


def learn(*graphs):
    return BaselineLearner().learn_graphs(list(graphs))


def detect(baseline, graph):
    return AnomalyDetector(baseline, "test").detect(graph, AgentFIScanner(graph).scan())


def categories(report, category):
    return [a for a in report.anomalies if a.category == category]


def scoped_graph(callers=("Build",), tool="deploy_staging"):
    """Known orchestrator and tool, plus sub-agents calling ``tool``."""
    g = AgentGraph(session_id="scoped", started_at="2026-10-02T10:00:00Z",
                   ended_at="2026-10-02T11:00:00Z")
    g.add_node("claude", "orchestrator")
    g.add_node("tool:Read", "tool", "Read")
    g.add_call("claude", "tool:Read")
    g.add_node(f"tool:{tool}", "tool", tool)
    for i, kind in enumerate(callers):
        aid = f"agent:{kind}:{i}"
        g.add_node(aid, "agent", kind, agentType=kind)
        g.add_call("claude", aid)
        g.add_call(aid, f"tool:{tool}")
    return g


# ------------------------------------------------------------------ parsing
def test_normalise_tool_accepts_both_spellings():
    assert normalise_tool("Bash") == "Bash"
    assert normalise_tool("tool:Bash") == "Bash"
    assert normalise_tool("  tool:Write  ") == "Write"


def test_normalise_tool_rejects_empty():
    with pytest.raises(ValueError, match="empty"):
        normalise_tool("   ")


def test_parse_link_prefixes_a_bare_target_as_a_tool():
    assert parse_link("agent:Build -> deploy_staging") == ("agent:Build", "tool:deploy_staging")


def test_parse_link_keeps_explicit_prefixes():
    assert parse_link("claude -> tool:Bash", learn(star(2))) == ("claude", "tool:Bash")


def test_parse_link_resolves_a_bare_word_against_the_baseline():
    """``claude`` is an orchestrator id, ``t0`` is a tool name; both are bare."""
    b = learn(star(2))
    assert normalise_endpoint("claude", b) == "claude"
    assert normalise_endpoint("t0", b) == "tool:t0"


def test_parse_link_says_what_it_expected():
    with pytest.raises(ValueError, match="SOURCE -> TARGET"):
        parse_link("agent:Build deploy_staging")


# ------------------------------------------------------------------- accept
def test_accepted_tool_stops_being_an_anomaly():
    b = learn(session_graph("s1", {"Read": 3, "Write": 2}))
    g = session_graph("s2", {"Read": 3, "Write": 2, "Bash": 1})
    assert [a.value for a in categories(detect(b, g), "new_tool")] == ["Bash"]
    b.accepted_tools.add("Bash")
    assert categories(detect(b, g), "new_tool") == []


def test_accepting_a_tool_does_not_touch_the_statistics():
    """Acceptance is a decision, not an observation: no mean moves."""
    b = learn(session_graph("s1", {"Read": 3, "Write": 2}))
    before = (b.fi_mean, b.node_count_mean, dict(b.tool_frequency), set(b.known_tools))
    b.accepted_tools.add("Bash")
    assert (b.fi_mean, b.node_count_mean, dict(b.tool_frequency), set(b.known_tools)) == before


# ------------------------------------------------------------------- reject
def test_rejected_tool_fires_even_though_the_baseline_learned_it():
    """The core of reject: being normal is not enough to stop firing."""
    b = learn(session_graph("s1", {"Read": 3, "Bash": 2}))
    g = session_graph("s2", {"Read": 3, "Bash": 2})
    assert categories(detect(b, g), "new_tool") == []     # learned, so silent
    b.rejected_tools.add("Bash")
    hits = categories(detect(b, g), "new_tool")
    assert [a.value for a in hits] == ["Bash"]
    assert hits[0].severity == "critical"
    assert "Rejected tool used" in hits[0].message
    assert "across re-learns" in hits[0].detail


def test_rejected_tool_is_not_promoted_to_a_required_policy_rule():
    b = learn(session_graph("s1", {"Read": 3, "Bash": 2}))
    assert any(r.target == "Bash" for r in PolicyGenerator().suggest(b).rules)
    b.rejected_tools.add("Bash")
    assert not any(r.target == "Bash" for r in PolicyGenerator().suggest(b).rules)


def test_rejection_beats_an_accepted_link():
    """A scoped approval cannot resurrect a tool the operator rejected outright."""
    g = scoped_graph(callers=("Build",))
    b = learn(session_graph("s1", {"Read": 3}))
    b.accepted_links.add(("agent:Build", "tool:deploy_staging"))
    assert categories(detect(b, g), "new_tool") == []
    b.rejected_tools.add("deploy_staging")
    assert [a.value for a in categories(detect(b, g), "new_tool")] == ["deploy_staging"]


# ---------------------------------------------------------- scoped accept
def test_scoped_accept_covers_only_the_named_caller():
    """The LinkedIn feedback, as a test: one agent approved, another still fires."""
    b = learn(session_graph("s1", {"Read": 3}))
    b.accepted_links.add(("agent:Build", "tool:deploy_staging"))

    assert categories(detect(b, scoped_graph(("Build",))), "new_tool") == []

    hits = categories(detect(b, scoped_graph(("Test",))), "new_tool")
    assert [a.value for a in hits] == ["deploy_staging"]
    assert "agent:Test" in hits[0].detail


def test_a_partially_covered_tool_still_fires_and_names_the_gap():
    b = learn(session_graph("s1", {"Read": 3}))
    b.accepted_links.add(("agent:Build", "tool:deploy_staging"))
    hits = categories(detect(b, scoped_graph(("Build", "Test"))), "new_tool")
    assert [a.value for a in hits] == ["deploy_staging"]
    assert "agent:Test" in hits[0].detail
    assert "agent:Build" not in hits[0].detail.split("accepted link:")[-1]


def test_accepted_link_silences_the_new_link_warning():
    """A link between two already-known nodes: new_link, not new_tool."""
    g = session_graph("s2", {"Read": 3, "Write": 2}, cross_links=1)
    b = learn(session_graph("s1", {"Read": 3, "Write": 2}))
    new = categories(detect(b, g), "new_link")
    assert new, "expected a new link to flag before acceptance"
    b.accepted_links.add(tuple(new[0].value.split(" -> ")))
    assert categories(detect(b, g), "new_link") == []


# ------------------------------------------------------- round-trip and carry
def test_overrides_survive_a_save_load_round_trip(tmp_path):
    b = learn(session_graph("s1", {"Read": 3}))
    b.accepted_tools.add("Bash")
    b.rejected_tools.add("deploy_prod")
    b.accepted_links.add(("agent:Build", "tool:deploy_staging"))
    p = BaselineLearner().save(b, tmp_path / "b.json")
    back = load_baseline(p)
    assert back.accepted_tools == {"Bash"}
    assert back.rejected_tools == {"deploy_prod"}
    assert back.accepted_links == {("agent:Build", "tool:deploy_staging")}
    assert back.has_overrides


def test_a_pre_0_6_baseline_still_loads(tmp_path):
    """The three fields are defaulted, so older files are not broken by the upgrade."""
    b = learn(session_graph("s1", {"Read": 3}))
    data = b.to_dict()
    for key in ("accepted_tools", "rejected_tools", "accepted_links"):
        del data[key]
    p = tmp_path / "old.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    old = load_baseline(p)
    assert not old.has_overrides


def test_carry_overrides_copies_decisions_onto_a_fresh_baseline():
    old = learn(session_graph("s1", {"Read": 3}))
    old.accepted_tools.add("Bash")
    old.rejected_tools.add("deploy_prod")
    old.accepted_links.add(("agent:Build", "tool:deploy_staging"))
    new = learn(session_graph("s2", {"Read": 3, "Write": 9}))
    carry_overrides(new, old)
    assert new.accepted_tools == {"Bash"}
    assert new.rejected_tools == {"deploy_prod"}
    assert new.accepted_links == {("agent:Build", "tool:deploy_staging")}
    # and the statistics are the new ones, not the old ones
    assert new.known_tools == {"Read", "Write"}


def test_carry_overrides_with_no_previous_baseline_is_a_no_op():
    new = learn(session_graph("s1", {"Read": 3}))
    assert carry_overrides(new, None) is new
    assert not new.has_overrides


def test_overrides_are_copied_not_shared():
    """Mutating the new baseline must not reach back into the old one."""
    old = learn(session_graph("s1", {"Read": 3}))
    old.accepted_tools.add("Bash")
    new = carry_overrides(learn(session_graph("s2", {"Read": 3})), old)
    new.accepted_tools.add("Write")
    assert old.accepted_tools == {"Bash"}


# ------------------------------------------------------------------- the CLI
def _baseline_file(tmp_path, tools=None):
    b = learn(session_graph("s1", tools or {"Read": 3, "Write": 2}))
    return BaselineLearner().save(b, tmp_path / "b.json")


def test_cli_accept_tool(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    assert main(["baseline", "accept", "--tool", "Bash", "--baseline", str(p)]) == 0
    assert load_baseline(p).accepted_tools == {"Bash"}
    assert "accepted tool: Bash" in capsys.readouterr().out


def test_cli_reject_tool(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    assert main(["baseline", "reject", "--tool", "Bash", "--baseline", str(p)]) == 0
    assert load_baseline(p).rejected_tools == {"Bash"}
    assert "rejected tool: Bash" in capsys.readouterr().out


def test_cli_reject_warns_when_the_tool_was_already_learned(tmp_path, capsys):
    p = _baseline_file(tmp_path, {"Read": 3, "Bash": 1})
    main(["baseline", "reject", "--tool", "Bash", "--baseline", str(p)])
    assert "already learned as normal" in capsys.readouterr().out


def test_cli_accept_link(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    assert main(["baseline", "accept", "--link", "agent:Build -> deploy_staging",
                 "--baseline", str(p)]) == 0
    assert load_baseline(p).accepted_links == {("agent:Build", "tool:deploy_staging")}
    out = capsys.readouterr().out
    assert "agent:Build -> tool:deploy_staging" in out
    assert "scoped" in out


def test_cli_accept_is_repeatable(tmp_path):
    p = _baseline_file(tmp_path)
    main(["baseline", "accept", "--tool", "Bash", "--tool", "tool:Grep",
          "--link", "agent:Build -> deploy_staging", "--baseline", str(p)])
    b = load_baseline(p)
    assert b.accepted_tools == {"Bash", "Grep"}
    assert b.accepted_links == {("agent:Build", "tool:deploy_staging")}


def test_cli_accept_then_reject_lets_the_newer_decision_win(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    main(["baseline", "accept", "--tool", "Bash", "--baseline", str(p)])
    main(["baseline", "reject", "--tool", "Bash", "--baseline", str(p)])
    b = load_baseline(p)
    assert b.rejected_tools == {"Bash"} and b.accepted_tools == set()
    assert "was accepted" in capsys.readouterr().out


def test_cli_reject_then_accept_lets_the_newer_decision_win(tmp_path):
    p = _baseline_file(tmp_path)
    main(["baseline", "reject", "--tool", "Bash", "--baseline", str(p)])
    main(["baseline", "accept", "--tool", "Bash", "--baseline", str(p)])
    b = load_baseline(p)
    assert b.accepted_tools == {"Bash"} and b.rejected_tools == set()


def test_cli_accept_needs_something_to_accept(tmp_path):
    p = _baseline_file(tmp_path)
    with pytest.raises(SystemExit, match="nothing to accept"):
        main(["baseline", "accept", "--baseline", str(p)])


def test_cli_accept_rejects_a_malformed_link(tmp_path):
    p = _baseline_file(tmp_path)
    with pytest.raises(SystemExit, match="SOURCE -> TARGET"):
        main(["baseline", "accept", "--link", "oops", "--baseline", str(p)])


def test_cli_edit_without_a_baseline_says_how_to_make_one(tmp_path):
    with pytest.raises(SystemExit, match="agent-certify learn"):
        main(["baseline", "accept", "--tool", "Bash",
              "--baseline", str(tmp_path / "missing.json")])


def test_cli_show_lists_the_decisions(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    main(["baseline", "accept", "--tool", "Bash", "--link", "agent:Build -> deploy_staging",
          "--baseline", str(p)])
    main(["baseline", "reject", "--tool", "deploy_prod", "--baseline", str(p)])
    capsys.readouterr()
    assert main(["baseline", "show", "--baseline", str(p)]) == 0
    out = capsys.readouterr().out
    assert "Bash" in out and "deploy_prod" in out
    assert "agent:Build -> tool:deploy_staging" in out


def test_cli_show_json(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    main(["baseline", "accept", "--tool", "Bash", "--baseline", str(p)])
    capsys.readouterr()
    main(["baseline", "show", "--format", "json", "--baseline", str(p)])
    data = json.loads(capsys.readouterr().out)
    assert data["accepted_tools"] == ["Bash"]
    assert data["rejected_tools"] == []


def test_cli_show_says_so_when_there_are_no_decisions(tmp_path, capsys):
    p = _baseline_file(tmp_path)
    main(["baseline", "show", "--baseline", str(p)])
    assert "No operator decisions" in capsys.readouterr().out


# ------------------------------------------- the headline: accept/reject survive learn
def _session_file(tmp_path, name, tools):
    """A minimal Claude Code session transcript the parser accepts."""
    from conftest import _assistant
    lines = []
    for tool, calls in tools.items():
        for i in range(calls):
            lines.append(json.dumps(_assistant([(f"{tool}-{i}", tool, {})])))
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_accept_then_relearn_keeps_the_tool_accepted(tmp_path, capsys):
    sess = _session_file(tmp_path, "s.jsonl", {"Read": 2, "Write": 1})
    out = tmp_path / "b.json"
    main(["learn", str(sess), "-o", str(out)])
    main(["baseline", "accept", "--tool", "Bash", "--baseline", str(out)])
    capsys.readouterr()

    main(["learn", str(sess), "-o", str(out)])
    b = load_baseline(out)
    assert b.accepted_tools == {"Bash"}, "a re-learn must not undo an accept"
    assert "Carried forward" in capsys.readouterr().out


def test_reject_then_relearn_keeps_the_tool_rejected(tmp_path, capsys):
    """Even when the re-learn sees the rejected tool in every session."""
    sess = _session_file(tmp_path, "s.jsonl", {"Read": 2, "Bash": 3})
    out = tmp_path / "b.json"
    main(["learn", str(sess), "-o", str(out)])
    main(["baseline", "reject", "--tool", "Bash", "--baseline", str(out)])
    main(["learn", str(sess), "-o", str(out)])

    b = load_baseline(out)
    assert b.rejected_tools == {"Bash"}
    assert "Bash" in b.known_tools, "the baseline still records what it observed"
    hits = categories(detect(b, session_graph("s2", {"Read": 2, "Bash": 3})), "new_tool")
    assert [a.value for a in hits] == ["Bash"], "learned in 100% of sessions and still firing"


def test_scoped_accept_survives_a_relearn(tmp_path):
    sess = _session_file(tmp_path, "s.jsonl", {"Read": 2})
    out = tmp_path / "b.json"
    main(["learn", str(sess), "-o", str(out)])
    main(["baseline", "accept", "--link", "agent:Build -> deploy_staging",
          "--baseline", str(out)])
    main(["learn", str(sess), "-o", str(out)])

    b = load_baseline(out)
    assert b.accepted_links == {("agent:Build", "tool:deploy_staging")}
    assert categories(detect(b, scoped_graph(("Build",))), "new_tool") == []
    assert categories(detect(b, scoped_graph(("Test",))), "new_tool")


def test_forget_overrides_drops_them_deliberately(tmp_path):
    sess = _session_file(tmp_path, "s.jsonl", {"Read": 2})
    out = tmp_path / "b.json"
    main(["learn", str(sess), "-o", str(out)])
    main(["baseline", "reject", "--tool", "Bash", "--baseline", str(out)])
    main(["learn", str(sess), "-o", str(out), "--forget-overrides"])
    assert not load_baseline(out).has_overrides


def test_learn_into_a_fresh_path_has_no_overrides_to_carry(tmp_path, capsys):
    sess = _session_file(tmp_path, "s.jsonl", {"Read": 2})
    main(["learn", str(sess), "-o", str(tmp_path / "new.json")])
    assert "Carried forward" not in capsys.readouterr().out


def test_an_unreadable_previous_baseline_does_not_block_learning(tmp_path):
    """A corrupt file loses the decisions; it must not lose the ability to learn."""
    sess = _session_file(tmp_path, "s.jsonl", {"Read": 2})
    out = tmp_path / "b.json"
    out.write_text("{ not json", encoding="utf-8")
    assert main(["learn", str(sess), "-o", str(out)]) == 0
    assert not load_baseline(out).has_overrides
