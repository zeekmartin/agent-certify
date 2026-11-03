# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Anomaly injection benchmark: each injection, and the scoring over all of them."""
import copy
import json

import pytest

from agent_certify.anomaly import CRITICAL, WARNING
from agent_certify.benchmark import (
    ANOMALY_TYPES,
    AnomalyInjector,
    BenchmarkRunner,
    clean_session,
    clean_sessions,
    learn_holdout,
)
from agent_certify.benchmark.__main__ import main
from agent_certify.benchmark.synthetic import TOOLS


@pytest.fixture
def sessions():
    return clean_sessions(8)


@pytest.fixture
def split(sessions):
    """(train, test, baseline) — the baseline never sees the sessions it is measured on."""
    return learn_holdout(sessions)


@pytest.fixture
def session(sessions):
    return sessions[1]


@pytest.fixture
def injector():
    return AnomalyInjector()


# ------------------------------------------------------------- the injectors
def test_new_tool_is_added_and_the_input_is_untouched(injector, session):
    before = copy.deepcopy(session)
    g = injector.inject_new_tool(session, "deploy_prod")
    assert "tool:deploy_prod" in g.nodes and g.nodes["tool:deploy_prod"].metadata["injected"] == "new_tool"
    assert g.get_edge("claude", "tool:deploy_prod").weight == 1
    assert g.total_tool_calls == session.total_tool_calls + 1
    assert g.session_id == f"{session.session_id}+new_tool"
    assert session.to_dict() == before.to_dict()          # the clean session is never modified


def test_new_tool_refuses_a_tool_the_session_already_uses(injector, session):
    with pytest.raises(ValueError, match="already a tool"):
        injector.inject_new_tool(session, TOOLS[0])


def test_error_spike_reaches_the_rate_without_changing_the_topology(injector, session):
    g = injector.inject_error_spike(session, rate=0.15)
    errors = sum(n.error_count for n in g.nodes.values())
    assert errors / g.total_tool_calls >= 0.15
    assert sorted(g.nodes) == sorted(session.nodes)       # no node or edge appears
    assert {(e.source, e.target) for e in g.edges} == {(e.source, e.target) for e in session.edges}
    assert all(e.errors <= e.weight for e in g.edges)     # never more failures than invocations


def test_error_spike_is_deterministic(injector, session):
    first = injector.inject_error_spike(session, rate=0.2)
    second = injector.inject_error_spike(session, rate=0.2)
    assert [(e.source, e.target, e.errors) for e in first.edges] == \
           [(e.source, e.target, e.errors) for e in second.edges]


@pytest.mark.parametrize("rate", [0, -0.1, 1.5])
def test_error_spike_rejects_an_impossible_rate(injector, session, rate):
    with pytest.raises(ValueError, match="rate must be"):
        injector.inject_error_spike(session, rate=rate)


def test_error_spike_needs_calls_to_fail(injector, session):
    empty = copy.deepcopy(session)
    empty.total_tool_calls = 0
    with pytest.raises(ValueError, match="no tool calls"):
        injector.inject_error_spike(empty)
    full = injector.inject_error_spike(session, rate=1.0)
    with pytest.raises(ValueError, match="at or above"):
        injector.inject_error_spike(full, rate=0.5)       # everything already fails


def test_new_agent_links_to_a_known_tool(injector, session):
    g = injector.inject_new_agent(session, "Exfiltrator")
    aid = "agent:Exfiltrator"
    assert g.nodes[aid].kind == "agent" and g.nodes[aid].metadata["agentType"] == "Exfiltrator"
    assert g.get_edge("claude", aid).weight == 1
    linked = [e.target for e in g.edges if e.source == aid]
    assert len(linked) == 1 and g.nodes[linked[0]].kind == "tool"
    assert g.total_tool_calls == session.total_tool_calls + 2


def test_new_agent_refuses_a_type_the_session_already_has(injector, session):
    existing = next(n.metadata["agentType"] for n in session.nodes.values() if n.kind == "agent")
    with pytest.raises(ValueError, match="already an agent"):
        injector.inject_new_agent(session, existing)      # ids are agent:<type>, so the type is enough


def test_volume_spike_multiplies_calls_only(injector, session):
    tool = f"tool:{TOOLS[0]}"
    before = session.nodes[tool].call_count
    g = injector.inject_volume_spike(session, TOOLS[0], factor=10)
    assert g.nodes[tool].call_count == before * 10
    assert sum(e.weight for e in g.edges if e.target == tool) == \
           sum(e.weight for e in session.edges if e.target == tool) * 10
    assert g.total_tool_calls > session.total_tool_calls
    assert sorted(g.nodes) == sorted(session.nodes)


@pytest.mark.parametrize("tool,factor,exc,match", [
    ("Bash", 1, ValueError, "greater than 1"),
    ("nope", 10, KeyError, "no node named"),
    ("claude", 10, ValueError, "not a tool"),
])
def test_volume_spike_rejects_bad_input(injector, session, tool, factor, exc, match):
    with pytest.raises(exc, match=match):
        injector.inject_volume_spike(session, tool, factor=factor)


def test_forbidden_tool_uses_the_tool_and_rejects_it_in_the_baseline(injector, session, split):
    _, _, baseline = split
    g = injector.inject_forbidden_tool(session, TOOLS[0])
    assert g.nodes[f"tool:{TOOLS[0]}"].metadata["injected"] == "forbidden_tool"
    forbidden = injector.forbid(baseline, TOOLS[0])
    assert TOOLS[0] in forbidden.rejected_tools and TOOLS[0] in forbidden.known_tools
    assert TOOLS[0] not in baseline.rejected_tools        # the original baseline is untouched


def test_forbidden_tool_needs_a_name(injector, session):
    with pytest.raises(ValueError, match="tool_name is required"):
        injector.inject_forbidden_tool(session, "")


def test_forbidden_tool_adds_one_the_session_lacks(injector, session):
    g = injector.inject_forbidden_tool(session, "deploy_prod")
    assert g.get_edge("claude", "tool:deploy_prod").weight == 1


def test_caller_falls_back_to_an_agent(injector):
    """A session with no orchestrator (a CrewAI crew of one, say) still takes an injection."""
    from agent_certify.graph import AgentGraph

    g = AgentGraph(session_id="agents-only")
    g.add_node("agent:A", "agent", "A", agentType="A")
    g.add_node("tool:t", "tool", "t")
    g.add_call("agent:A", "tool:t")
    g.total_tool_calls = 1
    assert injector.inject_new_tool(g, "x").get_edge("agent:A", "tool:x") is not None
    with pytest.raises(ValueError, match="no orchestrator or agent"):
        injector.inject_new_tool(AgentGraph(session_id="empty"), "x")


# ----------------------------------------- each injection is detected as expected
def test_injections_cover_every_anomaly_type(injector, session, split):
    _, _, baseline = split
    kinds = [i.kind for i in injector.injections(session, baseline)]
    assert sorted(kinds) == sorted(ANOMALY_TYPES)


@pytest.mark.parametrize("kind,category,severity", [
    ("new_tool", "new_tool", CRITICAL),
    ("error_spike", "error_rate", WARNING),
    ("new_agent", "new_link", WARNING),
    ("forbidden_tool", "new_tool", CRITICAL),
])
def test_injection_produces_the_expected_anomaly_and_severity(split, injector, kind, category, severity):
    """The point of the benchmark: a known fault comes back as the anomaly it should."""
    _, test, baseline = split
    runner = BenchmarkRunner(test, baseline, injector)
    for session in test:
        injection = next(i for i in injector.injections(session, baseline) if i.kind == kind)
        assert injection.expected_category == category and injection.min_severity == severity
        report = runner.detect(injection.graph, injection.baseline or baseline)
        hit = next((a for a in report.anomalies if a.category == category), None)
        assert hit is not None, f"{kind} not reported for {session.session_id}: {report.summary}"
        assert hit.severity in (severity, CRITICAL)      # the expected severity, or an escalation
    assert runner  # the runner is reusable across sessions


def test_forbidden_tool_is_reported_as_rejected_not_as_new(split, injector):
    """A rejected tool fires although the baseline knows it — that is the whole point of rejecting."""
    _, test, baseline = split
    session = test[0]
    injection = next(i for i in injector.injections(session, baseline) if i.kind == "forbidden_tool")
    report = BenchmarkRunner(test, baseline).detect(injection.graph, injection.baseline)
    hit = next(a for a in report.anomalies if a.category == "new_tool")
    assert "Rejected tool used" in hit.message and "rejected" in hit.detail
    # Against the unmodified baseline the same graph is clean: the fault is the decision.
    assert not BenchmarkRunner(test, baseline).detect(injection.graph, baseline).anomalies


def test_volume_spike_is_a_measured_blind_spot(split, injector):
    """No check reads call volume, so 10x the traffic is reported as nothing. Documented, not hidden."""
    _, test, baseline = split
    runner = BenchmarkRunner(test, baseline)
    for session in test:
        injection = next(i for i in injector.injections(session, baseline) if i.kind == "volume_spike")
        assert injection.is_blind_spot and injection.expected_category is None
        assert runner.detect(injection.graph, baseline).anomalies == []


# ------------------------------------------------------------------- runner
def test_runner_scores_the_full_suite(split):
    _, test, baseline = split
    result = BenchmarkRunner(test, baseline).run()
    assert {t.kind for t in result.per_type} == set(ANOMALY_TYPES)
    assert result.detection_rate == 1.0 and result.false_negative_rate == 0.0
    assert result.trials == 4 * len(test)                 # four covered types per session
    assert result.false_positive_rate == 0.0 and result.clean_flagged == 0
    assert result.blind_spots == ["volume_spike"]
    assert result.learned_from == baseline.learned_from
    for t in result.covered:
        assert t.detected == t.trials and t.missed == [] and sum(t.severities.values()) == t.trials


def test_runner_reports_a_false_positive_when_the_baseline_does_not_fit(sessions):
    """A baseline learned from one session flags the others; the benchmark must say so."""
    from agent_certify.baseline import BaselineLearner

    baseline = BaselineLearner().learn_graphs([clean_session(0)])
    result = BenchmarkRunner(sessions[1:4], baseline).run()
    assert result.false_positive_rate > 0 and result.clean_anomalies >= result.clean_flagged


def test_runner_needs_sessions(split):
    _, _, baseline = split
    with pytest.raises(ValueError, match="no sessions"):
        BenchmarkRunner([], baseline)


def test_result_table_and_dict(split):
    _, test, baseline = split
    result = BenchmarkRunner(test, baseline).run()
    table = result.table()
    assert table == str(result)
    assert "Anomaly injection benchmark" in table and "detection rate 100.0%" in table
    for kind in ANOMALY_TYPES:
        assert kind in table
    assert "blind spots: volume_spike" in table
    data = json.loads(json.dumps(result.to_dict()))       # must be JSON-serialisable as it stands
    assert data["detection_rate"] == 1.0 and data["blind_spots"] == ["volume_spike"]
    assert len(data["per_type"]) == len(ANOMALY_TYPES)


def test_learn_holdout_splits_without_overlap(sessions):
    train, test, baseline = learn_holdout(sessions)
    assert len(train) + len(test) == len(sessions)
    assert not {g.session_id for g in train} & {g.session_id for g in test}
    assert baseline.learned_from == len(train)
    with pytest.raises(ValueError, match="at least 3"):
        learn_holdout(sessions[:2], stride=2)


# -------------------------------------------------- synthetic clean sessions
def test_synthetic_sessions_vary(sessions):
    """Identical sessions would give a baseline with zero variance, and meaningless z-scores."""
    assert len({g.total_tool_calls for g in sessions}) > 1
    assert len({sum(1 for n in g.nodes.values() if n.kind == "agent") for g in sessions}) > 1
    assert len({sum(n.error_count for n in g.nodes.values()) for g in sessions}) > 1
    _, _, baseline = learn_holdout(sessions)
    assert baseline.fi_std > 0 and baseline.error_rate_std > 0

    assert clean_session(3).to_dict() == clean_session(3).to_dict()          # reproducible
    assert clean_session(3, seed=1).to_dict() != clean_session(3).to_dict()  # seed jitters it
    with pytest.raises(ValueError, match="at least 1"):
        clean_sessions(0)


# ---------------------------------------------------------------------- cli
def test_cli_table(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "Anomaly injection benchmark" in out and "volume_spike" in out


def test_cli_json(capsys):
    assert main(["--count", "6", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["sessions"] == 6 and data["learned_from"] == 3
    assert data["detection_rate"] == 1.0 and data["blind_spots"] == ["volume_spike"]


def test_cli_on_real_sessions(capsys, session_dir):
    """The suite also runs against parsed logs, not only synthetic sessions."""
    for i in range(2):                                    # three sessions in total: enough to hold one out
        (session_dir / f"copy-{i}.jsonl").write_text((session_dir / "sess-1.jsonl").read_text(encoding="utf-8"),
                                                     encoding="utf-8")
    assert main(["--sessions", str(session_dir)]) == 0
    assert "Anomaly injection benchmark" in capsys.readouterr().out


def test_cli_bad_input(capsys, tmp_path):
    assert main(["--sessions", str(tmp_path / "nope")]) == 1
    assert "Cannot read sessions" in capsys.readouterr().err
    assert main(["--count", "2"]) == 1                    # too few sessions to hold one out
    assert "Cannot benchmark" in capsys.readouterr().err
