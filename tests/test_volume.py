# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Call volume: what a baseline learns about how much a tool is used, and when a spike fires."""
import pytest
from conftest import session_graph

from agent_certify import AgentFIScanner, AnomalyDetector, BaselineLearner
from agent_certify.anomaly import (
    CRITICAL,
    VOLUME_RATIO_WARNING,
    VOLUME_SIGMA_CRITICAL,
    VOLUME_SIGMA_WARNING,
    WARNING,
)
from agent_certify.baseline import link_volume


def detect(graph, baseline):
    return AnomalyDetector(baseline, "test").detect(graph, AgentFIScanner(graph).scan())


def volume_anomalies(graph, baseline):
    return [a for a in detect(graph, baseline).anomalies if a.category == "call_volume_spike"]


@pytest.fixture
def sessions():
    """Eight sessions calling Bash around 50 times, with real variation to learn from."""
    return [session_graph(f"s{i}", {"Bash": 46 + 2 * i, "Read": 10}) for i in range(8)]


@pytest.fixture
def baseline(sessions):
    return BaselineLearner().learn_graphs(sessions)


# ------------------------------------------------------------------- learning
def test_baseline_records_per_tool_volume(baseline):
    stats = baseline.volume("tool", "Bash")
    assert stats["mean"] == pytest.approx(53.0)
    assert stats["std"] == pytest.approx(4.58, abs=0.01)
    assert stats["max"] == 60.0 and stats["sessions"] == 8.0
    assert baseline.volume("tool", "never_used") is None       # nothing to deviate from


def test_baseline_records_per_link_volume(baseline):
    assert baseline.volume("link", "claude -> tool:Bash")["mean"] == pytest.approx(53.0)
    assert baseline.volume("link", "claude -> tool:nope") is None


def test_link_volume_aggregates_by_role():
    """Two sub-agents of one type sharing a tool are one link used twice."""
    g = session_graph("s", {"Bash": 4}, agents=2)
    assert link_volume(g)["agent:Explore -> tool:Bash"] == 2    # one call each, same role
    assert link_volume(g)["claude -> agent:Explore"] == 2
    assert all(" -> " in key for key in link_volume(g))


def test_tools_absent_from_a_session_do_not_drag_the_mean_down():
    """A tool used in one session of ten is averaged over the session it appeared in."""
    sessions = [session_graph("a", {"Bash": 10}), session_graph("b", {"Bash": 10}),
                session_graph("c", {"Bash": 10, "deploy": 4})]
    b = BaselineLearner().learn_graphs(sessions)
    assert b.volume("tool", "deploy") == {"mean": 4.0, "std": 0.0, "max": 4.0, "sessions": 1.0}
    assert not volume_anomalies(session_graph("d", {"Bash": 10, "deploy": 4}), b)


# ------------------------------------------------------------------ detection
def test_normal_volume_is_not_flagged(baseline, sessions):
    for session in sessions:
        assert volume_anomalies(session, baseline) == []
    assert volume_anomalies(session_graph("mid", {"Bash": 53, "Read": 10}), baseline) == []


def test_three_sigma_spike_is_a_warning(baseline):
    stats = baseline.volume("tool", "Bash")
    count = int(stats["mean"] + VOLUME_SIGMA_WARNING * stats["std"]) + 2      # just past 3 sigma
    hits = volume_anomalies(session_graph("spike", {"Bash": count, "Read": 10}), baseline)
    assert [a.severity for a in hits] == [WARNING]
    assert VOLUME_SIGMA_WARNING < hits[0].z_score < VOLUME_SIGMA_CRITICAL


def test_five_sigma_spike_is_critical(baseline):
    stats = baseline.volume("tool", "Bash")
    count = int(stats["mean"] + VOLUME_SIGMA_CRITICAL * stats["std"]) + 2
    hits = volume_anomalies(session_graph("spike", {"Bash": count, "Read": 10}), baseline)
    assert [a.severity for a in hits] == [CRITICAL]
    assert hits[0].z_score > VOLUME_SIGMA_CRITICAL


def test_exactly_at_three_sigma_is_not_flagged():
    """The check is strictly past the threshold, like every other z-score check in the module."""
    two = [session_graph("a", {"Bash": 50}), session_graph("b", {"Bash": 54})]
    b = BaselineLearner().learn_graphs(two)
    assert b.volume("tool", "Bash")["mean"] == 52.0 and b.volume("tool", "Bash")["std"] == 2.0
    assert volume_anomalies(session_graph("at", {"Bash": 58}), b) == []      # z == 3.0 exactly
    assert len(volume_anomalies(session_graph("past", {"Bash": 59}), b)) == 1


def test_exactly_at_five_sigma_is_a_warning_not_a_critical():
    """Both bounds are exclusive, as "warning past 3 sigma; critical past 5" says.

    The critical bound used `z >= 5` while the warning bound used `z > 3`, so a
    deviation of exactly 5.0 sigma came back critical where all three texts
    describing the check put it at warning (audit DOC-017).
    """
    two = [session_graph("a", {"Bash": 50}), session_graph("b", {"Bash": 54})]
    b = BaselineLearner().learn_graphs(two)                 # mean 52, std 2
    at = volume_anomalies(session_graph("at", {"Bash": 62}), b)
    assert [a.z_score for a in at] == [VOLUME_SIGMA_CRITICAL]        # z == 5.0 exactly
    assert [a.severity for a in at] == [WARNING]
    past = volume_anomalies(session_graph("past", {"Bash": 63}), b)
    assert [a.severity for a in past] == [CRITICAL] and past[0].z_score > VOLUME_SIGMA_CRITICAL


def test_a_quiet_session_is_never_an_anomaly(baseline):
    """Volume dropping is not a risk: only increases are reported."""
    assert volume_anomalies(session_graph("quiet", {"Bash": 1, "Read": 1}), baseline) == []


def test_message_names_the_tool_the_count_and_the_baseline(baseline):
    hits = volume_anomalies(session_graph("spike", {"Bash": 487, "Read": 10}), baseline)
    assert hits[0].message == "Tool Bash called 487 times (baseline: 53 ± 5, 94.7σ)"
    assert hits[0].value == 487 and hits[0].baseline_value == "53 ± 5"
    assert "called by claude" in hits[0].detail


# --------------------------------------------------------------------- scoping
@pytest.fixture
def shared_baseline():
    """Eight sessions where claude and one Explore agent both call Bash."""
    return BaselineLearner().learn_graphs(
        [session_graph(f"s{i}", {"Bash": 46 + 2 * i, "Read": 10}, agents=1) for i in range(8)])


def test_a_link_spike_names_the_caller_and_replaces_the_tool_anomaly(shared_baseline):
    """One agent responsible for a spike should be named, not the tool everyone shares."""
    g = session_graph("spike", {"Bash": 46, "Read": 10}, agents=1)
    g.add_call("agent:spike-0", "tool:Bash", count=400)
    g.total_tool_calls += 400
    hits = volume_anomalies(g, shared_baseline)
    assert len(hits) == 1                                   # the tool-level duplicate is left out
    assert hits[0].message.startswith("Link agent:Explore -> tool:Bash called 401 times")
    assert "other callers of tool:Bash are compared separately" in hits[0].detail
    # claude called Bash its usual number of times and is not named anywhere.
    assert "claude ->" not in hits[0].message


def test_a_single_caller_is_reported_as_the_tool(baseline):
    """With one caller the link adds nothing, so the message is about the tool itself."""
    hits = volume_anomalies(session_graph("spike", {"Bash": 400, "Read": 10}), baseline)
    assert len(hits) == 1 and hits[0].message.startswith("Tool Bash called 400 times")


def test_another_caller_at_normal_volume_does_not_trigger(baseline):
    """The spike is scoped to the link that caused it."""
    sessions = [session_graph(f"s{i}", {"Bash": 46 + 2 * i, "Read": 10}, agents=1) for i in range(8)]
    scoped = BaselineLearner().learn_graphs(sessions)
    assert scoped.volume("link", "agent:Explore -> tool:Bash")["mean"] == 1.0

    quiet = session_graph("normal", {"Bash": 52, "Read": 10}, agents=1)
    assert volume_anomalies(quiet, scoped) == []

    noisy = session_graph("noisy", {"Bash": 52, "Read": 10}, agents=1)
    noisy.add_call("agent:noisy-0", "tool:Bash", count=200)
    hits = volume_anomalies(noisy, scoped)
    assert len(hits) == 1 and hits[0].message.startswith("Link agent:Explore -> tool:Bash")


def test_a_new_tool_or_link_has_no_volume_to_compare(baseline):
    """Absence is new_tool's business; a volume check needs something learned."""
    g = session_graph("new", {"Bash": 50, "Read": 10, "deploy_prod": 900})
    categories = {a.category for a in detect(g, baseline).anomalies}
    assert "new_tool" in categories and "call_volume_spike" not in categories


# -------------------------------------------------------------------- fallback
def test_single_session_baseline_falls_back_to_a_multiple_of_the_mean():
    """With no deviation to compare against, past 2x the mean is a warning with no z-score."""
    b = BaselineLearner().learn_graphs([session_graph("only", {"Bash": 50})])
    assert b.volume("tool", "Bash") == {"mean": 50.0, "std": 0.0, "max": 50.0, "sessions": 1.0}
    assert volume_anomalies(session_graph("same", {"Bash": 50}), b) == []
    assert volume_anomalies(session_graph("twice", {"Bash": 100}), b) == []      # 2x is the boundary
    hits = volume_anomalies(session_graph("over", {"Bash": 101}), b)
    assert len(hits) == 1 and hits[0].severity == WARNING and hits[0].z_score is None
    assert "no variation to compare against" in hits[0].message
    assert f"past {VOLUME_RATIO_WARNING:g}x" in hits[0].message


def test_identical_sessions_also_fall_back():
    """Several sessions that never varied are the same case as one session."""
    b = BaselineLearner().learn_graphs([session_graph(f"s{i}", {"Bash": 20}) for i in range(5)])
    assert b.volume("tool", "Bash")["std"] == 0.0 and b.volume("tool", "Bash")["sessions"] == 5.0
    assert volume_anomalies(session_graph("same", {"Bash": 40}), b) == []
    assert len(volume_anomalies(session_graph("spike", {"Bash": 41}), b)) == 1


def test_report_and_json_carry_the_anomaly(baseline):
    report = detect(session_graph("spike", {"Bash": 487, "Read": 10}), baseline)
    assert report.has_critical
    hit = next(a for a in report.to_dict()["anomalies"] if a["category"] == "call_volume_spike")
    assert hit["severity"] == CRITICAL and hit["value"] == 487
    assert "Tool Bash called 487 times" in str(report)
