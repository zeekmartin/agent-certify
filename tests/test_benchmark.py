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
    BLIND_SPOTS,
    FALSE_POSITIVE_CASES,
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
    injections = injector.injections(session, baseline)
    kinds = [i.kind for i in injections]
    assert sorted(kinds) == sorted(ANOMALY_TYPES)
    assert len(ANOMALY_TYPES) == 22
    blind = sorted(i.kind for i in injections if i.is_blind_spot)
    assert blind == sorted(BLIND_SPOTS) == ["file_upload_exfil", "shell_var_domain", "ssh_tunnel_domain"]
    assert [i.expected_category for i in injections if i.is_blind_spot] == [None, None, None]
    # A clean session is injected too, and is not a blind spot: silence there
    # is the rule working, not a check missing.
    clean = sorted(i.kind for i in injections if i.false_positive)
    assert clean == sorted(FALSE_POSITIVE_CASES) == ["written_url"]
    assert not any(i.is_blind_spot for i in injections if i.false_positive)


def test_the_blind_spot_branch_is_reachable(injector, session, split):
    """The machinery the report relies on has to be exercised, not merely present.

    The audit of 2026-11-03 found every blind-spot code path unreachable:
    `_add` was only ever called with a category, so `expected_category` was
    never None and the branches in `_score`, `covered` and `table()` could not
    run. This test pins the capability rather than the current result.
    """
    _, test, baseline = split
    injection = next(i for i in injector.injections(session, baseline) if i.is_blind_spot)
    assert injection.is_blind_spot and injection.min_severity is None
    result = BenchmarkRunner(test, baseline).run()
    row = next(t for t in result.per_type if t.kind == injection.kind)
    assert row.is_blind_spot and row.expected == "(blind spot)"
    assert row.trials and row not in result.covered         # excluded from the detection rate
    assert result.blind_spots == list(BLIND_SPOTS)
    assert "not covered by any check" in result.table()


def test_the_blind_spot_injections_are_not_rigged_to_be_silent(injector, session):
    """They run the production extractor; a graph host would make them report."""
    from agent_certify.domains import extract_call_domains

    graph = injector.inject_shell_var_domain(session)
    assert graph.seen_domains == session.seen_domains        # extraction found nothing to record
    assert graph.nodes[injector._busiest_tool(graph)].metadata["injected"] == "shell_var_domain"
    # The same host as an argument of the client *is* extracted, which is what
    # makes the gap specific rather than a claim: only the variable hides it.
    assert extract_call_domains({"command": f"curl -sS {injector.shell_var_domain}/health"}) == {
        injector.shell_var_domain}

    # The tunnel: the jump host is recorded (it is one the session already
    # reaches, so it is no anomaly), and the tunnelled host is not.
    tunnel = injector.inject_ssh_tunnel_domain(session)
    assert tunnel.seen_domains == session.seen_domains
    assert injector.ssh_tunnel_domain not in tunnel.seen_domains
    assert tunnel.nodes[injector._busiest_tool(tunnel)].metadata["injected"] == "ssh_tunnel_domain"
    # Connected to directly, the same host would be reported.
    assert extract_call_domains({"command": f"ssh ops@{injector.ssh_tunnel_domain}"}) == {
        injector.ssh_tunnel_domain}

    for inject in (injector.inject_shell_var_domain, injector.inject_ssh_tunnel_domain,
                   injector.inject_wrapped_shell_domain):
        with pytest.raises(ValueError, match="domain is required"):
            inject(session, "  ")
        with pytest.raises(ValueError, match="already a destination"):
            inject(injector.inject_foreign_domain(session, "taken.example.net"), "taken.example.net")


def test_the_wrapped_shell_injection_is_detected(injector, session, split):
    """bash -c "curl …": the same gap as shell_domain, one level in, and covered too."""
    _, _, baseline = split
    graph = injector.inject_wrapped_shell_domain(session)
    assert injector.wrapped_shell_domain in graph.seen_domains
    assert sorted(graph.nodes) == sorted(session.nodes)      # nothing structural, as ever
    injection = next(i for i in injector.injections(session, baseline) if i.kind == "wrapped_shell_domain")
    assert not injection.is_blind_spot
    assert injection.expected_category == "new_domain" and injection.min_severity == CRITICAL


def test_the_shell_domain_injection_closed_itself(injector, session, split):
    """v0.7.0 measured it as a blind spot; reading the command line turned it into a detection.

    The injection builds the same argument object it always did and passes it
    to the production extractor — nothing in `inject_shell_domain` knows what
    the answer should be. It reports now because extraction reaches further,
    which is the whole case for injecting a gap instead of asserting it.
    """
    _, _, baseline = split
    graph = injector.inject_shell_domain(session)
    assert injector.shell_domain in graph.seen_domains
    assert graph.nodes[injector._busiest_tool(graph)].metadata["injected"] == "shell_domain"
    assert sorted(graph.nodes) == sorted(session.nodes)      # still nothing structural
    assert {(e.source, e.target, e.weight) for e in graph.edges} ==            {(e.source, e.target, e.weight) for e in session.edges}
    injection = next(i for i in injector.injections(session, baseline) if i.kind == "shell_domain")
    assert not injection.is_blind_spot
    assert injection.expected_category == "new_domain" and injection.min_severity == CRITICAL
    with pytest.raises(ValueError, match="domain is required"):
        injector.inject_shell_domain(session, "  ")


def test_the_egress_injectors_refuse_what_they_cannot_inject(injector, session):
    """Every guard, so a fault that does not apply is named rather than half-injected."""
    import copy

    with pytest.raises(ValueError, match="factor must be"):
        injector.inject_exfiltration(session, factor=1)
    with pytest.raises(ValueError, match="decoys must be"):
        injector.inject_decoy_flood(session, decoys=0)
    with pytest.raises(ValueError, match="padding must be"):
        injector.inject_padding_evasion(session, padding=0)
    for inject in (injector.inject_decoy_flood, injector.inject_padding_evasion):
        with pytest.raises(ValueError, match="domain is required"):
            inject(session, "  ")
        taken = injector.inject_foreign_domain(session, "taken.example.net")
        with pytest.raises(ValueError, match="already a destination"):
            inject(taken, "taken.example.net")

    # A session that sent nothing anywhere has no volume to multiply.
    quiet = copy.deepcopy(session)
    quiet.egress_bytes.clear()
    quiet.egress_calls.clear()
    with pytest.raises(ValueError, match="reached no destination"):
        injector.inject_exfiltration(quiet)
    with pytest.raises(ValueError, match="reached no destination"):
        injector.inject_file_upload_exfil(quiet)
    with pytest.raises(ValueError, match="no outbound volume"):
        injector.inject_exfiltration(quiet, domain="api.internal.example")


def test_the_exfiltration_injection_changes_nothing_but_the_bytes(injector, session, split):
    """The case for the check: every structural number is identical."""
    _, _, baseline = split
    g = injector.inject_exfiltration(session, factor=20)
    assert sorted(g.nodes) == sorted(session.nodes)
    assert {(e.source, e.target, e.weight) for e in g.edges} ==            {(e.source, e.target, e.weight) for e in session.edges}
    assert g.total_tool_calls == session.total_tool_calls
    assert g.seen_domains == session.seen_domains            # the same host as always
    host = injector._busiest_domain(session)
    assert g.egress_bytes[host] > 20 * session.egress_bytes[host]
    report = BenchmarkRunner([session], baseline).detect(g, baseline)
    assert [a.category for a in report.anomalies] == ["egress_volume_spike"]


def test_the_decoy_flood_is_reported_as_a_truncated_scan(injector, session, split):
    """The hidden host is still not read — the bound is real — but the session is not clean."""
    _, _, baseline = split
    injection = next(i for i in injector.injections(session, baseline) if i.kind == "decoy_flood")
    g = injection.graph
    assert injector.hidden_domain not in g.seen_domains      # past MAX_DOMAINS: not seen, as advertised
    assert g.truncated_scans == 1 and g.truncated_network_scans == 1
    report = BenchmarkRunner([session], baseline).detect(g, injection.baseline)
    assert [a.category for a in report.anomalies] == ["destination_scan_truncated"]
    assert report.anomalies[0].severity == CRITICAL


def test_the_padding_evasion_is_read_through_the_padding(injector, session, split):
    """70 000 characters of echo used to hide the host that followed. It no longer does."""
    _, _, baseline = split
    g = injector.inject_padding_evasion(session)
    assert injector.padded_domain in g.seen_domains
    assert g.truncated_scans == 0                            # nothing was cut: the string is read whole
    report = BenchmarkRunner([session], baseline).detect(g, baseline)
    assert [a.category for a in report.anomalies] == ["new_domain"]


def test_the_file_upload_blind_spot_is_silent_but_present(injector, session, split):
    """The log holds the file's name, never its size: measured, not hidden."""
    _, _, baseline = split
    g = injector.inject_file_upload_exfil(session)
    host = injector._busiest_domain(session)
    assert g.egress_calls[host] == session.egress_calls[host] + 1      # the call is seen
    assert g.egress_bytes[host] < session.egress_bytes[host] * 1.1     # the payload is not
    assert BenchmarkRunner([session], baseline).detect(g, baseline).anomalies == []


def test_the_written_url_case_is_a_clean_session(injector, session, split):
    """A Write whose contents name a host: nothing to find, and nothing found.

    Not a blind spot — the rule is right, and this is the measurement that says
    so. It is also the shape that produced 35 of 56 new_domain alerts on real
    logs before content stopped being read.
    """
    _, _, baseline = split
    g = injector.inject_written_url(session)
    assert injector.written_domain not in g.seen_domains
    assert g.seen_domains == session.seen_domains and g.egress_bytes == session.egress_bytes
    assert g.nodes[injector._busiest_tool(g)].metadata["injected"] == "written_url"
    report = BenchmarkRunner([session], baseline).detect(g, baseline)
    assert report.anomalies == []

    injection = next(i for i in injector.injections(session, baseline) if i.kind == "written_url")
    assert injection.false_positive and not injection.is_blind_spot
    assert injection.expected_category is None

    # The same host in a command *is* read: that is the line being drawn.
    from agent_certify.domains import extract_call_domains
    assert extract_call_domains({"command": f"curl -sS {injector.written_domain}/drop"}) == {
        injector.written_domain}
    with pytest.raises(ValueError, match="domain is required"):
        injector.inject_written_url(session, "  ")
    with pytest.raises(ValueError, match="already a destination"):
        injector.inject_written_url(injector.inject_foreign_domain(session, "taken.example.net"),
                                    "taken.example.net")


def test_a_reported_false_positive_case_is_named_as_one(split, injector):
    """The row has to be able to fail, or it measures nothing."""
    from agent_certify.benchmark.runner import TypeResult

    row = TypeResult(kind="written_url", expected_category=None, min_severity=None,
                     false_positive=True, trials=6, detected=2)
    assert row.expected == "(must stay silent)" and row.quiet == 4
    assert not row.is_blind_spot
    result = BenchmarkRunner(split[1], split[2]).run()
    assert result.injected_false_positives == 0
    assert [t.kind for t in result.false_positive_cases] == ["written_url"]
    assert "silent, as it must be" in result.table()
    data = result.to_dict()
    assert data["false_positive_cases"] == ["written_url"] and data["injected_false_positives"] == 0
    assert next(t for t in data["per_type"] if t["kind"] == "written_url")["false_positive_case"]


def test_the_region_injection_is_scored_against_the_policy(injector, session, split):
    """The one fault the policy owns rather than the baseline.

    A destination in a forbidden country is not unusual, it is not allowed; no
    amount of history makes it normal, and nothing in a baseline would ever
    report it. The runner has to check policies for the suite to measure that.
    """
    _, _, baseline = split
    g = injector.inject_forbidden_region(session)
    assert injector.region_domain in g.seen_domains
    assert sorted(g.nodes) == sorted(session.nodes)              # nothing structural
    injection = next(i for i in injector.injections(session, baseline) if i.kind == "forbidden_region")
    assert injection.expected_rule == "forbidden_region" and injection.min_severity == CRITICAL
    assert injection.expected_category is None and not injection.is_blind_spot
    assert injection.policy is not None and injection.policy.rules[0].regions == ["RU"]

    violations = BenchmarkRunner([session], baseline).check_policy(g, injection.policy)
    assert [v.rule.kind for v in violations] == ["forbidden_region"]
    assert "RU" in violations[0].message and injector.region_domain in violations[0].message
    assert "ccTLD" in violations[0].message                      # how it was decided

    # And the clean session it was injected into violates nothing.
    assert BenchmarkRunner([session], baseline).check_policy(session, injection.policy) == []


def test_the_runner_scores_a_policy_fault_like_any_other(split, injector):
    _, test, baseline = split
    result = BenchmarkRunner(test, baseline).run()
    row = next(t for t in result.per_type if t.kind == "forbidden_region")
    assert row.expected_rule == "forbidden_region" and row.expected == "policy forbidden_region/crit"
    assert row.detected == row.trials == len(test) and row.missed == []
    assert row.severities == {CRITICAL: len(test)}
    assert row in result.covered and not row.is_blind_spot and not row.false_positive
    # Both region faults are scored against the policy engine: the second one
    # is the same fault under an internationalised ccTLD.
    assert [t.kind for t in result.policy_cases] == ["forbidden_region", "forbidden_region_idn"]
    assert result.to_dict()["policy_cases"] == ["forbidden_region", "forbidden_region_idn"]
    assert next(t for t in result.to_dict()["per_type"]
                if t["kind"] == "forbidden_region")["expected_rule"] == "forbidden_region"
    assert "policy forbidden_region/crit" in result.table()


def test_a_policy_fault_counts_as_missed_when_the_rule_is_not_there(split, injector, session):
    """The row must be able to fail: with no region rule, nothing is violated."""
    from agent_certify.benchmark.runner import TypeResult
    from agent_certify.policy import Policy

    _, test, baseline = split
    runner = BenchmarkRunner(test, baseline)
    injection = next(i for i in injector.injections(session, baseline) if i.kind == "forbidden_region")
    toothless = Policy(rules=[])
    assert runner.check_policy(injection.graph, toothless) == []
    assert runner.check_policy(injection.graph, None) == []
    row = TypeResult(kind="forbidden_region", expected_category=None, min_severity=CRITICAL,
                     expected_rule="forbidden_region")
    runner._score(row, replace_policy(injection, toothless))
    assert row.detected == 0 and row.missed == [injection.graph.session_id]


def replace_policy(injection, policy):
    import dataclasses

    return dataclasses.replace(injection, policy=policy)


def test_forbid_region_builds_the_rule_the_benchmark_needs(injector):
    policy = injector.forbid_region("RU,CN")
    assert [r.kind for r in policy.rules] == ["forbidden_region"]
    assert policy.rules[0].regions == ["CN", "RU"] and policy.rules[0].severity == CRITICAL
    assert injector.forbid_region("RU", severity=WARNING).rules[0].severity == WARNING


def test_accept_domain_leaves_the_original_baseline_alone(injector, split):
    _, _, baseline = split
    accepted = injector.accept_domain(baseline, "*.decoy.example.net")
    assert accepted.accepted_domains == {"*.decoy.example.net"}
    assert baseline.accepted_domains == set()


def test_foreign_domain_injector_guards(injector, session):
    graph = injector.inject_foreign_domain(session, "API.Unknown.CN")
    assert "api.unknown.cn" in graph.seen_domains
    assert session.seen_domains == {"api.internal.example"}      # the clean session is untouched
    with pytest.raises(ValueError, match="already a destination"):
        injector.inject_foreign_domain(graph, "api.unknown.cn")
    with pytest.raises(ValueError, match="domain is required"):
        injector.inject_foreign_domain(session, "  ")


@pytest.mark.parametrize("kind,category,severity", [
    # The fixture baseline is four sessions, under MIN_BASELINE_SESSIONS, so an
    # unknown tool is expected at warning — the injector takes the expectation
    # from the rule rather than assuming one (see the test below).
    ("new_tool", "new_tool", WARNING),
    ("error_spike", "error_rate", WARNING),
    ("new_agent", "new_link", WARNING),
    ("volume_spike", "call_volume_spike", WARNING),
    ("forbidden_tool", "new_tool", CRITICAL),
    ("foreign_domain", "new_domain", CRITICAL),
    ("shell_domain", "new_domain", CRITICAL),
    ("wrapped_shell_domain", "new_domain", CRITICAL),
    ("exfiltration", "egress_volume_spike", WARNING),
    ("decoy_flood", "destination_scan_truncated", CRITICAL),
    ("padding_evasion", "new_domain", CRITICAL),
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


def test_the_expected_severity_of_new_tool_follows_the_baseline_size(sessions, injector):
    """A thin baseline turns an unknown tool into a warning, and the suite knows it.

    The benchmark would otherwise score a miss for a rule the detector is
    following on purpose: the expectation has to come from the same rule.
    """
    from agent_certify.anomaly import MIN_BASELINE_SESSIONS

    thin = learn_holdout(sessions)[2]                       # four sessions
    assert thin.learned_from < MIN_BASELINE_SESSIONS
    injection = next(i for i in injector.injections(sessions[1], thin) if i.kind == "new_tool")
    assert injection.min_severity == WARNING and "expected at warning" in injection.note

    thick = learn_holdout(clean_sessions(12))[2]            # six sessions
    assert thick.learned_from >= MIN_BASELINE_SESSIONS
    injection = next(i for i in injector.injections(sessions[1], thick) if i.kind == "new_tool")
    assert injection.min_severity == CRITICAL and "expected at warning" not in injection.note


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


def test_volume_spike_was_the_blind_spot_and_is_now_caught(split, injector):
    """The fault v0.6.1 measured as a miss. It is now reported, and nothing else about it moved."""
    _, test, baseline = split
    runner = BenchmarkRunner(test, baseline)
    for session in test:
        injection = next(i for i in injector.injections(session, baseline) if i.kind == "volume_spike")
        assert not injection.is_blind_spot
        report = runner.detect(injection.graph, baseline)
        hit = next(a for a in report.anomalies if a.category == "call_volume_spike")
        assert hit.severity == CRITICAL and hit.z_score > 5        # 10x is far past 5 sigma
        assert "called" in hit.message and "times" in hit.message
        # The injection adds no node, no link and no failure: volume is the only thing out of place.
        assert sorted(injection.graph.nodes) == sorted(session.nodes)
        assert {a.category for a in report.anomalies} == {"call_volume_spike"}


def test_foreign_domain_is_detected_without_any_structural_change(split, injector):
    """A tool pointed at another host looks identical in the topology."""
    _, test, baseline = split
    runner = BenchmarkRunner(test, baseline)
    for session in test:
        injection = next(i for i in injector.injections(session, baseline) if i.kind == "foreign_domain")
        graph = injection.graph
        assert sorted(graph.nodes) == sorted(session.nodes)
        assert {(e.source, e.target, e.weight) for e in graph.edges} == \
               {(e.source, e.target, e.weight) for e in session.edges}
        report = runner.detect(graph, baseline)
        hit = next(a for a in report.anomalies if a.category == "new_domain")
        assert hit.severity == CRITICAL and "api.unknown.cn" in hit.message
        assert {a.category for a in report.anomalies} == {"new_domain"}


def test_forbidden_domain_fires_for_a_learned_host(split, injector):
    """forbid_domain() exercises the operator's decision, not new_domain."""
    _, test, baseline = split
    from agent_certify.benchmark.synthetic import HOME_DOMAIN

    rejected = injector.forbid_domain(baseline, HOME_DOMAIN)
    report = BenchmarkRunner(test, baseline).detect(test[0], rejected)
    hit = next(a for a in report.anomalies if a.category == "rejected_domain")
    assert hit.severity == CRITICAL and HOME_DOMAIN in hit.message
    assert HOME_DOMAIN not in baseline.rejected_domains       # the original baseline is untouched
    assert not BenchmarkRunner(test, baseline).detect(test[0], baseline).anomalies


# ------------------------------------------------------------------- runner
def test_runner_scores_the_full_suite(split):
    _, test, baseline = split
    result = BenchmarkRunner(test, baseline).run()
    assert {t.kind for t in result.per_type} == set(ANOMALY_TYPES)
    assert result.detection_rate == 1.0 and result.false_negative_rate == 0.0
    covered = len(ANOMALY_TYPES) - len(BLIND_SPOTS) - len(FALSE_POSITIVE_CASES)
    assert result.trials == covered * len(test)    # blind spots and clean cases are not in the rate
    assert result.false_positive_rate == 0.0 and result.clean_flagged == 0
    assert result.blind_spots == list(BLIND_SPOTS)            # measured, not asserted away
    # The clean session injected on purpose: nothing reported about it, ever.
    assert [t.kind for t in result.false_positive_cases] == list(FALSE_POSITIVE_CASES)
    assert result.injected_false_positives == 0
    for t in result.false_positive_cases:
        assert t.trials == len(test) and t.quiet == t.trials and t.expected == "(must stay silent)"
    assert "stayed silent, as a clean session must" in result.table()
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
    assert "Anomaly injection benchmark" in table
    # Both rates, side by side. See INT-002: the covered-only figure never
    # appears on its own, here or anywhere else.
    assert "detection 100.0% (" in table and "among covered types" in table
    assert "of all injected faults, blind spots included" in table
    for kind in ANOMALY_TYPES:
        assert kind in table
    assert "blind spots: shell_var_domain" in table       # the line only appears when there are some
    assert "what was injected:" in table                  # every row's note is rendered
    assert all(t.note in table for t in result.per_type)
    data = json.loads(json.dumps(result.to_dict()))       # must be JSON-serialisable as it stands
    assert data["detection_rate"] == 1.0 and data["blind_spots"] == list(BLIND_SPOTS)
    assert [t["kind"] for t in data["per_type"] if t["blind_spot"]] == list(BLIND_SPOTS)
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
    assert "foreign_domain" in out


def test_cli_json(capsys):
    assert main(["--count", "6", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["sessions"] == 6 and data["learned_from"] == 3
    assert data["detection_rate"] == 1.0 and data["blind_spots"] == list(BLIND_SPOTS)
    assert len(data["per_type"]) == len(ANOMALY_TYPES)


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


# ---------------------------------------------------------------------------
# The five injections for the egress false negatives of 2026-11-24. Each one
# was silence in a released version, so each one is measured from now on.
AUDIT_INJECTIONS = ("idn_domain", "cloud_storage", "dns_exfil", "numeric_ipv4",
                    "assignment_substitution")


@pytest.mark.parametrize("kind", AUDIT_INJECTIONS)
def test_an_audited_false_negative_is_now_detected(kind, injector, session, split):
    _, _, baseline = split
    injection = next(i for i in injector.injections(session, baseline) if i.kind == kind)
    assert injection.expected_category == "new_domain"
    assert injection.min_severity == "critical"
    assert kind not in BLIND_SPOTS
    reached = injection.graph.seen_domains - session.seen_domains
    assert reached, f"{kind} injected nothing: the fault has to be reachable to be measured"


def test_the_audited_injections_record_their_destination_the_way_production_does(injector, session, split):
    """The injections go through measure_call, not around it.

    An injection that wrote the expected destination straight into the graph
    would pass whatever the extractor does — it would measure the benchmark
    instead of the tool. These build a real argument object and record what
    comes back, so the one Unicode host injected has to come out as punycode
    and the bucket as ``s3:…``.
    """
    _, _, baseline = split
    found = {i.kind: i.graph.seen_domains - session.seen_domains
             for i in injector.injections(session, baseline) if i.kind in AUDIT_INJECTIONS}
    assert found["idn_domain"] == {"collector.xn--p1ai"}       # punycode, not the Unicode form
    assert found["cloud_storage"] == {"s3:benchmark-exfil"}
    assert found["numeric_ipv4"] == {"127.0.0.1"}              # canonical, not 2130706433
    assert found["dns_exfil"] == {"secret.benchmark.unknown.cn"}
    assert found["assignment_substitution"] == {"assigned.unknown.cn"}


def test_both_detection_rates_are_reported_together(split):
    """INT-002: the covered-only rate never stands alone.

    102/102 among covered types reads as "nothing gets past this" while three
    declared blind spots sit in the same table. Quoting the second figure
    beside it is the whole point, so the table, the JSON summary and the README
    all carry both.
    """
    _, test, baseline = split
    result = BenchmarkRunner(test, baseline).run()
    assert result.all_trials > result.trials          # the blind spots are in the denominator
    assert result.overall_detection_rate < result.detection_rate
    summary = result.to_dict()
    assert summary["all_trials"] == result.all_trials
    assert summary["overall_detection_rate"] == result.overall_detection_rate
    table = result.table()
    assert "among covered types" in table
    assert "of all injected faults, blind spots included" in table
    # The one line that carries a rate carries both of them.
    rate_lines = [line for line in table.splitlines() if line.startswith("detection ")]
    assert len(rate_lines) == 1
    assert "among covered types;" in rate_lines[0] and "all injected faults" in rate_lines[0]


def test_the_internationalised_region_fault_is_scored_as_a_policy_violation(split, injector, session):
    """A rule naming RU has to catch a destination under `xn--p1ai`.

    The quiet half of a policy that looks like it works: the destination was
    recorded and reported as new, and the region rule — the one the operator
    wrote to stop exactly this — said nothing, because the two-letter table
    could not answer for a label that is not two letters.
    """
    _, test, baseline = split
    injection = next(i for i in injector.injections(session, baseline)
                     if i.kind == "forbidden_region_idn")
    assert injection.expected_rule == "forbidden_region"
    assert injection.min_severity == CRITICAL
    assert injector.region_idn_domain in injection.graph.seen_domains

    violations = BenchmarkRunner([session], baseline).check_policy(injection.graph, injection.policy)
    assert [v.rule.kind for v in violations] == ["forbidden_region"]
    assert "RU" in violations[0].message
    assert injector.region_idn_domain in violations[0].message
    assert "ccTLD (IDN)" in violations[0].message        # and it says which table answered

    result = BenchmarkRunner(test, baseline).run()
    row = next(t for t in result.per_type if t.kind == "forbidden_region_idn")
    assert row.detected == row.trials == len(test) and row.missed == []
    assert row.expected == "policy forbidden_region/crit"
