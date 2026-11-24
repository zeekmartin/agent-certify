# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""The command line around regions, certificates and the one network option.

`--resolve-dns` is the only thing in agent-certify that opens a socket. These
tests replace `socket.getaddrinfo` with a fake — no test here makes a real
network call — and one of them asserts that nothing reaches it unless the flag
is given.
"""
import json
import socket
import time

import pytest

from agent_certify.cli import main
from agent_certify.domains import MAX_SHELL_SEGMENTS, measure_call
from agent_certify.policy import Policy, PolicyRule

RU_ADDRESS = "77.88.8.8"


@pytest.fixture
def geoip_csv(tmp_path):
    path = tmp_path / "ip2country.csv"
    path.write_text("77.88.8.0,77.88.8.255,RU\n1.0.0.0,1.0.0.255,AU\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def no_dns(monkeypatch):
    """Any name resolution fails the test it happens in."""
    def guard(*args, **kwargs):
        raise AssertionError("a name was resolved without --resolve-dns")

    monkeypatch.setattr(socket, "getaddrinfo", guard)
    return guard


@pytest.fixture
def fake_dns(monkeypatch):
    """Resolution that answers one address, and counts the calls."""
    calls = []

    def fake(host, port=None, *args, **kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (RU_ADDRESS, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return calls


def write_session(directory, name, hosts):
    """A one-call Claude Code session reaching ``hosts``."""
    blocks = [{"type": "tool_use", "id": f"t{i}", "name": "WebFetch",
               "input": {"url": f"https://{host}/v1"}} for i, host in enumerate(hosts)]
    path = directory / name
    path.write_text(json.dumps({"type": "assistant",
                                "message": {"role": "assistant", "content": blocks}}) + "\n",
                    encoding="utf-8")
    return str(path)


# --------------------------------------------------------- regions in a scan
def test_a_region_rule_fires_offline(tmp_path, capsys, no_dns):
    """A ccTLD needs no file and no network."""
    session = write_session(tmp_path, "s.jsonl", ["collector.example.ru", "ok.example.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "data stays in the EU")]).save(policy)
    assert main(["scan", session, "--policy", str(policy), "--no-baseline", "--fail-on", "never"]) == 0
    out = capsys.readouterr().out
    assert "FORBIDDEN region RU: collector.example.ru (RU (ccTLD))" in out
    assert "ok.example.com" not in out


def test_geoip_db_puts_a_country_on_an_address_and_opens_no_socket(tmp_path, capsys, geoip_csv, no_dns):
    session = write_session(tmp_path, "s.jsonl", [RU_ADDRESS])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    # Without the database the address says nothing.
    assert main(["scan", session, "--policy", str(policy), "--no-baseline", "--fail-on", "never"]) == 0
    assert "FORBIDDEN region" not in capsys.readouterr().out
    assert main(["scan", session, "--policy", str(policy), "--no-baseline", "--fail-on", "never",
                 "--geoip-db", geoip_csv]) == 0
    out = capsys.readouterr().out
    assert f"FORBIDDEN region RU: {RU_ADDRESS}" in out
    assert "GeoIP database on an address literal" in out


def test_resolve_dns_resolves_and_says_so(tmp_path, capsys, geoip_csv, fake_dns):
    session = write_session(tmp_path, "s.jsonl", ["mirror.example.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    assert main(["scan", session, "--policy", str(policy), "--no-baseline", "--fail-on", "never",
                 "--geoip-db", geoip_csv, "--resolve-dns"]) == 0
    captured = capsys.readouterr()
    assert "--resolve-dns: resolving destination names over the network" in captured.err
    assert "FORBIDDEN region RU: mirror.example.com" in captured.out
    assert "DNS lookup then GeoIP database" in captured.out
    assert fake_dns == ["mirror.example.com"]


def test_resolve_dns_needs_a_database(tmp_path, no_dns):
    session = write_session(tmp_path, "s.jsonl", ["mirror.example.com"])
    with pytest.raises(SystemExit, match="--resolve-dns needs --geoip-db"):
        main(["scan", session, "--no-baseline", "--no-policy", "--resolve-dns"])


def test_an_unusable_database_stops_the_run(tmp_path, no_dns):
    session = write_session(tmp_path, "s.jsonl", ["x.example.com"])
    empty = tmp_path / "empty.csv"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit, match="no usable address ranges"):
        main(["scan", session, "--no-baseline", "--no-policy", "--geoip-db", str(empty)])
    with pytest.raises(SystemExit, match="cannot read the GeoIP database"):
        main(["scan", session, "--no-baseline", "--no-policy", "--geoip-db", str(tmp_path / "nope.csv")])


def test_skipped_database_rows_are_reported(tmp_path, capsys, no_dns):
    session = write_session(tmp_path, "s.jsonl", ["x.example.com"])
    db = tmp_path / "db.csv"
    db.write_text("1.0.0.0,1.0.0.255,AU\nrubbish\n", encoding="utf-8")
    assert main(["scan", session, "--no-baseline", "--no-policy", "--geoip-db", str(db),
                 "--fail-on", "never"]) == 0
    assert "1 unusable row(s)" in capsys.readouterr().err


def test_no_region_option_opens_no_socket(tmp_path, capsys, no_dns):
    """The default path, which is the one that matters: nothing resolves anything."""
    session = write_session(tmp_path, "s.jsonl", ["a.example.com", "b.example.ru", RU_ADDRESS])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "CN", "critical", "x",
                        unknown_region="warning")]).save(policy)
    assert main(["scan", session, "--policy", str(policy), "--no-baseline", "--fail-on", "never"]) == 0
    out = capsys.readouterr().out
    assert "Region unknown for a.example.com" in out            # and no crash, no lookup


def test_resolve_dns_is_not_an_mcp_option():
    """The server's contract: local files only. The flag exists where a person types it."""
    from agent_certify.mcp_server import TOOLS

    for tool in TOOLS:
        schema = json.dumps(tool["inputSchema"])
        assert "resolve_dns" not in schema and "resolve-dns" not in schema
        assert "geoip" not in schema.lower()


# ------------------------------------------- one resolver for the whole watch
def test_a_watch_resolves_each_name_once_and_leaves_no_thread_behind(tmp_path, geoip_csv):
    """A watch runs for hours; a lookup that times out must not be retried every cycle.

    The resolver is held for the process, so its cache holds the *failures*
    too: a name whose lookup ran past the deadline stays unknown, is never
    looked up again, and leaves exactly one abandoned thread rather than one
    per cycle. The lookup budget is a budget for the run, for the same reason.
    """
    import threading

    from agent_certify.regions import RegionResolver, load_geoip
    from agent_certify.watcher import SessionWatcher

    calls, release = [], threading.Event()

    def blocking(host, port=None, *args, **kwargs):
        calls.append(host)
        release.wait(30)                   # never answers within the deadline
        return []

    resolver = RegionResolver(geoip=load_geoip(geoip_csv), resolve_dns=True,
                              getaddrinfo=blocking, timeout=0.05)
    policy = Policy([PolicyRule("forbidden_region", "RU", "critical", "x")])
    session = tmp_path / "live.jsonl"
    session.write_text("", encoding="utf-8")

    def grow(cycle):
        """One more tool call, reaching the same two hosts every time."""
        blocks = [{"type": "tool_use", "id": f"t{cycle}-{i}", "name": "WebFetch",
                   "input": {"url": f"https://a{i}.example.com/{cycle}"}} for i in (1, 2)]
        with session.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"type": "assistant",
                                     "message": {"role": "assistant", "content": blocks}}) + "\n")

    threads, lookups = [], []

    def after_scan(*_args):
        threads.append(threading.active_count())
        lookups.append(len(calls))

    grow(0)
    watcher = SessionWatcher(str(session), policy=policy, interval=0.01, max_scans=3,
                             out=lambda _line: None, on_scan=after_scan, regions=resolver)
    try:
        for cycle in range(1, 3):          # the file grows between cycles
            watcher.poll()
            grow(cycle)
        watcher.poll()
        assert len(watcher.history) == 3
        # Two names, each resolved once across three cycles.
        assert sorted(set(calls)) == ["a1.example.com", "a2.example.com"]
        assert len(calls) == 2, calls
        assert lookups == [2, 2, 2]
        assert resolver.lookups == 2
        # And no thread accumulation: the abandoned lookups are not re-created.
        assert threads[-1] <= threads[0], threads
    finally:
        release.set()


def test_a_timed_out_name_stays_unknown_for_the_run(geoip_csv):
    """The cache holds failures, which is what stops the retry loop."""
    import threading

    from agent_certify.regions import RegionResolver, load_geoip

    calls, release = [], threading.Event()

    def blocking(host, port=None, *args, **kwargs):
        calls.append(host)
        release.wait(30)
        return []

    resolver = RegionResolver(geoip=load_geoip(geoip_csv), resolve_dns=True,
                              getaddrinfo=blocking, timeout=0.05)
    try:
        for _ in range(5):
            assert resolver.region("slow.example.com").source == "unknown"
        assert calls == ["slow.example.com"]
        assert resolver.lookups == 1
    finally:
        release.set()


# ----------------------------------------------------- certify and verify
def test_certify_signs_the_egress_rules_in_force(tmp_path, capsys, no_dns):
    session = write_session(tmp_path, "s.jsonl", ["api.openai.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU,CN", "critical", "x")]).save(policy)
    out_path = tmp_path / "c.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline",
                 "-o", str(out_path)]) == 0
    printed = capsys.readouterr()
    assert "egress: 1 destination(s)" in printed.out and "2 forbidden region(s)" in printed.out
    assert "review it before publishing" in printed.err
    cert = json.loads(out_path.read_text(encoding="utf-8"))
    assert cert["cert_format"] == 3
    assert cert["egress"] == {"accepted_domains": [], "rejected_domains": [],
                              "forbidden_regions": ["CN", "RU"],
                              "destinations": ["api.openai.com"]}


def test_certify_can_keep_the_rules_and_drop_the_observed_destinations(tmp_path, capsys, no_dns):
    """For a certificate that leaves the organisation: the rules, not the host names."""
    session = write_session(tmp_path, "s.jsonl", ["internal-billing.corp.example", "api.openai.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    out_path = tmp_path / "shared.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline",
                 "--omit-observed-destinations", "-o", str(out_path)]) == 0
    printed = capsys.readouterr()
    assert "destinations not recorded (--omit-observed-destinations)" in printed.out
    assert "review it before publishing" not in printed.err       # there is nothing to review
    text = out_path.read_text(encoding="utf-8")
    assert "internal-billing" not in text and "api.openai.com" not in text
    cert = json.loads(text)
    assert "destinations" not in cert["egress"]
    assert cert["egress"]["forbidden_regions"] == ["RU"]

    # And it still verifies: the signature covers the section as written.
    assert main(["verify", str(out_path), session, "--allow-unsigned", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["is_valid"] and report["added_destinations"] == []
    assert any("no observed destinations" in w for w in report["warnings"])
    assert any("--omit-observed-destinations" in w for w in report["warnings"])


def test_without_an_observed_list_verify_still_enforces_rejections_and_regions(tmp_path, capsys, no_dns):
    certified = write_session(tmp_path, "certified.jsonl", ["api.openai.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    cert_path = tmp_path / "c.cert.json"
    assert main(["certify", certified, "--policy", str(policy), "--no-baseline",
                 "--omit-observed-destinations", "-o", str(cert_path)]) == 0
    capsys.readouterr()

    drifted = write_session(tmp_path, "live.jsonl", ["api.openai.com", "mirror.example.ru",
                                                    "brand.new.example.com"])
    assert main(["verify", str(cert_path), drifted, "--allow-unsigned", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    # A host it never saw cannot be judged; a forbidden region still can.
    assert report["added_destinations"] == []
    assert [hit["country"] for hit in report["forbidden_destinations"]] == ["RU"]
    assert not report["is_valid"]


def test_certify_refuses_a_system_that_already_breaks_its_egress_rules(tmp_path, capsys, no_dns):
    """A certificate says "known good state". Signing over a live violation would say the opposite."""
    session = write_session(tmp_path, "s.jsonl", ["api.openai.com", "collector.example.ru"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "data stays in the EU")]).save(policy)
    out_path = tmp_path / "c.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline",
                 "-o", str(out_path)]) == 1
    err = capsys.readouterr().err
    assert "refusing to certify: 1 destination(s)" in err
    assert "collector.example.ru: in forbidden region RU (ccTLD)" in err
    assert "--allow-egress-violations" in err
    assert not out_path.exists()                               # nothing was written


def test_certify_refuses_a_destination_that_matches_a_rejected_pattern(tmp_path, capsys, no_dns):
    from agent_certify.baseline import BaselineLearner, load_baseline

    session = write_session(tmp_path, "s.jsonl", ["api.openai.com", "api.unknown.cn"])
    baseline_path = tmp_path / "baseline.json"
    BaselineLearner().save(BaselineLearner().learn([session]), baseline_path)
    capsys.readouterr()
    assert main(["baseline", "reject", "--domain", "*.cn", "--baseline", str(baseline_path)]) == 0
    assert load_baseline(baseline_path).rejected_domains == {"*.cn"}
    capsys.readouterr()
    out_path = tmp_path / "c.cert.json"
    assert main(["certify", session, "--baseline", str(baseline_path), "--no-policy",
                 "-o", str(out_path)]) == 1
    err = capsys.readouterr().err
    assert "api.unknown.cn: matches rejected pattern *.cn" in err
    assert not out_path.exists()


def test_allow_egress_violations_signs_and_records_them(tmp_path, capsys, no_dns):
    session = write_session(tmp_path, "s.jsonl", ["api.openai.com", "collector.example.ru"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    key = tmp_path / "issuer.key"
    assert main(["keygen", str(key)]) == 0
    capsys.readouterr()
    out_path = tmp_path / "forced.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline", "--key", str(key),
                 "--allow-egress-violations", "-o", str(out_path)]) == 0
    printed = capsys.readouterr()
    assert "--allow-egress-violations: signing although 1 destination(s)" in printed.err
    assert "collector.example.ru: in forbidden region RU" in printed.err
    cert = json.loads(out_path.read_text(encoding="utf-8"))
    assert cert["egress"]["violations_at_issue"] == [
        "collector.example.ru: in forbidden region RU (ccTLD)"]
    assert cert["signature"]

    # And the forced certificate still fails verification: the signature does
    # not make the violation go away.
    public = (tmp_path / "issuer.key.pub").read_text(encoding="utf-8").strip()
    pub_file = tmp_path / "issuer.pub"
    pub_file.write_text(public, encoding="utf-8")
    assert main(["verify", str(out_path), session, "--public-key", str(pub_file),
                 "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["is_valid"] is False and report["signature_valid"] is True
    assert [hit["host"] for hit in report["forbidden_destinations"]] == ["collector.example.ru"]
    assert any("issued over 1 egress violation(s)" in w for w in report["warnings"])


def test_certify_is_unaffected_when_nothing_is_wrong(tmp_path, capsys, no_dns):
    session = write_session(tmp_path, "s.jsonl", ["api.openai.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    out_path = tmp_path / "c.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline",
                 "-o", str(out_path)]) == 0
    assert "refusing" not in capsys.readouterr().err
    assert "violations_at_issue" not in out_path.read_text(encoding="utf-8")


def test_certify_reads_a_local_database_for_the_refusal(tmp_path, capsys, geoip_csv, no_dns):
    """An address literal in a forbidden region blocks certification too, offline."""
    session = write_session(tmp_path, "s.jsonl", [RU_ADDRESS])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    out_path = tmp_path / "c.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline",
                 "-o", str(out_path)]) == 0                    # no database: nothing to see
    capsys.readouterr()
    other = tmp_path / "d.cert.json"
    assert main(["certify", session, "--policy", str(policy), "--no-baseline",
                 "--geoip-db", geoip_csv, "-o", str(other)]) == 1
    assert f"{RU_ADDRESS}: in forbidden region RU" in capsys.readouterr().err


def test_verify_reports_egress_drift_and_regions(tmp_path, capsys, no_dns):
    certified = write_session(tmp_path, "certified.jsonl", ["api.openai.com"])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    cert_path = tmp_path / "c.cert.json"
    assert main(["certify", certified, "--policy", str(policy), "--no-baseline",
                 "-o", str(cert_path)]) == 0
    capsys.readouterr()

    drifted = write_session(tmp_path, "live.jsonl", ["api.openai.com", "mirror.example.ru"])
    assert main(["verify", str(cert_path), drifted, "--allow-unsigned", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["added_destinations"] == ["mirror.example.ru"]
    assert report["forbidden_destinations"][0]["country"] == "RU"
    assert any("forbidden region RU" in reason for reason in report["reasons"])


def test_verify_can_read_a_local_database_and_still_resolves_nothing(tmp_path, capsys, geoip_csv, no_dns):
    certified = write_session(tmp_path, "certified.jsonl", ["api.openai.com", RU_ADDRESS])
    policy = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "RU", "critical", "x")]).save(policy)
    cert_path = tmp_path / "c.cert.json"
    main(["certify", certified, "--policy", str(policy), "--no-baseline", "-o", str(cert_path)])
    capsys.readouterr()
    assert main(["verify", str(cert_path), certified, "--allow-unsigned", "--format", "json",
                 "--geoip-db", geoip_csv]) == 1
    report = json.loads(capsys.readouterr().out)
    assert [hit["host"] for hit in report["forbidden_destinations"]] == [RU_ADDRESS]
    assert report["forbidden_destinations"][0]["source"] == "geoip"


def test_verify_has_no_resolve_dns_option(tmp_path):
    from agent_certify.cli import build_parser

    actions = {a.dest for p in build_parser()._subparsers._group_actions[0].choices.values()
               for a in p._actions}
    assert "geoip_db" in actions                       # offline, available
    verify = build_parser()._subparsers._group_actions[0].choices["verify"]
    dests = {a.dest for a in verify._actions}
    assert "geoip_db" in dests and "resolve_dns" not in dests
    for command in ("scan", "watch", "learn"):
        parser = build_parser()._subparsers._group_actions[0].choices[command]
        assert "resolve_dns" in {a.dest for a in parser._actions}


# ------------------------------------------------------- the segment bound
def test_a_command_line_of_a_million_commands_is_bounded():
    """10 MB of `a;` with an open quote: nine seconds before, and an MCP call gets thirty."""
    command = "a;" * 5_000_000 + '"'
    started = time.perf_counter()
    egress = measure_call({"command": command})
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"took {elapsed:.2f}s"
    assert egress.domains == set()
    assert "segments" in egress.truncated


def test_the_segment_bound_is_reported_as_a_truncated_scan(tmp_path, capsys, no_dns):
    """It is a bound, so it is published: the destinations of that call are incomplete."""
    from agent_certify.domains import extract_call_domains

    flood = "; ".join(["true"] * (MAX_SHELL_SEGMENTS + 5) + ["curl hidden.example.net/x"])
    egress = measure_call({"command": flood})
    assert "segments" in egress.truncated
    assert "hidden.example.net" not in egress.domains          # past the bound, and said so
    # Under the bound, the same command line reads to the end.
    short = "; ".join(["true"] * 10 + ["curl visible.example.net/x"])
    assert extract_call_domains({"command": short}) == {"visible.example.net"}


def test_an_ordinary_command_line_is_not_truncated():
    for command in ("curl -sS collector.example.net/x",
                    "cd /tmp && curl a.example.net | nc b.example.net 90",
                    "; ".join(f"curl h{i}.example.net/x" for i in range(50))):
        assert "segments" not in measure_call({"command": command}).truncated
