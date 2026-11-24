# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""The signed ``egress`` section: what a certificate says about where data may go.

Two things are load-bearing here. A certificate must record the egress rules in
force when it was issued, so that drift in *destinations* is as checkable as
drift in topology. And every certificate issued before this must keep verifying
with its original bytes — a format change that breaks old signatures is not a
format change, it is a revocation.
"""
import base64
import json

import pytest
from conftest import session_graph
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_certify import AgentCertificate, generate_keypair, graph_hash
from agent_certify.baseline import BaselineLearner
from agent_certify.certificate import (
    CURRENT_FORMAT,
    DOMAIN,
    EGRESS_KEYS,
    _public_hex,
    _topology,
    egress_section,
    egress_violations,
)
from agent_certify.policy import Policy, PolicyRule
from agent_certify.regions import RegionResolver, load_geoip


def session(hosts=("api.openai.com",), tool="WebFetch"):
    g = session_graph("sess", {tool: 3, "Read": 2})
    if hosts:
        g.record_egress(f"tool:{tool}", set(hosts), outbound_bytes=500)
    return g


@pytest.fixture
def baseline():
    b = BaselineLearner().learn_graphs([session() for _ in range(3)])
    b.accepted_domains.add("*.openai.com")
    b.rejected_domains.add("*.cn")
    return b


@pytest.fixture
def policy():
    return Policy([PolicyRule("forbidden_region", "RU,CN", "critical", "data stays in the EU"),
                   PolicyRule("forbidden_tool", "deploy_prod", "critical", "not from here")])


# ------------------------------------------------------------------ the section
def test_the_section_records_the_rules_in_force_and_what_was_seen(baseline, policy):
    cert = AgentCertificate.create(session(["api.openai.com", "eu.openai.com"]),
                                   baseline=baseline, policy=policy)
    assert cert.cert_format == CURRENT_FORMAT == 3
    # Every key but the last: nothing was violated, so there is nothing to record.
    assert set(cert.egress) == set(EGRESS_KEYS) - {"violations_at_issue"}
    assert cert.egress == {
        "accepted_domains": ["*.openai.com"],
        "rejected_domains": ["*.cn"],
        "forbidden_regions": ["CN", "RU"],          # the union of every region rule, sorted
        "destinations": ["api.openai.com", "eu.openai.com"],
    }


def test_the_section_is_filled_without_a_baseline_or_policy():
    """What was observed is worth signing on its own."""
    cert = AgentCertificate.create(session(["a.example.com"]))
    assert cert.egress["destinations"] == ["a.example.com"]
    assert cert.egress["accepted_domains"] == [] and cert.egress["forbidden_regions"] == []


def test_the_section_is_sorted_so_the_signed_bytes_are_stable():
    hosts = ["z.example.com", "a.example.com", "m.example.com"]
    one = egress_section(session(hosts))
    other = egress_section(session(list(reversed(hosts))))
    assert one == other == {
        "accepted_domains": [], "rejected_domains": [], "forbidden_regions": [],
        "destinations": ["a.example.com", "m.example.com", "z.example.com"]}


def test_the_observed_list_can_be_left_out(baseline, policy):
    """The key is absent, not empty: an empty list would claim nothing was reached."""
    graph = session(["internal.corp.example", "api.openai.com"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy,
                                   omit_observed_destinations=True)
    assert "destinations" not in cert.egress
    assert cert.egress["accepted_domains"] == ["*.openai.com"]
    assert cert.egress["rejected_domains"] == ["*.cn"]
    assert cert.egress["forbidden_regions"] == ["CN", "RU"]
    assert "internal.corp.example" not in json.dumps(cert.to_dict())
    # A session that reached nothing still records an (empty) list: the two
    # cases are different and must stay so.
    assert egress_section(session(hosts=()))["destinations"] == []
    assert "destinations" not in egress_section(graph, include_destinations=False)


def test_without_an_observed_list_only_rejections_and_regions_are_checked(baseline, policy):
    graph = session(["api.openai.com", "api.unknown.cn", "mirror.example.ru", "new.example.net"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy,
                                   omit_observed_destinations=True)
    report = cert.verify(graph, allow_unsigned=True)
    # *.cn is rejected, so that host is still drift; the unknown one cannot be judged.
    assert report.added_destinations == ["api.unknown.cn"]
    # Both forbidden regions are still read: CN from the rejected host, RU from the other.
    assert [(hit["host"], hit["country"]) for hit in report.forbidden_destinations] == [
        ("api.unknown.cn", "CN"), ("mirror.example.ru", "RU")]
    assert any("no observed destinations" in w for w in report.warnings)
    assert not report.is_valid


def test_the_omission_is_signed_too(baseline, policy):
    """An operator cannot add the list afterwards, or take it away."""
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(session(["a.example.com"]), signing_key=priv,
                                   baseline=baseline, policy=policy,
                                   omit_observed_destinations=True)
    assert cert.signature_valid(pub)
    cert.egress["destinations"] = ["a.example.com"]
    assert not cert.signature_valid(pub)

    full = AgentCertificate.create(session(["a.example.com"]), signing_key=priv,
                                   baseline=baseline, policy=policy)
    assert full.signature_valid(pub)
    del full.egress["destinations"]
    assert not full.signature_valid(pub)


def test_the_section_is_signed(baseline, policy):
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(session(), signing_key=priv, baseline=baseline, policy=policy)
    assert cert.signature_valid(pub)
    cert.egress["forbidden_regions"] = []                 # an operator "relaxing" the rules
    assert not cert.signature_valid(pub)


def test_graph_hash_does_not_change(baseline, policy):
    """A certificate's identity is still its shape: egress is recorded, not hashed."""
    graph = session(["api.openai.com"])
    before = graph_hash(graph)
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)
    assert cert.graph_hash == before
    graph.record_egress("tool:WebFetch", {"brand.new.example"}, 10)
    assert graph_hash(graph) == before                    # a new destination is not a new topology
    assert AgentCertificate.create(graph).graph_hash == before


# ------------------------------------- a system already breaking its own rules
def test_egress_violations_names_what_is_already_wrong(baseline, policy):
    """Both kinds: a host a pattern rejects, and a host in a forbidden region."""
    graph = session(["api.openai.com", "api.unknown.cn", "mirror.example.ru"])
    lines = egress_violations(graph, baseline, policy)
    # Host by host, and for each host the operator's own pattern before the
    # region: one is a decision about that name, the other about a country.
    assert lines == [
        "api.unknown.cn: matches rejected pattern *.cn",
        "api.unknown.cn: in forbidden region CN (ccTLD)",
        "mirror.example.ru: in forbidden region RU (ccTLD)",
    ]
    # A clean session has nothing to report, and neither has one with no rules.
    assert egress_violations(session(["api.openai.com"]), baseline, policy) == []
    assert egress_violations(graph) == []
    assert egress_violations(graph, baseline) == [            # the patterns alone
        "api.unknown.cn: matches rejected pattern *.cn"]


def test_egress_violations_resolves_regions_offline(tmp_path, monkeypatch, policy):
    def no_dns(*args, **kwargs):
        raise AssertionError("a name was resolved")

    monkeypatch.setattr("socket.getaddrinfo", no_dns)
    db = tmp_path / "ip.csv"
    db.write_text("77.88.8.0,77.88.8.255,RU\n", encoding="utf-8")
    graph = session(["77.88.8.8"])
    assert egress_violations(graph, policy=policy) == []       # an address says nothing by itself
    lines = egress_violations(graph, policy=policy, regions=RegionResolver(geoip=load_geoip(db)))
    assert lines == ["77.88.8.8: in forbidden region RU (GeoIP database on an address literal)"]


def test_a_certificate_carries_the_violations_it_was_issued_over(baseline, policy):
    """The evidence travels with the signature, so nobody has to take it on trust."""
    graph = session(["api.openai.com", "mirror.example.ru"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)
    assert cert.egress["violations_at_issue"] == ["mirror.example.ru: in forbidden region RU (ccTLD)"]
    report = cert.verify(graph, allow_unsigned=True)
    assert any("issued over 1 egress violation(s)" in w for w in report.warnings)
    assert not report.is_valid                                 # and it still fails, on the region


def test_the_recorded_violations_are_signed(baseline, policy):
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(session(["mirror.example.ru"]), signing_key=priv,
                                   baseline=baseline, policy=policy)
    assert cert.signature_valid(pub)
    cert.egress["violations_at_issue"] = []                    # "it was fine when we signed it"
    assert not cert.signature_valid(pub)


@pytest.mark.parametrize("recorded", [{"violations_at_issue": "not-a-list"},
                                      {"violations_at_issue": [1]}])
def test_a_malformed_violation_record_is_refused(recorded):
    data = AgentCertificate.create(session()).to_dict()
    data["egress"].update(recorded)
    with pytest.raises(ValueError, match="Invalid certificate format"):
        AgentCertificate.from_dict(data)


# ------------------------------------------------- older formats keep verifying
def _legacy(graph, drop, *, fi_fixed: bool, domain: bool,
            cert_format: int | None = None) -> tuple[AgentCertificate, str]:
    """A certificate as an older version wrote it, signed over exactly its own bytes."""
    data = AgentCertificate.create(graph).to_dict()
    for key in drop:
        data.pop(key, None)
    if cert_format is not None:
        data["cert_format"] = cert_format
    topo = _topology(graph, "id") if "identity" in drop else _topology(graph, "role")
    if "identity" in drop:
        data.update(nodes=dict(topo["nodes"]), edges=[list(e) for e in topo["edges"]],
                    graph_hash=graph_hash(graph, identity="id"))
    key = Ed25519PrivateKey.generate()
    data["signer_public_key"] = _public_hex(key.public_key())
    body = {k: v for k, v in data.items() if k != "signature"}
    if fi_fixed:
        body["fi_score"] = f"{data['fi_score']:.10f}"
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        payload = DOMAIN + payload if domain else payload
    else:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    data["signature"] = base64.b64encode(key.sign(payload)).decode()
    return AgentCertificate.from_dict(data), data["signer_public_key"]


def test_a_format_1_certificate_still_verifies():
    """Issued before v0.5: no validity window, no egress section, its own encoding."""
    graph = session()
    cert, issuer = _legacy(graph, ("identity", "cert_format", "not_before", "not_after",
                                   "skipped_records", "egress"), fi_fixed=False, domain=False)
    assert cert.cert_format == 1 and cert.egress == {} and cert.identity == "id"
    assert cert.signature_valid(issuer)
    # Its signature still checks out, and it still verifies — but a certificate
    # with no end date is now a decision rather than a default (CRY-003), so
    # the waiver has to be explicit.
    refused = cert.verify(graph, public_key=issuer)
    assert not refused.is_valid
    assert any("no validity period" in r for r in refused.reasons)
    assert any("--allow-no-expiry" in r for r in refused.reasons)

    report = cert.verify(graph, public_key=issuer, allow_no_expiry=True)
    assert report.is_valid, report.reasons
    assert any("no validity period" in w for w in report.warnings)
    assert any("Certificate format 1, current is 3" in w for w in report.warnings)
    assert any("not checked" in w for w in report.warnings)       # its destinations
    assert report.added_destinations == [] and report.forbidden_destinations == []
    # The session did reach somewhere and this certificate carries no egress
    # rules, so coverage cannot be decided: the signature and the topology are
    # good, and whether those destinations were the certified ones is unknown.
    # `verify` exits 3 for this, not 0 (CRY-001).
    assert graph.seen_domains == {"api.openai.com"}
    assert report.egress_coverage == "no_section" and not report.egress_verifiable
    assert "NOT VERIFIABLE" in str(report)


def test_a_format_2_certificate_still_verifies():
    """Issued by v0.5 to v0.8: a validity window, no egress section."""
    graph = session()
    cert, issuer = _legacy(graph, ("egress",), fi_fixed=True, domain=True, cert_format=2)
    assert cert.cert_format == 2 and cert.egress == {}
    assert cert.signature_valid(issuer)
    report = cert.verify(graph, public_key=issuer)
    assert report.is_valid, report.reasons
    assert any("Certificate format 2, current is 3" in w for w in report.warnings)
    assert any("no egress section" in w for w in report.warnings)


def test_an_egress_section_cannot_be_bolted_onto_an_older_certificate():
    """The older payloads leave it out, so a section there was never signed."""
    data = AgentCertificate.create(session()).to_dict()
    data["cert_format"] = 2
    with pytest.raises(ValueError, match="Invalid certificate format"):
        AgentCertificate.from_dict(data)
    data["cert_format"] = 1
    with pytest.raises(ValueError, match="Invalid certificate format"):
        AgentCertificate.from_dict(data)


def test_the_format_is_part_of_the_signed_bytes():
    """A format 3 certificate cannot be re-labelled as a format 2 one."""
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(session(), signing_key=priv)
    assert cert.signature_valid(pub)
    cert.cert_format = 2
    assert not cert.signature_valid(pub)


# --------------------------------------------------------------------- verify
def test_verify_reports_a_destination_the_certificate_does_not_cover(baseline, policy):
    priv, pub = generate_keypair()
    certified = session(["api.openai.com"])
    cert = AgentCertificate.create(certified, signing_key=priv, baseline=baseline, policy=policy)

    live = session(["api.openai.com", "collector.example.net"])
    report = cert.verify(live, public_key=pub)
    assert not report.is_valid
    assert report.added_destinations == ["collector.example.net"]
    assert any("1 destination(s) not covered by the certificate: collector.example.net" in r
               for r in report.reasons)
    assert "1 not covered" in str(report)
    # An accepted pattern covers what it covers, without being listed.
    assert cert.verify(session(["api.openai.com", "eu.openai.com"]),
                       public_key=pub).added_destinations == []


def test_a_rejected_pattern_stays_rejected_even_if_the_host_was_observed(baseline, policy):
    """The certificate carries the operator's decision, not just the traffic."""
    graph = session(["api.openai.com", "api.unknown.cn"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)
    assert "api.unknown.cn" in cert.egress["destinations"]
    report = cert.verify(graph, allow_unsigned=True)
    assert report.added_destinations == ["api.unknown.cn"]        # matches the rejected *.cn


def test_verify_reports_a_destination_in_a_forbidden_region(baseline, policy):
    graph = session(["api.openai.com", "mirror.example.ru"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)
    report = cert.verify(graph, allow_unsigned=True)
    assert [hit["host"] for hit in report.forbidden_destinations] == ["mirror.example.ru"]
    assert report.forbidden_destinations[0]["country"] == "RU"
    assert report.forbidden_destinations[0]["source"] == "cctld"
    assert any("is in forbidden region RU (cctld)" in r for r in report.reasons)
    assert not report.is_valid


def test_verify_resolves_regions_offline_and_can_read_a_local_database(tmp_path, baseline, policy):
    db = tmp_path / "ip.csv"
    db.write_text("77.88.8.0,77.88.8.255,RU\n", encoding="utf-8")
    graph = session(["api.openai.com", "77.88.8.8"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)

    offline = cert.verify(graph, allow_unsigned=True)                  # ccTLD only: an address says nothing
    assert offline.forbidden_destinations == []
    with_db = cert.verify(graph, allow_unsigned=True, regions=RegionResolver(geoip=load_geoip(db)))
    assert [hit["country"] for hit in with_db.forbidden_destinations] == ["RU"]
    assert with_db.forbidden_destinations[0]["source"] == "geoip"


def test_verify_never_resolves_a_name(monkeypatch, baseline, policy):
    def no_dns(*args, **kwargs):
        raise AssertionError("verify resolved a name")

    monkeypatch.setattr("socket.getaddrinfo", no_dns)
    graph = session(["api.openai.com", "somewhere.example.com"])
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)
    assert cert.verify(graph, allow_unsigned=True).forbidden_destinations == []


def test_a_session_with_no_destinations_is_no_egress_drift(baseline, policy):
    graph = session(hosts=())
    cert = AgentCertificate.create(graph, baseline=baseline, policy=policy)
    report = cert.verify(graph, allow_unsigned=True)
    assert report.is_valid, report.reasons
    assert report.added_destinations == [] and report.forbidden_destinations == []


def test_the_report_carries_the_new_fields_in_json(baseline, policy):
    cert = AgentCertificate.create(session(["api.openai.com"]), baseline=baseline, policy=policy)
    data = cert.verify(session(["api.openai.com", "x.example.net"]), allow_unsigned=True).to_dict()
    assert data["added_destinations"] == ["x.example.net"]
    assert data["forbidden_destinations"] == []
    assert json.loads(json.dumps(data))["added_destinations"] == ["x.example.net"]


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("egress", [
    {"destinations": "not-a-list"},
    {"destinations": [1, 2]},
    {"unexpected": []},
    {"forbidden_regions": ["CHN"]},
    {"forbidden_regions": ["cn"]},
    {"accepted_domains": [None]},
    [],
    "",
])
def test_a_malformed_egress_section_is_refused(egress):
    data = AgentCertificate.create(session()).to_dict()
    data["egress"] = egress
    with pytest.raises(ValueError, match="Invalid certificate format"):
        AgentCertificate.from_dict(data)


def test_a_certificate_round_trips_through_a_file(tmp_path, baseline, policy):
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(session(["api.openai.com"]), signing_key=priv,
                                   baseline=baseline, policy=policy)
    path = cert.save(tmp_path / "c.cert.json")
    loaded = AgentCertificate.load(path)
    assert loaded.egress == cert.egress and loaded.signature_valid(pub)
    assert json.loads(path.read_text(encoding="utf-8"))["egress"]["forbidden_regions"] == ["CN", "RU"]
