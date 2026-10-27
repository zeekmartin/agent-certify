# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Adversarial certificate tests (audit SEC-002, SEC-004, SEC-007, SEC-008, FUN-003, TST-001)."""
import base64
import json
import math
from datetime import datetime, timedelta, timezone

import pytest
from conftest import star

from agent_certify import AgentCertificate, generate_keypair
from agent_certify.certificate import DOMAIN


@pytest.fixture
def keys():
    return generate_keypair()


@pytest.fixture
def signed(star_graph, keys):
    return AgentCertificate.create(star_graph, system_id="sys", signing_key=keys[0])


def roundtrip(cert, tmp_path, mutate=None):
    data = cert.to_dict()
    if mutate:
        mutate(data)
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    return AgentCertificate.load(p)


# ----------------------------------------------------------------- trust
def test_valid_with_trusted_key(star_graph, signed, keys):
    report = signed.verify(star_graph, public_key=keys[1])
    assert report.is_valid, report.reasons
    assert report.signature_valid is True and report.warnings == []


def test_no_key_never_passes(star_graph, signed):
    report = signed.verify(star_graph)
    assert not report.is_valid
    assert "No trusted public key given: the signature cannot be checked" in report.reasons
    assert not signed.signature_valid()                       # the embedded key is never a trust anchor


def test_stripped_signature_fails(star_graph, signed, keys, tmp_path):
    def strip(d):
        d["signature"] = ""
        d["signer_public_key"] = ""
    cert = roundtrip(signed, tmp_path, strip)
    for key in (keys[1], None):
        report = cert.verify(star_graph, public_key=key)
        assert not report.is_valid and "Certificate is not signed" in report.reasons


def test_attacker_resigned_certificate_fails(star_graph, signed, keys):
    attacker_priv, attacker_pub = generate_keypair()
    signed.edges.append(["claude", "tool:deploy"])            # widen the certified topology
    signed.sign(attacker_priv)                                # signer_public_key now names the attacker
    assert signed.signature_valid(attacker_pub)               # internally consistent...
    report = signed.verify(star_graph, public_key=keys[1])    # ...but not by the trusted issuer
    assert not report.is_valid and report.signature_valid is False
    assert not signed.verify(star_graph).is_valid             # and without a key it cannot pass at all


@pytest.mark.parametrize("field,value", [
    ("nodes", {"claude": "orchestrator"}),
    ("edges", [["claude", "tool:t0"]]),
    ("fi_score", 0.5),
    ("critical_nodes", []),
    ("not_after", "2099-01-01T00:00:00Z"),
    ("system_id", "other"),
    ("identity", "id"),
    ("skipped_records", 0 + 7),
])
def test_any_edit_breaks_the_signature(star_graph, signed, keys, tmp_path, field, value):
    cert = roundtrip(signed, tmp_path, lambda d: d.__setitem__(field, value))
    assert not cert.signature_valid(keys[1])
    assert not cert.verify(star_graph, public_key=keys[1]).is_valid


def test_format_downgrade_breaks_the_signature(signed, keys):
    signed.cert_format = 1                                    # try to fall back to the legacy encoding
    assert not signed.signature_valid(keys[1])


def test_allow_unsigned(star_graph, capsys):
    cert = AgentCertificate.create(star_graph)
    report = cert.verify(star_graph, allow_unsigned=True)
    assert report.is_valid and report.signature_valid is None
    assert any("not checked" in w for w in report.warnings)


# --------------------------------------------------------------- validity
def test_expired(star_graph, keys):
    old = datetime.now(timezone.utc) - timedelta(days=100)
    cert = AgentCertificate.create(star_graph, signing_key=keys[0], validity_days=90, now=old)
    report = cert.verify(star_graph, public_key=keys[1])
    assert not report.is_valid
    assert f"Certificate expired on {cert.not_after}" in report.reasons
    assert cert.verify(star_graph, public_key=keys[1], ignore_expiry=True).is_valid


def test_not_yet_valid(star_graph, keys):
    future = datetime.now(timezone.utc) + timedelta(days=3)
    cert = AgentCertificate.create(star_graph, signing_key=keys[0], now=future)
    report = cert.verify(star_graph, public_key=keys[1])
    assert f"Certificate not valid before {cert.not_before}" in report.reasons


def test_within_window(star_graph, keys):
    cert = AgentCertificate.create(star_graph, signing_key=keys[0], validity_days=1)
    assert cert.verify(star_graph, public_key=keys[1]).is_valid
    later = datetime.now(timezone.utc) + timedelta(days=2)
    assert not cert.verify(star_graph, public_key=keys[1], now=later).is_valid


def test_validity_days_must_be_positive(star_graph):
    for bad in (0, -1, 1.5, None):
        with pytest.raises(ValueError):
            AgentCertificate.create(star_graph, validity_days=bad)


def test_expected_system_id(star_graph, signed, keys):
    assert signed.verify(star_graph, public_key=keys[1], expected_system_id="sys").is_valid
    report = signed.verify(star_graph, public_key=keys[1], expected_system_id="prod")
    assert "Certificate is for system 'sys', not 'prod'" in report.reasons


# ------------------------------------------------------------- loading
@pytest.mark.parametrize("raw", ['NaN', 'Infinity', '-Infinity'])
def test_nan_and_infinity_rejected_on_load(signed, tmp_path, raw):
    text = json.dumps(signed.to_dict()).replace(f'"fi_score": {signed.fi_score}', f'"fi_score": {raw}')
    assert raw in text
    p = tmp_path / "c.json"
    p.write_text(text)
    with pytest.raises(ValueError, match="^Invalid certificate format$"):
        AgentCertificate.load(p)


def test_nan_in_memory_fails_verify(star_graph):
    cert = AgentCertificate.create(star_graph)
    cert.fi_score = math.nan
    report = cert.verify(star_graph, allow_unsigned=True)
    assert not report.is_valid and "Certificate FI is not a finite number" in report.reasons


@pytest.mark.parametrize("mutate", [
    lambda d: d.__setitem__("unexpected", 1),
    lambda d: d.__setitem__("signature", 12345),
    lambda d: d.__setitem__("signature", "not base64!"),
    lambda d: d.__setitem__("signer_public_key", "zz"),
    lambda d: d.__setitem__("node_count", "17"),
    lambda d: d.__setitem__("node_count", True),
    lambda d: d.__setitem__("fi_score", 1.5),
    lambda d: d.__setitem__("edges", [["a"]]),
    lambda d: d.__setitem__("nodes", {"a": "spaceship"}),
    lambda d: d.__setitem__("graph_hash", "abc"),
    lambda d: d.__setitem__("not_after", "tomorrow"),
    lambda d: d.__setitem__("cert_format", 9),
    lambda d: d.pop("system_id"),
])
def test_type_and_range_validation(signed, tmp_path, mutate):
    with pytest.raises(ValueError, match="^Invalid certificate format$"):
        roundtrip(signed, tmp_path, mutate)


def test_load_rejects_non_objects(tmp_path):
    for text in ("[1, 2]", '"x"', "null", "{not json", "[" * 50_000):
        p = tmp_path / "c.json"
        p.write_text(text)
        with pytest.raises(ValueError, match="^Invalid certificate format$"):
            AgentCertificate.load(p)


# --------------------------------------------------------- canonical bytes
def test_payload_is_domain_separated_with_fixed_point_fi(signed):
    payload = signed.payload()
    assert payload.startswith(DOMAIN)
    body = json.loads(payload[len(DOMAIN):])
    assert body["fi_score"] == f"{signed.fi_score:.10f}" and "signature" not in body
    assert payload[len(DOMAIN):].isascii()


def test_payload_independent_of_file_layout(signed, keys, tmp_path):
    data = signed.to_dict()
    p = tmp_path / "c.json"
    p.write_text(json.dumps(dict(reversed(list(data.items()))), indent=7))   # other key order and spacing
    assert AgentCertificate.load(p).signature_valid(keys[1])


def test_signature_is_64_bytes_base64(signed):
    assert len(base64.b64decode(signed.signature)) == 64


# ------------------------------------------------------------- FUN-003
def test_node_kind_change_is_a_reason(keys):
    g = star(2)
    cert = AgentCertificate.create(g, signing_key=keys[0])
    g2 = star(2)
    g2.nodes["tool:t0"].kind = "file"
    report = cert.verify(g2, public_key=keys[1])
    assert "Node kind changed: tool:t0 (was tool, now file)" in report.reasons
    assert report.kind_changes == ["tool:t0"]
    assert not report.graph_hash_match


def test_hash_mismatch_always_has_a_reason(star_graph, keys):
    cert = AgentCertificate.create(star_graph, signing_key=keys[0])
    cert.graph_hash = "0" * 64                         # hash alone disagrees
    cert.sign(keys[0])
    report = cert.verify(star_graph, public_key=keys[1])
    assert not report.is_valid
    assert report.reasons == ["Topology hash differs from the certified one"]


def test_role_changes_are_informational(star_graph, keys):
    cert = AgentCertificate.create(star_graph, signing_key=keys[0])
    cert.node_classifications["tool:t0"] = "CRITICAL"
    cert.sign(keys[0])
    report = cert.verify(star_graph, public_key=keys[1])
    assert report.is_valid and len(report.changed_classifications) == 1
    assert "(informational)" in str(report)
