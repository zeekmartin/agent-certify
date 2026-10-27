# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
import pytest

from agent_certify import AgentCertificate, generate_keypair, graph_hash


def test_sign_and_verify(star_graph, tmp_path):
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(star_graph, system_id="star-system", signing_key=priv)
    assert cert.is_signed and cert.signer_public_key == pub
    assert not cert.signature_valid()          # SEC-002: without a trusted key nothing is proven
    assert cert.signature_valid(pub)
    assert cert.signature_valid(pub)
    assert cert.fi_score == 1.0 and cert.bridge_count == 4 and cert.critical_nodes == ["claude"]

    path = cert.save(tmp_path / "c.json")
    loaded = AgentCertificate.load(path)
    assert loaded.signature_valid(pub)

    report = loaded.verify(star_graph, public_key=pub)
    assert report.is_valid, report.reasons
    assert report.graph_hash_match


def test_tampering_breaks_signature(star_graph):
    priv, _ = generate_keypair()
    cert = AgentCertificate.create(star_graph, signing_key=priv)
    cert.fi_score = 0.1
    assert not cert.signature_valid()


def test_wrong_signer_rejected(star_graph):
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    cert = AgentCertificate.create(star_graph, signing_key=priv)
    assert not cert.signature_valid(other_pub)
    assert not cert.verify(star_graph, public_key=other_pub).is_valid


def test_drift_new_trust_link(star_graph):
    cert = AgentCertificate.create(star_graph)
    g = star_graph
    g.add_call("tool:t0", "tool:t1")            # new link between tools: a triangle appears
    report = cert.verify(g)
    assert not report.is_valid
    assert report.added_edges == [["tool:t0", "tool:t1"]]
    assert report.fi_delta == pytest.approx(0.4 - 1.0)   # 2 of 5 links still unsupported
    assert not report.graph_hash_match


def test_hash_ignores_call_counts(star_graph):
    h = graph_hash(star_graph)
    star_graph.add_call("claude", "tool:t0", count=10)
    assert graph_hash(star_graph) == h
