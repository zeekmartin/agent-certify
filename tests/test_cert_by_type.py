# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_certify import AgentCertificate, AgentGraph, generate_keypair, graph_hash
from agent_certify.certificate import _topology


def _session(agents: dict[str, str]) -> AgentGraph:
    """claude -> {Bash, Read}; each agent (id -> type) is spawned by claude and calls Bash."""
    g = AgentGraph()
    g.add_node("claude", "orchestrator")
    for t in ("Bash", "Read"):
        g.add_node(f"tool:{t}", "tool", t)
        g.add_call("claude", f"tool:{t}")
    for aid, kind in agents.items():
        g.add_node(f"agent:{aid}", "agent", f"{kind}: task", agentType=kind)
        g.add_call("claude", f"agent:{aid}")
        g.add_call(f"agent:{aid}", "tool:Bash")
    return g


def test_same_type_different_id_passes():
    priv, pub = generate_keypair()
    cert = AgentCertificate.create(_session({"abc": "Explore"}), signing_key=priv)
    assert cert.identity == "role"
    assert "agent:Explore" in cert.nodes and "agent:abc" not in cert.nodes
    assert ["agent:Explore", "tool:Bash"] in cert.edges

    report = cert.verify(_session({"xyz": "Explore"}), public_key=pub)
    assert report.is_valid, report.reasons
    assert report.graph_hash_match
    assert report.added_nodes == [] and report.removed_nodes == []


def test_different_type_fails_with_type_messages():
    cert = AgentCertificate.create(_session({"abc": "Explore"}))
    report = cert.verify(_session({"xyz": "Research"}))
    assert not report.is_valid
    assert report.added_agent_types == ["agent:Research"]
    assert report.removed_agent_types == ["agent:Explore"]
    assert "New agent type: agent:Research (not in certified baseline)" in report.reasons
    assert "Missing agent type: agent:Explore (was in certified baseline)" in report.reasons
    assert not any("agent:xyz" in r or "agent:abc" in r for r in report.reasons)
    assert ["agent:Research", "tool:Bash"] in report.added_edges


def test_more_agents_of_same_type_changes_fi_only():
    cert = AgentCertificate.create(_session({"abc": "Explore"}))
    report = cert.verify(_session({"x1": "Explore", "x2": "Explore"}))
    assert report.graph_hash_match                            # same types, same links
    assert not report.is_valid
    assert report.reasons == [f"FI changed by {report.fi_delta:+.4f} (tolerance 0.001)"]


def test_hash_by_role_vs_id():
    a, b = _session({"abc": "Explore"}), _session({"xyz": "Explore"})
    assert graph_hash(a) == graph_hash(b)
    assert graph_hash(a, identity="id") != graph_hash(b, identity="id")


def test_pre_v03_certificate_still_verifies_and_compares_by_id(tmp_path):
    # Reproduce a certificate written by v0.2: no "identity" field, id-based topology,
    # signed over exactly the fields it had.
    g = _session({"abc": "Explore"})
    data = AgentCertificate.create(g).to_dict()
    data.pop("identity")
    topo = _topology(g, "id")
    data.update(nodes=dict(topo["nodes"]), edges=[list(e) for e in topo["edges"]],
                graph_hash=graph_hash(g, identity="id"), agent_certify_version="0.2.0")
    key = Ed25519PrivateKey.generate()
    from agent_certify.certificate import _public_hex
    data["signer_public_key"] = _public_hex(key.public_key())
    body = {k: v for k, v in data.items() if k != "signature"}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    data["signature"] = base64.b64encode(key.sign(payload)).decode()
    path = tmp_path / "v02.cert.json"
    path.write_text(json.dumps(data))

    cert = AgentCertificate.load(path)
    assert cert.identity == "id"
    assert cert.signature_valid()                              # old signature still checks out
    assert cert.verify(g).is_valid
    report = cert.verify(_session({"xyz": "Explore"}))         # legacy semantics: ids differ
    assert not report.is_valid and report.added_nodes == ["agent:xyz"]


def test_cli_certify_verify_by_type(tmp_path):
    from agent_certify.cli import main

    def write(path, agent_id, agent_type):
        path.mkdir(parents=True, exist_ok=True)
        (path / "s.jsonl").write_text(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}},
            {"type": "tool_use", "id": agent_id, "name": "Agent",
             "input": {"subagent_type": agent_type, "description": "d", "prompt": "p"}}]}}) + "\n")
        return str(path / "s.jsonl")

    first = write(tmp_path / "a", "toolu_A", "Explore")
    same = write(tmp_path / "b", "toolu_B", "Explore")
    other = write(tmp_path / "c", "toolu_C", "Research")
    cert = str(tmp_path / "c.json")
    assert main(["certify", first, "-o", cert]) == 0
    assert main(["verify", cert, same]) == 0
    assert main(["verify", cert, other]) == 1
