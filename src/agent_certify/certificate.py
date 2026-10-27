# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
"""Signed structural baseline of a multiagent system.

An :class:`AgentCertificate` records a system's topology (which agents exist,
which tools each may invoke), its FI and its node roles, and can be signed with
an Ed25519 key so that any later edit to the certificate is detectable.
:meth:`AgentCertificate.verify` compares a live graph against it and names
every structural change: a new agent, a new tool link, lost redundancy. A
topology change is visible before any behaviour it enables.

``graph_hash`` covers the node ids, their kinds and the directed binary
adjacency (who may invoke whom). Call counts are deliberately left out: a
system that does the same thing more often has not changed shape.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_certify.graph import AgentGraph
from agent_certify.scanner import AgentFIScanner

DEFAULT_FI_TOLERANCE = 0.001
_TS = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> str:
    return time.strftime(_TS, time.gmtime())


ROLE, ID = "role", "id"


def _topology(graph: AgentGraph, identity: str = ROLE) -> dict:
    """Nodes and directed links, with agents named by type (``role``) or by unique id (``id``)."""
    name = graph.role if identity == ROLE else (lambda nid: nid)
    return {
        "nodes": sorted({(name(nid), n.kind) for nid, n in graph.nodes.items()}),
        "edges": sorted({(name(e.source), name(e.target)) for e in graph.edges}),
    }


def graph_hash(graph: AgentGraph, identity: str = ROLE) -> str:
    """SHA-256 of the graph's nodes and directed binary adjacency.

    With ``identity="role"`` (the default since v0.3) sub-agents count by type,
    so two sessions that spawn the same kinds of agent for the same tools hash
    the same. ``identity="id"`` is the v0.1/v0.2 behaviour.
    """
    topo = _topology(graph, identity)
    blob = json.dumps({"nodes": [list(n) for n in topo["nodes"]], "edges": [list(e) for e in topo["edges"]]},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------ keys
def generate_keypair() -> tuple[str, str]:
    """New Ed25519 key pair as (private seed hex, public key hex)."""
    key = Ed25519PrivateKey.generate()
    return _private_hex(key), _public_hex(key.public_key())


def _private_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption()).hex()


def _public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _signing_key(key) -> Ed25519PrivateKey:
    if isinstance(key, Ed25519PrivateKey):
        return key
    if isinstance(key, str):
        key = bytes.fromhex(key.strip())
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return Ed25519PrivateKey.from_private_bytes(bytes(key))
    raise TypeError("signing_key must be an Ed25519PrivateKey or its 32-byte seed (bytes or hex string)")


# ----------------------------------------------------------------- certificate
@dataclass
class AgentCertificate:
    """Signed structural baseline of a multiagent system.

    Usage::

        priv, pub = generate_keypair()
        cert = AgentCertificate.create(graph, system_id="support-bot-v3", signing_key=priv)
        cert.save("support-bot-v3.cert.json")

        cert = AgentCertificate.load("support-bot-v3.cert.json")
        drift = cert.verify(live_graph, public_key=pub)
        drift.is_valid        # False if the topology changed
        drift.added_edges     # [["agent:planner", "tool:Bash"]]
    """
    system_id: str
    timestamp: str
    fi_score: float
    node_count: int
    edge_count: int
    bridge_count: int
    critical_nodes: list[str]
    node_classifications: dict[str, str]
    graph_hash: str           # SHA-256 of the adjacency matrix
    signature: str = ""       # Ed25519 signature, base64
    signer_public_key: str = ""   # Ed25519 public key, hex
    nodes: dict[str, str] = field(default_factory=dict)      # role (or id) -> kind
    edges: list[list[str]] = field(default_factory=list)     # directed [source, target]
    certificate_id: str = ""
    agent_certify_version: str = ""
    # How agents are named in nodes/edges/graph_hash: "role" (by type, v0.3+) or
    # "id" (unique spawn id). Certificates written before v0.3 have no such field
    # and load as "id", so they keep comparing exactly as they did.
    identity: str = ID

    @classmethod
    def create(cls, graph: AgentGraph, system_id: str | None = None, signing_key=None) -> AgentCertificate:
        """Scan ``graph`` and package its structural profile."""
        from agent_certify import __version__

        result = AgentFIScanner(graph).scan()
        topo = _topology(graph, ROLE)
        cert = cls(
            system_id=system_id or graph.session_id or "unnamed-system",
            timestamp=_now(),
            fi_score=result.fi,
            node_count=result.node_count,
            edge_count=result.edge_count,
            bridge_count=len(result.bridges),
            critical_nodes=result.critical_nodes,
            node_classifications=result.node_classifications,
            graph_hash=graph_hash(graph, ROLE),
            nodes={nid: kind for nid, kind in topo["nodes"]},
            edges=[list(e) for e in topo["edges"]],
            certificate_id=str(uuid4()),
            agent_certify_version=__version__,
            identity=ROLE,
        )
        if signing_key is not None:
            cert.sign(signing_key)
        return cert

    # --------------------------------------------------------------- signature
    def payload(self) -> bytes:
        """The canonical bytes that the signature covers (every field but it)."""
        data = asdict(self)
        data.pop("signature")
        if data["identity"] == ID:
            data.pop("identity")      # pre-v0.3 certificates were signed without this field
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, signing_key) -> AgentCertificate:
        """Sign the certificate in place with an Ed25519 private key."""
        key = _signing_key(signing_key)
        self.signer_public_key = _public_hex(key.public_key())
        self.signature = base64.b64encode(key.sign(self.payload())).decode("ascii")
        return self

    @property
    def is_signed(self) -> bool:
        return bool(self.signature)

    def signature_valid(self, public_key: str | bytes | None = None) -> bool:
        """True when the signature matches the certificate's contents.

        Without ``public_key`` this checks against the key recorded in the
        certificate, which proves it was not edited after signing but not *who*
        signed it. Pass the issuer's public key, obtained through a trusted
        channel, to check both.
        """
        if not self.signature or not self.signer_public_key:
            return False
        expected = self.signer_public_key
        if public_key is not None:
            given = public_key.hex() if isinstance(public_key, bytes) else str(public_key)
            if given.lower() != expected.lower():
                return False
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected)).verify(
                base64.b64decode(self.signature, validate=True), self.payload())
        except (InvalidSignature, ValueError):
            return False
        return True

    # ------------------------------------------------------------ verification
    def verify(self, graph: AgentGraph, fi_tolerance: float = DEFAULT_FI_TOLERANCE,
               public_key: str | bytes | None = None) -> DriftReport:
        """Compare a live graph against this certificate.

        Agents are compared the way the certificate names them: by type for
        certificates issued since v0.3, by spawn id for older ones.
        """
        result = AgentFIScanner(graph).scan()
        topo = _topology(graph, self.identity)
        now_nodes = dict(topo["nodes"])
        now_edges = {tuple(e) for e in topo["edges"]}
        cert_edges = {tuple(e) for e in self.edges}

        added_nodes = sorted(set(now_nodes) - set(self.nodes))
        removed_nodes = sorted(set(self.nodes) - set(now_nodes))
        added_edges = sorted(list(e) for e in now_edges - cert_edges)
        removed_edges = sorted(list(e) for e in cert_edges - now_edges)
        # Roles of individual agents can't be paired across sessions; compare the rest.
        comparable = {n for n in result.node_classifications
                      if self.identity == ID or graph.nodes[n].kind != "agent"}
        changed = [{"node": n, "was": self.node_classifications[n], "now": c}
                   for n, c in sorted(result.node_classifications.items())
                   if n in comparable and n in self.node_classifications and self.node_classifications[n] != c]
        fi_delta = result.fi - self.fi_score
        hash_match = graph_hash(graph, self.identity) == self.graph_hash
        sig_ok = self.signature_valid(public_key) if self.is_signed else None

        def is_agent_type(n):
            return self.identity == ROLE and n.startswith("agent:")

        added_types = [n for n in added_nodes if is_agent_type(n)]
        removed_types = [n for n in removed_nodes if is_agent_type(n)]
        added_other = [n for n in added_nodes if not is_agent_type(n)]
        removed_other = [n for n in removed_nodes if not is_agent_type(n)]

        reasons = [f"New agent type: {n} (not in certified baseline)" for n in added_types]
        reasons += [f"Missing agent type: {n} (was in certified baseline)" for n in removed_types]
        if added_other:
            reasons.append(f"{len(added_other)} node(s) not in the certified topology: {', '.join(added_other)}")
        if removed_other:
            reasons.append(f"{len(removed_other)} certified node(s) missing: {', '.join(removed_other)}")
        if added_edges:
            reasons.append(f"{len(added_edges)} new invocation link(s): "
                           + ", ".join(f"{s} -> {t}" for s, t in added_edges))
        if removed_edges:
            reasons.append(f"{len(removed_edges)} certified link(s) gone: "
                           + ", ".join(f"{s} -> {t}" for s, t in removed_edges))
        if abs(fi_delta) >= fi_tolerance:
            reasons.append(f"FI changed by {fi_delta:+.4f} (tolerance {fi_tolerance})")
        if sig_ok is False:
            reasons.append("certificate signature is invalid")
        elif sig_ok is None and public_key is not None:
            reasons.append("certificate is not signed")

        return DriftReport(
            is_valid=not reasons, graph_hash_match=hash_match,
            fi_certified=self.fi_score, fi_current=result.fi, fi_delta=fi_delta,
            added_nodes=added_nodes, removed_nodes=removed_nodes,
            added_edges=added_edges, removed_edges=removed_edges,
            changed_classifications=changed, signature_valid=sig_ok,
            certificate_id=self.certificate_id, verified_at=_now(), reasons=reasons,
            added_agent_types=added_types, removed_agent_types=removed_types,
        )

    # --------------------------------------------------------------------- io
    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path) -> AgentCertificate:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        unknown = set(data) - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"{path} is not an agent-certify certificate (unknown fields: {sorted(unknown)})")
        return cls(**data)


@dataclass
class DriftReport:
    """Structural differences between a live graph and its certificate."""
    is_valid: bool
    graph_hash_match: bool
    fi_certified: float
    fi_current: float
    fi_delta: float
    added_nodes: list[str]
    removed_nodes: list[str]
    added_edges: list[list[str]]
    removed_edges: list[list[str]]
    changed_classifications: list[dict]
    signature_valid: bool | None      # None = certificate not signed
    certificate_id: str
    verified_at: str
    reasons: list[str] = field(default_factory=list)
    added_agent_types: list[str] = field(default_factory=list)
    removed_agent_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        lines = [
            f"Verification: {'PASS' if self.is_valid else 'FAIL'}",
            f"  FI: {self.fi_certified:.4f} -> {self.fi_current:.4f} (delta={self.fi_delta:+.4f})",
            f"  Topology hash match: {self.graph_hash_match}",
            f"  Role changes: {len(self.changed_classifications)}",
            f"  Signature: {'unsigned' if self.signature_valid is None else self.signature_valid}",
            f"  Certificate: {self.certificate_id}",
        ]
        lines += [f"  - {r}" for r in self.reasons]
        return "\n".join(lines)
