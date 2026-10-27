# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""Signed structural baseline of a multiagent system.

An :class:`AgentCertificate` records a system's topology (which agents exist,
which tools each may invoke), its FI and its node roles, and is signed with an
Ed25519 key. :meth:`AgentCertificate.verify` compares a live graph against it
and names every structural change: a new agent, a new tool link, lost
redundancy. A topology change is visible before any behaviour it enables.

Trust model
-----------
A signature only means something when it is checked against a public key the
verifier already trusts. ``signer_public_key`` inside the certificate is
informational (it helps pick a key from a keyring) and is **never** used as the
trust anchor: whoever can edit the certificate can also replace it. So
:meth:`verify` fails unless it is given the issuer's public key, or is told
explicitly that unsigned certificates are acceptable (``allow_unsigned``).

Certificates issued since v0.5 also carry a validity window (``not_before``,
``not_after``; 90 days by default) that :meth:`verify` enforces, so an older,
more permissive certificate cannot be replayed indefinitely.

Signed bytes (``cert_format`` 2, since v0.5)
--------------------------------------------
``b"agent-certify/cert/v1\\x00"`` followed by the certificate as JSON: every
field except ``signature``, keys sorted, separators ``,`` and ``:``, non-ASCII
escaped (``ensure_ascii``), and ``fi_score`` written as a fixed-point decimal
string with 10 places, so that no float formatting is involved. Any
implementation that sorts keys and escapes the same way reproduces the bytes.

Certificates written before v0.5 (``cert_format`` 1) keep their original
encoding, so their signatures still verify; :meth:`verify` reports them as
legacy. The format is part of the signed bytes, so a v2 certificate cannot be
re-labelled as v1.

``graph_hash`` covers the node ids, their kinds and the directed binary
adjacency (who may invoke whom). Call counts are deliberately left out: a
system that does the same thing more often has not changed shape.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import time
from dataclasses import MISSING, asdict, dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_certify.graph import NODE_KINDS, AgentGraph
from agent_certify.scanner import AgentFIScanner

DEFAULT_FI_TOLERANCE = 0.001
DEFAULT_VALIDITY_DAYS = 90
DOMAIN = b"agent-certify/cert/v1\x00"
CURRENT_FORMAT = 2
_TS = "%Y-%m-%dT%H:%M:%SZ"
_V2_ONLY = ("cert_format", "not_before", "not_after", "skipped_records")


def _now() -> str:
    return time.strftime(_TS, time.gmtime())


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, _TS).replace(tzinfo=timezone.utc)


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


def _public_key_hex(public_key: str | bytes) -> str | None:
    """Normalise a trusted public key to lowercase hex, or None when it is not 32 bytes."""
    try:
        raw = bytes(public_key) if isinstance(public_key, (bytes, bytearray)) else bytes.fromhex(str(public_key).strip())
    except (ValueError, TypeError):
        return None
    return raw.hex() if len(raw) == 32 else None


# ----------------------------------------------------------------- certificate
@dataclass
class AgentCertificate:
    """Signed structural baseline of a multiagent system.

    Usage::

        priv, pub = generate_keypair()
        cert = AgentCertificate.create(graph, system_id="support-bot-v3", signing_key=priv)
        cert.save("support-bot-v3.cert.json")

        cert = AgentCertificate.load("support-bot-v3.cert.json")
        drift = cert.verify(live_graph, public_key=pub)   # the issuer's key, obtained out of band
        drift.is_valid        # False if the topology changed, the signature or dates are wrong
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
    signer_public_key: str = ""   # Ed25519 public key, hex — informational, never a trust anchor
    nodes: dict[str, str] = field(default_factory=dict)      # role (or id) -> kind
    edges: list[list[str]] = field(default_factory=list)     # directed [source, target]
    certificate_id: str = ""
    agent_certify_version: str = ""
    # How agents are named in nodes/edges/graph_hash: "role" (by type, v0.3+) or
    # "id" (unique spawn id). Certificates written before v0.3 have no such field
    # and load as "id", so they keep comparing exactly as they did.
    identity: str = ID
    # Since v0.5. Certificates without these fields load as format 1 (legacy).
    cert_format: int = 1
    not_before: str = ""      # ISO 8601 UTC; empty = no validity window (legacy)
    not_after: str = ""
    skipped_records: int = 0  # records the parser could not read when the graph was certified

    @classmethod
    def create(cls, graph: AgentGraph, system_id: str | None = None, signing_key=None,
               validity_days: int = DEFAULT_VALIDITY_DAYS, now: datetime | None = None) -> AgentCertificate:
        """Scan ``graph`` and package its structural profile, valid for ``validity_days``."""
        from agent_certify import __version__

        if not isinstance(validity_days, int) or validity_days < 1:
            raise ValueError("validity_days must be a positive integer")
        start = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
        result = AgentFIScanner(graph).scan()
        topo = _topology(graph, ROLE)
        cert = cls(
            system_id=system_id or graph.session_id or "unnamed-system",
            timestamp=start.strftime(_TS),
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
            cert_format=CURRENT_FORMAT,
            not_before=start.strftime(_TS),
            not_after=(start + timedelta(days=validity_days)).strftime(_TS),
            skipped_records=graph.skipped_records,
        )
        if signing_key is not None:
            cert.sign(signing_key)
        return cert

    # --------------------------------------------------------------- signature
    def payload(self) -> bytes:
        """The exact bytes the signature covers (see the module docstring)."""
        data = asdict(self)
        data.pop("signature")
        if self.cert_format >= 2:
            data["fi_score"] = f"{self.fi_score:.10f}"
            return DOMAIN + json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        for key in _V2_ONLY:                   # pre-v0.5 encoding, kept so old signatures still verify
            data.pop(key)
        if data["identity"] == ID:
            data.pop("identity")               # pre-v0.3 certificates were signed without this field
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
        """True only when the certificate was signed by ``public_key`` and not edited since.

        ``public_key`` is the issuer's key (hex or 32 raw bytes), obtained through a
        trusted channel. Without it this returns False: the key recorded in the
        certificate proves nothing, since whoever edits the certificate can
        replace it too.
        """
        if not self.signature or public_key is None:
            return False
        trusted = _public_key_hex(public_key)
        if trusted is None:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted)).verify(
                base64.b64decode(self.signature, validate=True), self.payload())
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            return False
        return True

    # ------------------------------------------------------------ verification
    def verify(self, graph: AgentGraph, fi_tolerance: float = DEFAULT_FI_TOLERANCE,
               public_key: str | bytes | None = None, *, allow_unsigned: bool = False,
               ignore_expiry: bool = False, expected_system_id: str | None = None,
               now: datetime | None = None) -> DriftReport:
        """Compare a live graph against this certificate.

        Fails (``is_valid`` False) when: the topology or FI changed; no trusted
        ``public_key`` is given (unless ``allow_unsigned``); the certificate is
        unsigned or its signature does not match that key; the current time is
        outside [``not_before``, ``not_after``] (unless ``ignore_expiry``); the
        system id differs from ``expected_system_id``. Agents are compared the
        way the certificate names them: by type since v0.3, by spawn id before.
        """
        reasons: list[str] = []
        warnings: list[str] = []

        # --- trust: signature against a key the caller supplies
        sig_ok: bool | None = None
        if public_key is not None:
            if not self.is_signed:
                reasons.append("Certificate is not signed")
                sig_ok = False
            else:
                sig_ok = self.signature_valid(public_key)
                if not sig_ok:
                    reasons.append("Certificate signature is invalid or was not made by the trusted key")
        elif allow_unsigned:
            warnings.append("Signature not checked (unsigned certificates explicitly allowed)")
        elif not self.is_signed:
            reasons.append("Certificate is not signed")
        else:
            reasons.append("No trusted public key given: the signature cannot be checked")

        # --- validity window
        moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if not (self.not_before or self.not_after):
            warnings.append("Certificate has no validity period (issued before v0.5): it never expires")
        elif not ignore_expiry:
            try:
                if self.not_before and moment < _parse_ts(self.not_before):
                    reasons.append(f"Certificate not valid before {self.not_before}")
                if self.not_after and moment > _parse_ts(self.not_after):
                    reasons.append(f"Certificate expired on {self.not_after}")
            except ValueError:
                reasons.append("Certificate validity dates are malformed")
        if self.cert_format < CURRENT_FORMAT:
            warnings.append("Legacy certificate format (issued before v0.5); re-issue it to get the current format")
        if expected_system_id is not None and expected_system_id != self.system_id:
            reasons.append(f"Certificate is for system {self.system_id!r}, not {expected_system_id!r}")
        if not (isinstance(self.fi_score, (int, float)) and math.isfinite(self.fi_score)):
            reasons.append("Certificate FI is not a finite number")

        # --- topology
        result = AgentFIScanner(graph).scan()
        topo = _topology(graph, self.identity)
        now_nodes = dict(topo["nodes"])
        now_edges = {tuple(e) for e in topo["edges"]}
        cert_edges = {tuple(e) for e in self.edges}
        kind_changed = sorted(n for n in set(now_nodes) & set(self.nodes) if now_nodes[n] != self.nodes[n])
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
        fi_delta = result.fi - self.fi_score if math.isfinite(self.fi_score) else float("nan")
        hash_match = graph_hash(graph, self.identity) == self.graph_hash

        def is_agent_type(n):
            return self.identity == ROLE and n.startswith("agent:")

        added_types = [n for n in added_nodes if is_agent_type(n)]
        removed_types = [n for n in removed_nodes if is_agent_type(n)]
        added_other = [n for n in added_nodes if not is_agent_type(n)]
        removed_other = [n for n in removed_nodes if not is_agent_type(n)]

        topology_reasons = [f"New agent type: {n} (not in certified baseline)" for n in added_types]
        topology_reasons += [f"Missing agent type: {n} (was in certified baseline)" for n in removed_types]
        topology_reasons += [f"Node kind changed: {n} (was {self.nodes[n]}, now {now_nodes[n]})" for n in kind_changed]
        if added_other:
            topology_reasons.append(f"{len(added_other)} node(s) not in the certified topology: {', '.join(added_other)}")
        if removed_other:
            topology_reasons.append(f"{len(removed_other)} certified node(s) missing: {', '.join(removed_other)}")
        if added_edges:
            topology_reasons.append(f"{len(added_edges)} new invocation link(s): "
                                    + ", ".join(f"{s} -> {t}" for s, t in added_edges))
        if removed_edges:
            topology_reasons.append(f"{len(removed_edges)} certified link(s) gone: "
                                    + ", ".join(f"{s} -> {t}" for s, t in removed_edges))
        if not hash_match and not topology_reasons:
            topology_reasons.append("Topology hash differs from the certified one")
        reasons += topology_reasons
        if math.isfinite(fi_delta) and abs(fi_delta) >= fi_tolerance:
            reasons.append(f"FI changed by {fi_delta:+.4f} (tolerance {fi_tolerance})")
        if graph.skipped_records:
            warnings.append(f"{graph.skipped_records} record(s) of the live session could not be read")

        return DriftReport(
            is_valid=not reasons, graph_hash_match=hash_match,
            fi_certified=self.fi_score, fi_current=result.fi, fi_delta=fi_delta,
            added_nodes=added_nodes, removed_nodes=removed_nodes,
            added_edges=added_edges, removed_edges=removed_edges,
            changed_classifications=changed, signature_valid=sig_ok,
            certificate_id=self.certificate_id, verified_at=_now(), reasons=reasons,
            added_agent_types=added_types, removed_agent_types=removed_types,
            kind_changes=kind_changed, warnings=warnings,
        )

    # --------------------------------------------------------------------- io
    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return p

    @classmethod
    def from_dict(cls, data) -> AgentCertificate:
        """Build a certificate from untrusted JSON data, checking every field's type and range.

        Raises ``ValueError("Invalid certificate format")`` on any problem; the
        message deliberately names no field or value.
        """
        try:
            _validate(data)
            return cls(**data)
        except (TypeError, KeyError, AttributeError):
            raise ValueError("Invalid certificate format") from None

    @classmethod
    def load(cls, path) -> AgentCertificate:
        """Read a certificate written by :meth:`save`. NaN and Infinity are rejected."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            raise ValueError("Invalid certificate format") from None
        return cls.from_dict(data)


def _reject_constant(name: str):
    raise ValueError("Invalid certificate format")


_HEX64 = re.compile(r"[0-9a-f]{64}")
_FIELD_TYPES = {f.name: f for f in fields(AgentCertificate)}


def _validate(data) -> None:
    def check(ok: bool):
        if not ok:
            raise ValueError("Invalid certificate format")

    def is_count(v):
        return isinstance(v, int) and not isinstance(v, bool) and v >= 0

    def is_str_list(v):
        return isinstance(v, list) and all(isinstance(x, str) for x in v)

    check(isinstance(data, dict))
    check(set(data) <= set(_FIELD_TYPES))
    required = {n for n, f in _FIELD_TYPES.items() if f.default is MISSING and f.default_factory is MISSING}
    check(required <= set(data))
    for key in ("system_id", "timestamp", "graph_hash", "signature", "signer_public_key", "certificate_id",
                "agent_certify_version", "identity", "not_before", "not_after"):
        if key in data:
            check(isinstance(data[key], str))
    fi = data["fi_score"]
    check(isinstance(fi, (int, float)) and not isinstance(fi, bool) and math.isfinite(fi) and 0 <= fi <= 1)
    for key in ("node_count", "edge_count", "bridge_count", "skipped_records"):
        if key in data:
            check(is_count(data[key]))
    check(is_str_list(data["critical_nodes"]))
    check(isinstance(data["node_classifications"], dict)
          and all(isinstance(k, str) and isinstance(v, str) for k, v in data["node_classifications"].items()))
    check(bool(_HEX64.fullmatch(data["graph_hash"])))
    if "nodes" in data:
        check(isinstance(data["nodes"], dict)
              and all(isinstance(k, str) and v in NODE_KINDS for k, v in data["nodes"].items()))
    if "edges" in data:
        check(isinstance(data["edges"], list) and all(is_str_list(e) and len(e) == 2 for e in data["edges"]))
    check(data.get("identity", ID) in (ID, ROLE))
    check(data.get("cert_format", 1) in (1, 2) and not isinstance(data.get("cert_format", 1), bool))
    if data.get("signer_public_key"):
        check(bool(_HEX64.fullmatch(data["signer_public_key"])))
    if data.get("signature"):
        try:
            check(len(base64.b64decode(data["signature"], validate=True)) == 64)
        except (binascii.Error, ValueError):
            check(False)
    stamps = {}
    for key in ("timestamp", "not_before", "not_after"):
        if data.get(key):
            try:
                stamps[key] = _parse_ts(data[key])
            except ValueError:
                check(False)                    # strptime's message would quote the value
    if "not_before" in stamps and "not_after" in stamps:
        check(stamps["not_before"] <= stamps["not_after"])


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
    signature_valid: bool | None      # None = not checked (no key, unsigned certificates allowed)
    certificate_id: str
    verified_at: str
    reasons: list[str] = field(default_factory=list)
    added_agent_types: list[str] = field(default_factory=list)
    removed_agent_types: list[str] = field(default_factory=list)
    kind_changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        sig = "not checked" if self.signature_valid is None else ("valid" if self.signature_valid else "INVALID")
        lines = [
            f"Verification: {'PASS' if self.is_valid else 'FAIL'}",
            f"  FI: {self.fi_certified:.4f} -> {self.fi_current:.4f} (delta={self.fi_delta:+.4f})",
            f"  Topology hash match: {self.graph_hash_match}",
            f"  Role changes: {len(self.changed_classifications)} (informational)",
            f"  Signature: {sig}",
            f"  Certificate: {self.certificate_id}",
        ]
        lines += [f"  - {r}" for r in self.reasons]
        lines += [f"  ! {w}" for w in self.warnings]
        return "\n".join(lines)
