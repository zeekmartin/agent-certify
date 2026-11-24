# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
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

Egress (``cert_format`` 3, since v0.8.0)
----------------------------------------
A certificate also records **where the system was allowed to send data** when
it was issued: the destination patterns an operator had accepted and rejected,
the forbidden regions in force, and the destinations actually observed. It is
part of the signed bytes, so it cannot be edited after the fact, and
:meth:`verify` uses it to report a destination the certificate does not cover
and a destination in a forbidden country.

The observed list can be left out (``omit_observed_destinations``,
``certify --omit-observed-destinations``) for a certificate that leaves the
organisation: host names from a real session are not something to hand to a
third party with a signature on them. The rules stay, and ``verify`` then
checks the rejected patterns and the forbidden regions and says so.

``graph_hash`` does **not** change: it stays the topology hash it has always
been, so a certificate's identity is still its shape. Formats 1 and 2 keep
their original encoding — the ``egress`` field is dropped from the signed bytes
for them — so every signature issued before this still verifies, and a
certificate without the section is simply not checked for egress drift.

Regions are decided **offline** here as everywhere else: a ccTLD, or an address
literal looked up in a local database the operator supplies. ``verify`` never
resolves a name (see :mod:`agent_certify.regions`).
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

from agent_certify.domains import domain_matches, matching_pattern
from agent_certify.graph import NODE_KINDS, AgentGraph
from agent_certify.regions import OFFLINE, RegionResolver
from agent_certify.scanner import AgentFIScanner

DEFAULT_FI_TOLERANCE = 0.001
DEFAULT_VALIDITY_DAYS = 90
DOMAIN = b"agent-certify/cert/v1\x00"
CURRENT_FORMAT = 3

#: Certificate format -> the oldest ``agent_certify.__version__`` allowed to
#: write it. A format is a wire contract: a verifier that predates one cannot
#: read it, so the version that introduced it is part of its definition rather
#: than a release note. The table exists so that adding a format without
#: declaring its version is a **test failure** instead of a surprise for
#: whoever has to tell a reader which version to install.
#:
#: Format 1 is pre-v0.5 (no validity window). Format 2 added the window and
#: ``skipped_records``. Format 3 added the signed ``egress`` section.
#: What a verification could decide about egress coverage.
#:
#: * ``checked`` — the certificate records what the system was observed
#:   reaching, so every destination of the live session was compared to it.
#: * ``nothing_reached`` — the session reached nowhere, so there is nothing to
#:   cover and nothing to doubt.
#: * ``not_recorded`` — the certificate was issued with
#:   ``--omit-observed-destinations``: its patterns and forbidden regions were
#:   checked, coverage was not.
#: * ``no_section`` — the certificate predates ``cert_format`` 3 and carries no
#:   egress rules at all.
#:
#: The last two are the ones ``verify`` will not call a pass: see
#: :attr:`DriftReport.egress_verifiable`.
COVERAGE_CHECKED = "checked"
COVERAGE_NOTHING_REACHED = "nothing_reached"
COVERAGE_NOT_RECORDED = "not_recorded"
COVERAGE_NO_SECTION = "no_section"
EGRESS_COVERAGE_STATES = (COVERAGE_CHECKED, COVERAGE_NOTHING_REACHED,
                          COVERAGE_NOT_RECORDED, COVERAGE_NO_SECTION)

MIN_VERSION_FOR_FORMAT = {
    1: "0.1.0",
    2: "0.5.0",
    3: "0.8.0",
}
_TS = "%Y-%m-%dT%H:%M:%SZ"
_V2_ONLY = ("cert_format", "not_before", "not_after", "skipped_records")
_V3_ONLY = ("egress",)

#: The keys of the signed ``egress`` section, and what each holds.
EGRESS_KEYS = ("accepted_domains", "rejected_domains", "forbidden_regions", "destinations",
               "violations_at_issue")


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


def egress_violations(graph: AgentGraph, baseline=None, policy=None,
                      regions: RegionResolver | None = None) -> list[str]:
    """Destinations the session reached that its **own** egress rules forbid.

    A rejected pattern and a forbidden region are decisions the operator had
    already made when the session ran. A certificate is a statement that a
    system is in a known good state, so a system that was breaking those rules
    while being certified is the one case where issuing is the wrong answer:
    the signature would say the opposite of the evidence. ``certify`` refuses,
    and ``--allow-egress-violations`` signs anyway and records what was wrong
    (see :func:`egress_section`).

    Each line names the destination and which rule it broke. Regions are
    resolved **offline** unless the caller passes a resolver that was told
    otherwise.
    """
    resolver = regions or OFFLINE
    rejected = sorted(getattr(baseline, "rejected_domains", ()) or ())
    forbidden: set[str] = set()
    for rule in getattr(policy, "rules", ()) or ():
        if getattr(rule, "kind", "") == "forbidden_region":
            forbidden |= set(rule.regions)
    out = []
    for host in sorted(graph.seen_domains):
        pattern = matching_pattern(host, rejected)
        if pattern:
            out.append(f"{host}: matches rejected pattern {pattern}")
        if forbidden:
            region = resolver.region(host)
            if region.country in forbidden:
                out.append(f"{host}: in forbidden region {region.describe()}")
    return out


def egress_section(graph: AgentGraph, baseline=None, policy=None,
                   include_destinations: bool = True, violations=None) -> dict:
    """The ``egress`` section of a certificate: where this system may send data, and where it did.

    ``accepted_domains`` and ``rejected_domains`` are the operator's patterns
    from the baseline, ``forbidden_regions`` the union of the country codes of
    every ``forbidden_region`` policy rule, and ``destinations`` what the graph
    actually reached. All sorted, so the signed bytes do not depend on set
    order.

    ``violations`` records what was already wrong when the certificate was
    issued (:func:`egress_violations`), so that a certificate forced out with
    ``--allow-egress-violations`` carries the evidence of it, signed. The key
    is absent when there was nothing to record, which is the usual case.

    ``include_destinations=False`` leaves the observed list **out of the
    section entirely** (the key is absent, which is not the same as an empty
    list: that would claim the session reached nothing). The rules stay, so the
    certificate still says what was allowed; what it no longer carries is the
    host names of a real session, which a certificate shared outside the
    organisation would otherwise disclose. :meth:`AgentCertificate.verify` then
    checks the rejected patterns and the forbidden regions, and says that it
    could do no more.
    """
    regions: set[str] = set()
    for rule in getattr(policy, "rules", ()) or ():
        if getattr(rule, "kind", "") == "forbidden_region":
            regions |= set(rule.regions)
    section = {
        "accepted_domains": sorted(getattr(baseline, "accepted_domains", ()) or ()),
        "rejected_domains": sorted(getattr(baseline, "rejected_domains", ()) or ()),
        "forbidden_regions": sorted(regions),
    }
    if include_destinations:
        section["destinations"] = sorted(graph.seen_domains)
    if violations:
        section["violations_at_issue"] = list(violations)
    return section


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


def _key32_hex(key: str | bytes) -> str | None:
    """A 32-byte Ed25519 key as lowercase hex, or None when it is not one.

    An Ed25519 public key and a private seed are both exactly 32 bytes, so one
    shape check serves both sides of the pair; :func:`_public_key_hex` and
    :func:`_private_key_hex` name which side a call is validating, because in a
    key-handling path that is worth saying at the call site.
    """
    try:
        raw = bytes(key) if isinstance(key, (bytes, bytearray)) else bytes.fromhex(str(key).strip())
    except (ValueError, TypeError):
        return None
    return raw.hex() if len(raw) == 32 else None


def _public_key_hex(public_key: str | bytes) -> str | None:
    """Normalise a trusted public key to lowercase hex, or None when it is not 32 bytes."""
    return _key32_hex(public_key)


def _private_key_hex(private_key: str | bytes) -> str | None:
    """Normalise an Ed25519 private seed to lowercase hex, or None when it is not 32 bytes.

    Checked before :func:`_signing_key` gets it, so a file that is not a key
    produces a message naming what was expected instead of a ``ValueError``
    traceback out of ``bytes.fromhex``.
    """
    return _key32_hex(private_key)


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
    #: Since v0.8.0 (``cert_format`` 3): where this system was allowed to send
    #: data when the certificate was issued, and where it was observed sending
    #: it. Keys: :data:`EGRESS_KEYS`. Empty on certificates issued before, which
    #: are then not checked for egress drift.
    egress: dict = field(default_factory=dict)

    @classmethod
    def create(cls, graph: AgentGraph, system_id: str | None = None, signing_key=None,
               validity_days: int = DEFAULT_VALIDITY_DAYS, now: datetime | None = None,
               baseline=None, policy=None, omit_observed_destinations: bool = False,
               regions: RegionResolver | None = None) -> AgentCertificate:
        """Scan ``graph`` and package its structural profile, valid for ``validity_days``.

        ``baseline`` and ``policy``, when given, fill the signed ``egress``
        section: the destination patterns the operator had accepted and
        rejected, and the regions a ``forbidden_region`` rule forbade. The
        destinations observed come from the graph. Pass neither and the section
        records the observed destinations alone — which is still worth signing,
        and still what ``verify`` compares against.

        ``omit_observed_destinations`` keeps the rules and drops the observed
        list, for a certificate that will be shared outside the organisation:
        internal host names are not something to hand over with a signature.

        Whatever the session was already doing wrong against those rules is
        recorded in the section (:func:`egress_violations`), signed with the
        rest. This method does not refuse — ``agent-certify certify`` does,
        unless told ``--allow-egress-violations`` — but a certificate issued
        over violations always carries them.
        """
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
            egress=egress_section(graph, baseline, policy,
                                  include_destinations=not omit_observed_destinations,
                                  violations=egress_violations(graph, baseline, policy, regions)),
        )
        if signing_key is not None:
            cert.sign(signing_key)
        return cert

    # --------------------------------------------------------------- signature
    def payload(self) -> bytes:
        """The exact bytes the signature covers (see the module docstring)."""
        data = asdict(self)
        data.pop("signature")
        if self.cert_format < CURRENT_FORMAT:
            for key in _V3_ONLY:               # not in the bytes a format 1 or 2 signature covered
                data.pop(key, None)
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
               ignore_expiry: bool = False, allow_no_expiry: bool = False,
               expected_system_id: str | None = None,
               now: datetime | None = None, regions: RegionResolver | None = None) -> DriftReport:
        """Compare a live graph against this certificate.

        Fails (``is_valid`` False) when: the topology or FI changed; no trusted
        ``public_key`` is given (unless ``allow_unsigned``); the certificate is
        unsigned or its signature does not match that key; the current time is
        outside [``not_before``, ``not_after``] (unless ``ignore_expiry``), or
        has no window at all (unless ``allow_no_expiry``); the
        system id differs from ``expected_system_id``. Agents are compared the
        way the certificate names them: by type since v0.3, by spawn id before.

        A certificate with an ``egress`` section (format 3) also fails on a
        destination it does not cover, and on one in a region its policy
        forbade. ``regions`` decides those countries and resolves **offline**
        by default (ccTLD only); pass a
        :class:`~agent_certify.regions.RegionResolver` with a local address
        database to read address literals too. Certificates issued before
        format 3 carry no section and are not checked for egress at all.
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
            # A certificate that never expires is a credential with no end,
            # and the only thing that can retire it is the issuer destroying
            # the key that signed it (there is no revocation list: SECURITY.md
            # §2). Until v0.8.0 this was a warning and such a certificate
            # passed; it is now a failure that the operator can waive in one
            # explicit option, because "valid forever" should be a decision
            # rather than a default inherited from a 2026 release.
            if allow_no_expiry:
                warnings.append("Certificate has no validity period (issued before v0.5): it never "
                                "expires, and --allow-no-expiry was given")
            else:
                reasons.append("Certificate has no validity period (issued before v0.5): it would "
                               "never expire. Re-issue it with --validity-days, or pass "
                               "--allow-no-expiry to accept it as it is")
        elif not ignore_expiry:
            try:
                if self.not_before and moment < _parse_ts(self.not_before):
                    reasons.append(f"Certificate not valid before {self.not_before}")
                if self.not_after and moment > _parse_ts(self.not_after):
                    reasons.append(f"Certificate expired on {self.not_after}")
            except ValueError:
                reasons.append("Certificate validity dates are malformed")
        if self.cert_format < CURRENT_FORMAT:
            warnings.append(f"Certificate format {self.cert_format}, current is {CURRENT_FORMAT}: "
                            "re-issue it to record the egress rules and have them checked")
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

        # --- egress: destinations the certificate does not cover, and forbidden regions
        added_destinations, forbidden_destinations = [], []
        coverage = COVERAGE_CHECKED if graph.seen_domains else COVERAGE_NOTHING_REACHED
        if self.egress:
            added_destinations, forbidden_destinations = self._egress_drift(graph, regions or OFFLINE)
            if added_destinations:
                reasons.append(f"{len(added_destinations)} destination(s) not covered by the certificate: "
                               + ", ".join(added_destinations))
            for hit in forbidden_destinations:
                reasons.append(f"Destination {hit['host']} is in forbidden region {hit['country']} "
                               f"({hit['source']})")
            recorded = self.egress.get("violations_at_issue") or ()
            if recorded:
                warnings.append(
                    f"Certificate was issued over {len(recorded)} egress violation(s) already "
                    "present in the certified session (--allow-egress-violations): "
                    + "; ".join(recorded[:3]))
            if "destinations" not in self.egress and graph.seen_domains:
                coverage = COVERAGE_NOT_RECORDED
                warnings.append(
                    "Certificate records no observed destinations (issued with "
                    "--omit-observed-destinations): only its rejected patterns and forbidden "
                    f"regions were checked against the {len(graph.seen_domains)} destination(s) "
                    "of this session, not whether each one was certified")
        elif graph.seen_domains:
            coverage = COVERAGE_NO_SECTION
            warnings.append("Certificate records no egress section (issued before v0.8.0): the "
                            f"{len(graph.seen_domains)} destination(s) of this session are not checked")

        return DriftReport(
            is_valid=not reasons, graph_hash_match=hash_match,
            fi_certified=self.fi_score, fi_current=result.fi, fi_delta=fi_delta,
            added_nodes=added_nodes, removed_nodes=removed_nodes,
            added_edges=added_edges, removed_edges=removed_edges,
            changed_classifications=changed, signature_valid=sig_ok,
            certificate_id=self.certificate_id, verified_at=_now(), reasons=reasons,
            added_agent_types=added_types, removed_agent_types=removed_types,
            kind_changes=kind_changed, warnings=warnings,
            added_destinations=added_destinations, forbidden_destinations=forbidden_destinations,
            egress_coverage=coverage,
        )

    def _egress_drift(self, graph: AgentGraph, resolver: RegionResolver) -> tuple[list[str], list[dict]]:
        """(destinations this certificate does not cover, destinations in a forbidden region).

        Covered means: recorded in the certificate as observed, or matched by
        one of its accepted patterns — and not matched by a rejected one. A
        rejected pattern is an operator's decision that the certificate carries,
        so reaching such a host is drift however often it happens.

        When the certificate records no observed list, coverage cannot be
        decided: only the rejected patterns and the forbidden regions are
        checked, and :meth:`verify` warns that the check was the narrower one.
        """
        observed = "destinations" in self.egress
        certified = set(self.egress.get("destinations") or ())
        accepted = list(self.egress.get("accepted_domains") or ())
        rejected = list(self.egress.get("rejected_domains") or ())
        forbidden = set(self.egress.get("forbidden_regions") or ())
        added, in_forbidden = [], []
        for host in sorted(graph.seen_domains):
            blocked = any(domain_matches(host, pattern) for pattern in rejected)
            if observed:
                covered = not blocked and (host in certified
                                           or any(domain_matches(host, pattern) for pattern in accepted))
            else:
                # No observed list was recorded (--omit-observed-destinations):
                # there is nothing to compare a host against, so the only thing
                # that can still be said is that a rejected pattern forbids it.
                covered = not blocked
            if not covered:
                added.append(host)
            if forbidden:
                region = resolver.region(host)
                if region.country in forbidden:
                    in_forbidden.append({"host": host, "country": region.country,
                                         "source": region.source, "detail": region.describe()})
        return added, in_forbidden

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
_COUNTRY = re.compile(r"[A-Z]{2}")
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
    check(data.get("cert_format", 1) in (1, 2, 3) and not isinstance(data.get("cert_format", 1), bool))
    egress = data.get("egress", {})
    check(isinstance(egress, dict) and set(egress) <= set(EGRESS_KEYS))
    for key in EGRESS_KEYS:
        if key in egress:
            check(is_str_list(egress[key]))
    check(all(_COUNTRY.fullmatch(code) for code in egress.get("forbidden_regions", ())))
    # A section on a certificate that claims an older format was never signed:
    # the older payloads leave it out, so it could be added by anyone.
    check(not egress or data.get("cert_format", 1) >= 3)
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
    #: Destinations of the live session the certificate does not cover, and the
    #: ones in a region its policy forbade ({"host", "country", "source", "detail"}).
    added_destinations: list[str] = field(default_factory=list)
    forbidden_destinations: list[dict] = field(default_factory=list)
    #: What could be decided about egress coverage. One of
    #: :data:`EGRESS_COVERAGE_STATES` — see :attr:`egress_verifiable`.
    egress_coverage: str = COVERAGE_CHECKED

    @property
    def egress_verifiable(self) -> bool:
        """Could this verification decide whether every destination was certified?

        False when the certificate carries no observed list and the session
        reached somewhere: the signature is good and the topology matches, and
        **nobody can say** whether those destinations were the certified ones.
        A pass is the wrong answer to that, and so is a failure — the
        certificate is not invalid, the question is unanswerable — which is why
        ``verify`` exits 3 rather than 0 or 1 unless the operator accepts it.
        """
        return self.egress_coverage in (COVERAGE_CHECKED, COVERAGE_NOTHING_REACHED)

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
        if self.added_destinations or self.forbidden_destinations:
            lines.append(f"  Destinations: {len(self.added_destinations)} not covered, "
                         f"{len(self.forbidden_destinations)} in a forbidden region")
        if not self.egress_verifiable:
            lines.append(f"  Egress coverage: NOT VERIFIABLE ({self.egress_coverage})")
        lines += [f"  - {r}" for r in self.reasons]
        lines += [f"  ! {w}" for w in self.warnings]
        return "\n".join(lines)
