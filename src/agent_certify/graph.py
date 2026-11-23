# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Agent graph data model.

An :class:`AgentGraph` is the communication topology of a multiagent session:
agents, tools and humans as nodes, invocations as directed edges. Structural
analysis (FI, bridges, blast radius) works on the undirected version, where two
nodes are linked if either one ever invoked the other.

Edges are indexed by (source, target) and adjacency sets are kept alongside, so
edge lookups are O(1) and neighbourhoods O(degree). The index follows ``edges``:
it is rebuilt whenever that list is replaced or changes length outside
:meth:`AgentGraph.add_call`.
"""
from __future__ import annotations

import copy
import math
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field

NODE_KINDS = ("human", "orchestrator", "agent", "tool", "file")   # file: code written (Cursor agent-trace)


@dataclass
class AgentNode:
    """A node in the agent graph — an agent or a tool."""
    id: str                          # unique identifier
    kind: str                        # "agent", "tool", "human", "orchestrator", "file"
    name: str                        # display name (e.g., "Bash", "Edit", "sub-agent-1")
    call_count: int = 0              # how many times this node was invoked
    error_count: int = 0             # how many times it returned an error
    metadata: dict = field(default_factory=dict)


@dataclass
class AgentEdge:
    """A directed edge: source invoked target."""
    source: str                      # caller node id
    target: str                      # callee node id
    weight: int = 1                  # number of invocations
    errors: int = 0                  # number of failed invocations
    tri_count: int = 0               # triangle participation (computed by scanner)

    @property
    def key(self) -> frozenset:
        """Undirected identity of the edge."""
        return frozenset((self.source, self.target))


@dataclass
class AgentGraph:
    """The complete topology of a multiagent session."""
    nodes: dict[str, AgentNode] = field(default_factory=dict)
    #: Directed invocations. Append through :meth:`add_call` or replace the
    #: whole list; the lookup index tracks it by ``(id(edges), len(edges))``,
    #: so an in-place swap that leaves the length unchanged
    #: (``edges[0] = other``, or ``pop()`` then ``append()``) leaves the index
    #: stale. Nothing in the package does that — the four mutation sites are
    #: ``add_call``, ``merge``, ``remove_node`` and ``from_dict``, and the
    #: first two maintain the index while the last two replace the list — but
    #: code outside it should rebuild by assigning a fresh list rather than
    #: editing this one in place.
    edges: list[AgentEdge] = field(default_factory=list)
    session_id: str | None = None
    project: str | None = None
    total_messages: int = 0
    total_tool_calls: int = 0
    duration_seconds: float | None = None
    started_at: str | None = None        # ISO 8601, UTC
    ended_at: str | None = None
    skipped_records: int = 0             # malformed / oversized records the parser could not read
    total_records: int = 0               # records the parser attempted (read or skipped)
    seen_domains: set[str] = field(default_factory=set)   # network destinations the tool calls pointed at
    #: Outbound bytes and calls per destination: the size of the arguments of
    #: every call that named that host, plus the literal payloads on its
    #: command lines. Numbers only, never content; see
    #: :func:`agent_certify.domains.measure_call`.
    egress_bytes: dict[str, int] = field(default_factory=dict)
    egress_calls: dict[str, int] = field(default_factory=dict)
    #: Calls whose destination scan hit a limit, so a host after it would not
    #: have been seen. Counted like ``skipped_records`` rather than dropped in
    #: silence, because a bound that hides a destination is an evasion:
    #: ``destination_scan_truncated`` reports them.
    truncated_scans: int = 0
    truncated_network_scans: int = 0     # of those, the ones that did name a destination
    truncation_reasons: set[str] = field(default_factory=set)
    source: str | None = field(default=None, compare=False, repr=False)   # file it came from; not serialised

    _edge_index: dict = field(default=None, init=False, repr=False, compare=False)
    _adjacency: dict = field(default=None, init=False, repr=False, compare=False)
    _successors: dict = field(default=None, init=False, repr=False, compare=False)
    _index_key: tuple = field(default=None, init=False, repr=False, compare=False)

    # ---------------------------------------------------------------- index
    def _ensure_index(self) -> None:
        key = (id(self.edges), len(self.edges))
        if self._index_key == key:
            return
        index, adj, succ = {}, {}, {}
        for e in self.edges:
            index[(e.source, e.target)] = e
            adj.setdefault(e.source, set()).add(e.target)
            adj.setdefault(e.target, set()).add(e.source)
            succ.setdefault(e.source, set()).add(e.target)
        self._edge_index, self._adjacency, self._successors, self._index_key = index, adj, succ, key

    def _index_append(self, e: AgentEdge) -> None:
        """Record an edge just appended to ``edges`` without rebuilding the index."""
        self._edge_index[(e.source, e.target)] = e
        self._adjacency.setdefault(e.source, set()).add(e.target)
        self._adjacency.setdefault(e.target, set()).add(e.source)
        self._successors.setdefault(e.source, set()).add(e.target)
        self._index_key = (id(self.edges), len(self.edges))

    @property
    def has_data(self) -> bool:
        """False when the parser found nothing usable: no messages, no calls, no links."""
        return bool(self.total_messages or self.total_tool_calls or self.edges)

    # ------------------------------------------------------------- building
    def add_node(self, node_id: str, kind: str, name: str | None = None, **metadata) -> AgentNode:
        """Add a node, or return the existing one with that id."""
        if kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind {kind!r}; expected one of {NODE_KINDS}")
        node = self.nodes.get(node_id)
        if node is None:
            node = self.nodes[node_id] = AgentNode(id=node_id, kind=kind, name=name or node_id)
        node.metadata.update(metadata)
        return node

    def get_edge(self, source: str, target: str) -> AgentEdge | None:
        self._ensure_index()
        return self._edge_index.get((source, target))

    def add_call(self, source: str, target: str, error: bool = False, count: int = 1) -> AgentEdge:
        """Record ``count`` invocations of ``target`` by ``source``."""
        for nid in (source, target):
            if nid not in self.nodes:
                raise KeyError(f"unknown node {nid!r}; add it with add_node() first")
        if source == target:
            raise ValueError(f"self-loop on {source!r}")
        edge = self.get_edge(source, target)
        if edge is None:
            edge = AgentEdge(source, target, weight=0)
            self.edges.append(edge)
            self._index_append(edge)
        edge.weight += count
        self.nodes[target].call_count += count
        if error:
            edge.errors += 1
            self.nodes[target].error_count += 1
        return edge

    def record_domains(self, node_id: str, domains) -> None:
        """Note the network destinations one node's calls pointed at.

        They are kept twice on purpose: on the graph as
        :attr:`seen_domains`, which is what a baseline learns and an anomaly
        check compares, and on the node, so a report can say *who* called a
        host. Nothing is resolved; see :mod:`agent_certify.domains`.
        """
        domains = {d for d in domains if d}
        if not domains:
            return
        if node_id not in self.nodes:
            raise KeyError(f"unknown node {node_id!r}; add it with add_node() first")
        self.seen_domains |= domains
        seen = self.nodes[node_id].metadata.setdefault("domains", [])
        seen[:] = sorted(set(seen) | domains)

    def record_egress(self, node_id: str, domains, outbound_bytes: int = 0, calls: int = 1) -> None:
        """Note one tool call's destinations, and the bytes it sent to each.

        The size is attributed in full to every destination of the call, for
        the reason :class:`~agent_certify.domains.CallEgress` gives: a log does
        not say how one call's bytes divided between two hosts.

        Kept twice like the destinations themselves — on the graph, which is
        what a baseline learns and ``egress_volume_spike`` compares, and on the
        calling node, so a report can say who sent them.
        """
        domains = {d for d in domains if d}
        if not domains:
            return
        self.record_domains(node_id, domains)
        size, calls = max(0, int(outbound_bytes)), max(0, int(calls))
        per_node = self.nodes[node_id].metadata.setdefault("egress", {})
        for domain in sorted(domains):
            self.egress_bytes[domain] = self.egress_bytes.get(domain, 0) + size
            self.egress_calls[domain] = self.egress_calls.get(domain, 0) + calls
            entry = per_node.setdefault(domain, {"bytes": 0, "calls": 0})
            entry["bytes"] += size
            entry["calls"] += calls

    def note_scan_truncation(self, node_id: str | None, reasons, network: bool = False) -> None:
        """Record that a limit stopped one call's destination scan.

        ``network`` says the call did name a destination, which is what makes
        the anomaly critical rather than a warning: the call reached somewhere,
        and something after the limit was not read.
        """
        reasons = {r for r in reasons if r}
        if not reasons:
            return
        self.truncated_scans += 1
        self.truncation_reasons |= reasons
        if network:
            self.truncated_network_scans += 1
        if node_id and node_id in self.nodes:
            meta = self.nodes[node_id].metadata
            meta["scan_truncated"] = meta.get("scan_truncated", 0) + 1
            meta["scan_truncated_reasons"] = sorted(set(meta.get("scan_truncated_reasons", [])) | reasons)

    def egress_total(self) -> int:
        """Outbound bytes over every destination of the session."""
        return sum(self.egress_bytes.values())

    def domain_callers(self, domain: str) -> list[str]:
        """Ids of the nodes whose calls pointed at ``domain``."""
        return sorted(nid for nid, n in self.nodes.items() if domain in (n.metadata.get("domains") or ()))

    def record_error(self, source: str, target: str) -> None:
        """Mark one already-recorded invocation of ``target`` by ``source`` as failed."""
        edge = self.get_edge(source, target)
        if edge is None:
            raise KeyError(f"no edge {source!r} -> {target!r}")
        edge.errors += 1
        self.nodes[target].error_count += 1

    # ------------------------------------------------------------ structure
    def adjacency_matrix(self) -> tuple[list[str], list[list[int]]]:
        """Return (node_ids, matrix) for FI computation.

        The matrix is the binary, symmetric adjacency of the undirected graph:
        ``matrix[i][j] == 1`` when either node ever invoked the other. Node ids
        are sorted so the matrix is canonical for a given topology. O(n²) memory:
        the scanner itself works on :meth:`adjacency` instead.
        """
        ids = sorted(self.nodes)
        index = {nid: i for i, nid in enumerate(ids)}
        n = len(ids)
        matrix = [[0] * n for _ in range(n)]
        for e in self.edges:
            i, j = index[e.source], index[e.target]
            matrix[i][j] = matrix[j][i] = 1
        return ids, matrix

    def neighbors(self, node_id: str) -> set[str]:
        """Undirected neighbours of ``node_id`` (a copy; safe to modify)."""
        self._ensure_index()
        return set(self._adjacency.get(node_id, ()))

    def adjacency(self) -> dict[str, set[str]]:
        """Undirected adjacency of every node, isolated ones included. Do not modify the sets."""
        self._ensure_index()
        empty: set[str] = set()
        return {nid: self._adjacency.get(nid, empty) for nid in self.nodes}

    def successors(self, node_id: str) -> set[str]:
        """Nodes that ``node_id`` invoked."""
        self._ensure_index()
        return set(self._successors.get(node_id, ()))

    def undirected_edges(self) -> list[tuple[str, str]]:
        """Distinct undirected edges as sorted (a, b) pairs."""
        return sorted({tuple(sorted((e.source, e.target))) for e in self.edges})

    def remove_node(self, node_id: str) -> AgentGraph:
        """Return a copy with node_id and its edges removed."""
        if node_id not in self.nodes:
            raise KeyError(f"unknown node {node_id!r}")
        g = copy.deepcopy(self)
        del g.nodes[node_id]
        g.edges = [e for e in g.edges if node_id not in (e.source, e.target)]
        return g

    def connected_components(self, without: str | None = None) -> list[set[str]]:
        """Return connected components of the undirected version.

        ``without`` leaves one node out, as if it were removed, without copying the graph.
        """
        adj = self.adjacency()
        seen: set[str] = {without} if without is not None else set()
        components = []
        for start in sorted(adj):
            if start in seen:
                continue
            comp, stack = set(), [start]
            while stack:
                v = stack.pop()
                if v in comp:
                    continue
                comp.add(v)
                stack.extend(w for w in adj[v] if w not in comp and w != without)
            seen |= comp
            components.append(comp)
        return components

    # ---------------------------------------------------------------- lookup
    def role(self, node_id: str) -> str:
        """Stable identity of a node across sessions.

        Sub-agent ids are unique per spawn, so an agent's role is its type
        (``agent:Explore``, or ``agent:unknown``); every other node is its own role.
        """
        node = self.nodes[node_id]
        if node.kind == "agent":
            return f"agent:{node.metadata.get('agentType') or 'unknown'}"
        return node_id

    def resolve(self, name: str) -> str:
        """Find a node id from an id or display name (case-insensitive).

        ``resolve("bash")`` finds ``tool:Bash``. Raises ``KeyError`` when the name
        matches no node or more than one.
        """
        if name in self.nodes:
            return name
        low = name.lower()
        hits = [nid for nid, n in self.nodes.items() if nid.lower() == low or n.name.lower() == low]
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise KeyError(f"no node named {name!r}; known: {', '.join(sorted(self.nodes))}")
        raise KeyError(f"{name!r} is ambiguous: {', '.join(sorted(hits))}")

    # ------------------------------------------------------------------- io
    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "project": self.project,
            "total_messages": self.total_messages,
            "total_tool_calls": self.total_tool_calls,
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "skipped_records": self.skipped_records,
            "total_records": self.total_records,
            "seen_domains": sorted(self.seen_domains),
            "egress_bytes": dict(sorted(self.egress_bytes.items())),
            "egress_calls": dict(sorted(self.egress_calls.items())),
            "truncated_scans": self.truncated_scans,
            "truncated_network_scans": self.truncated_network_scans,
            "truncation_reasons": sorted(self.truncation_reasons),
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> AgentGraph:
        """Rebuild a graph from :meth:`to_dict` output; ``ValueError("Invalid graph format")`` otherwise."""
        try:
            _check(isinstance(data, dict))
            _check(all(data.get(k) is None or isinstance(data[k], str)
                       for k in ("session_id", "project", "started_at", "ended_at")))
            _check(all(_is_count(data.get(k, 0))
                       for k in ("total_messages", "total_tool_calls", "skipped_records", "total_records")))
            duration = data.get("duration_seconds")
            _check(duration is None or (_is_number(duration) and duration >= 0))
            nodes, edges = data.get("nodes", []), data.get("edges", [])
            _check(isinstance(nodes, list) and isinstance(edges, list))
            domains = data.get("seen_domains", [])          # absent in graphs written before v0.7
            _check(isinstance(domains, list) and all(isinstance(d, str) for d in domains))
            volumes = {}
            for key in ("egress_bytes", "egress_calls"):    # absent in graphs written before v0.8
                value = data.get(key, {})
                _check(isinstance(value, dict)
                       and all(isinstance(d, str) and _is_count(n) for d, n in value.items()))
                volumes[key] = dict(value)
            _check(all(_is_count(data.get(k, 0)) for k in ("truncated_scans", "truncated_network_scans")))
            reasons = data.get("truncation_reasons", [])
            _check(isinstance(reasons, list) and all(isinstance(r, str) for r in reasons))
            g = cls(session_id=data.get("session_id"), project=data.get("project"),
                    total_messages=data.get("total_messages", 0), total_tool_calls=data.get("total_tool_calls", 0),
                    duration_seconds=duration, started_at=data.get("started_at"), ended_at=data.get("ended_at"),
                    skipped_records=data.get("skipped_records", 0), total_records=data.get("total_records", 0),
                    seen_domains=set(domains), truncated_scans=data.get("truncated_scans", 0),
                    truncated_network_scans=data.get("truncated_network_scans", 0),
                    truncation_reasons=set(reasons), **volumes)
            for n in nodes:
                _check(isinstance(n, dict) and set(n) <= set(AgentNode.__dataclass_fields__))
                _check(isinstance(n.get("id"), str) and n.get("kind") in NODE_KINDS and isinstance(n.get("name"), str))
                _check(_is_count(n.get("call_count", 0)) and _is_count(n.get("error_count", 0)))
                _check(isinstance(n.get("metadata", {}), dict))
                g.nodes[n["id"]] = AgentNode(**n)
            for e in edges:
                _check(isinstance(e, dict) and set(e) <= set(AgentEdge.__dataclass_fields__))
                _check(e.get("source") in g.nodes and e.get("target") in g.nodes and e["source"] != e["target"])
                _check(all(_is_count(e.get(k, 0)) for k in ("weight", "errors", "tri_count")))
            g.edges = [AgentEdge(**e) for e in edges]
        except (TypeError, KeyError, AttributeError):
            raise ValueError("Invalid graph format") from None
        return g

    @classmethod
    def merge(cls, graphs: Iterable[AgentGraph], session_id: str | None = None) -> AgentGraph:
        """Union of several graphs: nodes with the same id are combined and counts summed."""
        out = cls(session_id=session_id)
        durations = []
        projects = set()
        for g in graphs:
            for n in g.nodes.values():
                m = out.add_node(n.id, n.kind, n.name)
                m.call_count += n.call_count
                m.error_count += n.error_count
                for k, v in n.metadata.items():
                    if k in ("domains", "egress", "scan_truncated", "scan_truncated_reasons"):
                        continue        # a set or a sum, not a scalar: combined below
                    m.metadata.setdefault(k, v)
                # The per-node destinations have to be unioned, not defaulted:
                # one tool node reached one host in the first session and
                # another in the second, and setdefault would keep only the
                # first — leaving a host in seen_domains with no caller, which
                # is exactly what record_domains keeps the second copy for.
                if n.metadata.get("domains"):
                    out.record_domains(n.id, n.metadata["domains"])
                # Same reason, same fix, for the per-node byte counters: they
                # are sums, so they are added rather than defaulted.
                for domain, stats in (n.metadata.get("egress") or {}).items():
                    entry = m.metadata.setdefault("egress", {}).setdefault(domain, {"bytes": 0, "calls": 0})
                    entry["bytes"] += int(stats.get("bytes", 0) or 0)
                    entry["calls"] += int(stats.get("calls", 0) or 0)
                for key in ("scan_truncated",):
                    if n.metadata.get(key):
                        m.metadata[key] = m.metadata.get(key, 0) + n.metadata[key]
                if n.metadata.get("scan_truncated_reasons"):
                    m.metadata["scan_truncated_reasons"] = sorted(
                        set(m.metadata.get("scan_truncated_reasons", []))
                        | set(n.metadata["scan_truncated_reasons"]))
            for e in g.edges:
                f = out.get_edge(e.source, e.target)
                if f is None:
                    f = AgentEdge(e.source, e.target, weight=e.weight, errors=e.errors)
                    out.edges.append(f)
                    out._index_append(f)
                else:
                    f.weight += e.weight
                    f.errors += e.errors
            out.seen_domains |= g.seen_domains
            for domain, size in g.egress_bytes.items():
                out.egress_bytes[domain] = out.egress_bytes.get(domain, 0) + size
            for domain, calls in g.egress_calls.items():
                out.egress_calls[domain] = out.egress_calls.get(domain, 0) + calls
            out.truncated_scans += g.truncated_scans
            out.truncated_network_scans += g.truncated_network_scans
            out.truncation_reasons |= g.truncation_reasons
            out.total_messages += g.total_messages
            out.total_tool_calls += g.total_tool_calls
            out.skipped_records += g.skipped_records
            out.total_records += g.total_records
            if g.duration_seconds is not None:
                durations.append(g.duration_seconds)
            if g.project:
                projects.add(g.project)
            if g.started_at and (out.started_at is None or g.started_at < out.started_at):
                out.started_at = g.started_at
            if g.ended_at and (out.ended_at is None or g.ended_at > out.ended_at):
                out.ended_at = g.ended_at
        out.duration_seconds = sum(durations) if durations else None
        out.project = projects.pop() if len(projects) == 1 else None
        return out


def _check(ok: bool) -> None:
    if not ok:
        raise ValueError("Invalid graph format")


def _is_count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
