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
    edges: list[AgentEdge] = field(default_factory=list)
    session_id: str | None = None
    project: str | None = None
    total_messages: int = 0
    total_tool_calls: int = 0
    duration_seconds: float | None = None
    started_at: str | None = None        # ISO 8601, UTC
    ended_at: str | None = None
    skipped_records: int = 0             # malformed / oversized records the parser could not read

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
            _check(all(_is_count(data.get(k, 0)) for k in ("total_messages", "total_tool_calls", "skipped_records")))
            duration = data.get("duration_seconds")
            _check(duration is None or (_is_number(duration) and duration >= 0))
            nodes, edges = data.get("nodes", []), data.get("edges", [])
            _check(isinstance(nodes, list) and isinstance(edges, list))
            g = cls(session_id=data.get("session_id"), project=data.get("project"),
                    total_messages=data.get("total_messages", 0), total_tool_calls=data.get("total_tool_calls", 0),
                    duration_seconds=duration, started_at=data.get("started_at"), ended_at=data.get("ended_at"),
                    skipped_records=data.get("skipped_records", 0))
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
                    m.metadata.setdefault(k, v)
            for e in g.edges:
                f = out.get_edge(e.source, e.target)
                if f is None:
                    f = AgentEdge(e.source, e.target, weight=e.weight, errors=e.errors)
                    out.edges.append(f)
                    out._index_append(f)
                else:
                    f.weight += e.weight
                    f.errors += e.errors
            out.total_messages += g.total_messages
            out.total_tool_calls += g.total_tool_calls
            out.skipped_records += g.skipped_records
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
