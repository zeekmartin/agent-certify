"""Fragility Index (FI) of an agent graph.

FI is the fraction of communication links with **zero triangle support**: links
whose two endpoints share no common neighbour, so the link has no alternative
two-hop path. It is the same measure sal-torch computes on attention-head
graphs (``sal.fi.compute_fi``), applied here to agents and tools.

  * FI = 0 → every link sits in at least one triangle (fully redundant).
  * FI = 1 → no link sits in a triangle (a tree or star: fully fragile).

Direction is dropped first: two nodes are linked if either ever invoked the
other. Call counts do not enter FI; it is a property of the topology alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from agent_certify.graph import AgentEdge, AgentGraph

CRITICAL, BUFFER, IMMUNE = "CRITICAL", "BUFFER", "IMMUNE"
DEFAULT_CRITICAL_THR = 0.10
DEFAULT_IMMUNE_THR = 0.02


def compute_fi(adjacency) -> float:
    """Fragility Index: fraction of edges with zero triangle support.

    An edge (i, j) is fragile when i and j share no common neighbour, i.e.
    ``(A @ A)[i, j] == 0``. A graph with no edges has FI 0: it has no links
    that could fail. (sal-torch reports 1.0 there; for an attention graph an
    edgeless result means the measurement failed, for an agent graph it just
    means one agent and no tools.)
    """
    A = (np.asarray(adjacency) != 0).astype(np.int64)
    n = A.shape[0] if A.ndim == 2 else 0
    if n < 2:
        return 0.0
    np.fill_diagonal(A, 0)
    common = A @ A
    triu = np.triu_indices(n, k=1)
    edges = A[triu] > 0
    total = int(edges.sum())
    if total == 0:
        return 0.0
    return float(np.sum(common[triu][edges] == 0) / total)


def triangle_counts(graph: AgentGraph) -> dict[frozenset, int]:
    """tri(e) for every undirected edge: the number of triangles containing it."""
    ids, matrix = graph.adjacency_matrix()
    if not ids:
        return {}
    A = np.array(matrix, dtype=np.int64)
    common = A @ A
    index = {nid: i for i, nid in enumerate(ids)}
    return {frozenset((a, b)): int(common[index[a], index[b]]) for a, b in graph.undirected_edges()}


def find_bridges(graph: AgentGraph) -> set[frozenset]:
    """Undirected edges whose removal disconnects their component (iterative Tarjan)."""
    adj: dict[str, list[str]] = {nid: [] for nid in graph.nodes}
    for a, b in graph.undirected_edges():
        adj[a].append(b)
        adj[b].append(a)
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    bridges: set[frozenset] = set()
    t = 0
    for root in sorted(adj):
        if root in disc:
            continue
        disc[root] = low[root] = t
        t += 1
        stack = [(root, None, iter(adj[root]))]
        while stack:
            v, parent, it = stack[-1]
            advanced = False
            for w in it:
                if w == parent:
                    continue
                if w in disc:
                    low[v] = min(low[v], disc[w])
                else:
                    disc[w] = low[w] = t
                    t += 1
                    stack.append((w, v, iter(adj[w])))
                    advanced = True
                    break
            if not advanced:
                stack.pop()
                if parent is not None:
                    low[parent] = min(low[parent], low[v])
                    if low[v] > disc[parent]:
                        bridges.add(frozenset((parent, v)))
    return bridges


def articulation_points(graph: AgentGraph) -> set[str]:
    """Nodes whose removal splits their component into more pieces."""
    base = len(graph.connected_components())
    out = set()
    for nid in graph.nodes:
        # Removing an isolated node lowers the count by one; anything above
        # ``base - 1`` means the node held other nodes together.
        if len(graph.remove_node(nid).connected_components()) > base - (1 if not graph.neighbors(nid) else 0):
            out.add(nid)
    return out


@dataclass
class ScanResult:
    """Structural profile of one agent graph."""
    fi: float
    bridges: list[AgentEdge]
    node_classifications: dict[str, str]
    node_count: int = 0
    edge_count: int = 0                                   # undirected links
    fragile_edges: list[tuple[str, str]] = field(default_factory=list)   # tri(e) == 0
    articulation_points: list[str] = field(default_factory=list)
    fi_deltas: dict[str, float] = field(default_factory=dict)           # FI change on removing each node
    components: int = 1

    @property
    def critical_nodes(self) -> list[str]:
        return sorted(n for n, c in self.node_classifications.items() if c == CRITICAL)

    @property
    def buffer_nodes(self) -> list[str]:
        return sorted(n for n, c in self.node_classifications.items() if c == BUFFER)

    @property
    def immune_nodes(self) -> list[str]:
        return sorted(n for n, c in self.node_classifications.items() if c == IMMUNE)

    def summary(self) -> str:
        return (f"FI={self.fi:.4f} | {self.node_count} nodes, {self.edge_count} links, "
                f"{len(self.bridges)} bridges | {len(self.critical_nodes)} critical, "
                f"{len(self.buffer_nodes)} buffer, {len(self.immune_nodes)} immune")

    def to_dict(self) -> dict:
        return {
            "fi": self.fi,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "components": self.components,
            "bridges": [[e.source, e.target] for e in self.bridges],
            "fragile_edges": [list(e) for e in self.fragile_edges],
            "articulation_points": self.articulation_points,
            "node_classifications": self.node_classifications,
            "fi_deltas": self.fi_deltas,
        }


class AgentFIScanner:
    """Compute FI, bridges and node roles for an :class:`AgentGraph`.

    Usage::

        result = AgentFIScanner(graph).scan()
        result.fi                     # 0.0 .. 1.0
        result.bridges                # AgentEdge list
        result.node_classifications   # {"tool:Bash": "IMMUNE", "claude": "CRITICAL", ...}

    A node is CRITICAL when removing it raises FI by at least ``critical_thr``
    (relative), BUFFER between ``immune_thr`` and ``critical_thr``, IMMUNE
    below (including nodes whose removal lowers FI). A node whose removal disconnects the graph (an articulation point)
    is CRITICAL regardless of FI: it is a single point of failure even when the
    fraction of fragile links happens not to move. ``scan()`` also stores each
    edge's triangle count in ``edge.tri_count``.
    """

    def __init__(self, graph: AgentGraph, critical_thr: float = DEFAULT_CRITICAL_THR,
                 immune_thr: float = DEFAULT_IMMUNE_THR):
        if not 0 <= immune_thr <= critical_thr:
            raise ValueError("need 0 <= immune_thr <= critical_thr")
        self.graph = graph
        self.critical_thr = critical_thr
        self.immune_thr = immune_thr

    def scan(self) -> ScanResult:
        """Compute FI, classify nodes, identify bridges."""
        tri = triangle_counts(self.graph)
        for e in self.graph.edges:
            e.tri_count = tri.get(e.key, 0)
        fi = self._compute_fi()
        bridges = self._find_bridges()
        node_classes, deltas, cut_nodes = self._classify_nodes(fi)
        return ScanResult(
            fi=fi,
            bridges=bridges,
            node_classifications=node_classes,
            node_count=len(self.graph.nodes),
            edge_count=len(tri),
            fragile_edges=sorted(tuple(sorted(k)) for k, v in tri.items() if v == 0),
            articulation_points=sorted(cut_nodes),
            fi_deltas=deltas,
            components=len(self.graph.connected_components()),
        )

    def _compute_fi(self) -> float:
        """FI = proportion of edges with tri(e) = 0, on the undirected graph."""
        _, matrix = self.graph.adjacency_matrix()
        return compute_fi(matrix)

    def _find_bridges(self) -> list[AgentEdge]:
        """Edges whose removal disconnects the graph."""
        keys = find_bridges(self.graph)
        return [e for e in self.graph.edges if e.key in keys]

    def _classify_nodes(self, base_fi: float) -> tuple[dict[str, str], dict[str, float], set[str]]:
        """Classify each node as CRITICAL, BUFFER, or IMMUNE.

        Only an *increase* counts: a node whose removal lowers FI was holding up
        fragile links, not redundancy. (sal-torch's layer classifier uses the
        absolute change.) The increase is relative to the base FI; when the base
        FI is 0 the absolute increase is used instead.
        """
        cut_nodes = articulation_points(self.graph)
        classes, deltas = {}, {}
        for nid in sorted(self.graph.nodes):
            _, m = self.graph.remove_node(nid).adjacency_matrix()
            new_fi = compute_fi(m)
            delta = (new_fi - base_fi) / base_fi if base_fi > 1e-12 else new_fi - base_fi
            deltas[nid] = round(new_fi - base_fi, 6)
            if nid in cut_nodes or delta >= self.critical_thr:
                classes[nid] = CRITICAL
            elif delta >= self.immune_thr:
                classes[nid] = BUFFER
            else:
                classes[nid] = IMMUNE
        return classes, deltas, cut_nodes
