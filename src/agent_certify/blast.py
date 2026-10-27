# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Blast radius: what a compromised agent or tool can touch.

A compromised node can act on everything it invokes, and can influence
everything that invokes it (a poisoned tool result steers its caller). Spread
is therefore measured on the undirected graph. Tool *access* follows call
direction: the tools a node can reach by invoking, directly or through the
agents it spawns.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from agent_certify.graph import AgentGraph
from agent_certify.scanner import FIStructure


@dataclass
class BlastReport:
    """Impact of compromising one node."""
    compromised: str
    direct_impact: list[str]                 # 1-hop neighbours
    total_reachable: list[str]               # within ``hops`` hops
    accessible_tools: list[str]              # tools reachable by invocation
    remaining_fi: float                      # FI after isolating the node
    system_fragmented: bool                  # isolating it splits the system
    isolation_recommendation: str
    hops: int = 3
    baseline_fi: float = 0.0
    components_after: list[list[str]] = field(default_factory=list)
    reach_by_hop: dict[int, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        lines = [
            f"Blast radius: {self.compromised}",
            f"  Direct impact ({len(self.direct_impact)}): {', '.join(self.direct_impact) or '-'}",
            f"  Reachable within {self.hops} hops: {len(self.total_reachable)}",
            f"  Accessible tools ({len(self.accessible_tools)}): {', '.join(self.accessible_tools) or '-'}",
            f"  FI: {self.baseline_fi:.4f} -> {self.remaining_fi:.4f} after isolation",
            (f"  Fragmented after isolation: {self.system_fragmented} "
            f"({len(self.components_after)} component(s))"),
            f"  Recommendation: {self.isolation_recommendation}",
        ]
        return "\n".join(lines)


class BlastRadiusAnalyzer:
    """Usage::

        report = BlastRadiusAnalyzer(graph).analyze("tool:Bash")
        report.direct_impact      # ["claude", "agent:a3e..."]
        report.system_fragmented  # False
    """

    def __init__(self, graph: AgentGraph, hops: int = 3):
        if hops < 1:
            raise ValueError("hops must be at least 1")
        self.graph = graph
        self.hops = hops
        self._structure: FIStructure | None = None
        self._components_before: int | None = None

    def analyze(self, compromised_node: str) -> BlastReport:
        """What happens if this node is compromised?"""
        node = self.graph.resolve(compromised_node)
        direct = sorted(self._get_neighbors(node))
        by_hop = self._get_n_hop(node, n=self.hops)
        reachable = sorted(set().union(*by_hop.values())) if by_hop else []
        tools = self._reachable_tools(node)

        # One triangle structure serves every node: FI without a node is a local
        # computation, and components are counted without copying the graph.
        if self._structure is None:
            self._structure = FIStructure(self.graph)
            self._components_before = len(self.graph.connected_components())
        remaining_fi = self._structure.fi_without(node)
        before = self._components_before
        after = self.graph.connected_components(without=node)
        # More pieces than the system had before (an already-split system is
        # not "fragmented" by this node).
        fragmented = len(after) > before

        return BlastReport(
            compromised=node,
            direct_impact=direct,
            total_reachable=reachable,
            accessible_tools=tools,
            remaining_fi=remaining_fi,
            system_fragmented=fragmented,
            isolation_recommendation=self._recommend(node, fragmented, after, tools),
            hops=self.hops,
            baseline_fi=self._structure.fi,
            components_after=[sorted(c) for c in after],
            reach_by_hop={k: sorted(v) for k, v in by_hop.items()},
        )

    def analyze_all(self) -> dict[str, BlastReport]:
        return {nid: self.analyze(nid) for nid in sorted(self.graph.nodes)}

    # ------------------------------------------------------------ internals
    def _get_neighbors(self, node: str) -> set[str]:
        return self.graph.neighbors(node)

    def _get_n_hop(self, node: str, n: int) -> dict[int, set[str]]:
        """Nodes first reached at each hop distance 1..n (BFS, undirected)."""
        seen, frontier, out = {node}, {node}, {}
        for hop in range(1, n + 1):
            nxt = set().union(*(self.graph.neighbors(v) for v in frontier)) - seen if frontier else set()
            if not nxt:
                break
            out[hop] = nxt
            seen |= nxt
            frontier = nxt
        return out

    def _reachable_tools(self, node: str) -> list[str]:
        """Tools ``node`` can reach by invoking (transitively, along call direction)."""
        seen, stack = {node}, [node]
        while stack:
            for w in self.graph.successors(stack.pop()):
                if w not in seen:
                    seen.add(w)
                    stack.append(w)
        return sorted(w for w in seen if w != node and self.graph.nodes[w].kind == "tool")

    def _recommend(self, node: str, fragmented: bool, after: list[set[str]], tools: list[str]) -> str:
        kind = self.graph.nodes[node].kind
        if fragmented:
            stranded = sum(len(c) for c in after) - max((len(c) for c in after), default=0)
            return (f"Single point of failure: isolating {node} strands {stranded} node(s) in "
                    f"{len(after) - 1} detached group(s). Add a redundant path (a second caller or "
                    f"a fallback agent) before relying on isolation as a containment strategy.")
        if kind in ("orchestrator", "agent") and tools:
            return (f"Isolation is structurally safe, but {node} can invoke {len(tools)} tool(s); "
                    f"restrict its tool set to what its task needs.")
        return f"Isolation is structurally safe: {node} can be cut off without splitting the system."
