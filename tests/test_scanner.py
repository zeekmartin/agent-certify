# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
import numpy as np
import pytest
from conftest import star

from agent_certify import AgentFIScanner, AgentGraph, compute_fi
from agent_certify.scanner import articulation_points, find_bridges


def _graph(edges, kinds=None):
    g = AgentGraph()
    for a, b in edges:
        for n in (a, b):
            g.add_node(n, (kinds or {}).get(n, "agent"))
        g.add_call(a, b)
    return g


def test_star_is_fully_fragile(star_graph):
    r = AgentFIScanner(star_graph).scan()
    assert r.fi == 1.0
    assert len(r.bridges) == 4
    assert r.edge_count == 4
    assert r.node_classifications["claude"] == "CRITICAL"
    assert all(r.node_classifications[f"tool:t{i}"] == "IMMUNE" for i in range(4))


def test_triangle_is_fully_redundant():
    g = _graph([("a", "b"), ("b", "c"), ("c", "a")])
    r = AgentFIScanner(g).scan()
    assert r.fi == 0.0
    assert r.bridges == []
    assert all(e.tri_count == 1 for e in g.edges)


def test_triangle_with_tail():
    # a-b-c triangle plus c-d: 1 of 4 links unsupported.
    g = _graph([("a", "b"), ("b", "c"), ("c", "a"), ("c", "d")])
    r = AgentFIScanner(g).scan()
    assert r.fi == pytest.approx(0.25)
    assert [b.key for b in r.bridges] == [frozenset(("c", "d"))]
    assert r.articulation_points == ["c"]
    assert r.node_classifications["c"] == "CRITICAL"
    # Removing d leaves a pure triangle: FI 0.25 -> 0. Removal makes the
    # system *less* fragile, so d is not critical.
    assert r.node_classifications["d"] == "IMMUNE"
    assert r.fi_deltas["d"] == pytest.approx(-0.25, abs=1e-6)


def test_removal_that_raises_fi_is_critical():
    # Triangles a-b-c and b-c-d share edge b-c; leaf e hangs off a. Only a-e is
    # unsupported: FI = 1/6. Removing d breaks triangle b-c-d, leaving
    # a-b, b-c, c-a, a-e with one unsupported link: FI = 1/4, a 50% rise.
    g = _graph([("a", "b"), ("b", "c"), ("c", "a"), ("b", "d"), ("d", "c"), ("a", "e")])
    r = AgentFIScanner(g).scan()
    assert r.fi == pytest.approx(1 / 6)
    assert r.fi_deltas["d"] == pytest.approx(1 / 4 - 1 / 6, abs=1e-6)
    assert r.node_classifications["d"] == "CRITICAL"
    assert r.node_classifications["e"] == "IMMUNE"      # removal lowers FI
    assert r.node_classifications["a"] == "CRITICAL"    # articulation point for e


def test_direction_is_ignored():
    g = _graph([("a", "b"), ("b", "a"), ("b", "c"), ("a", "c")])
    assert AgentFIScanner(g).scan().edge_count == 3
    assert AgentFIScanner(g).scan().fi == 0.0


def test_fragile_but_not_bridge():
    # 4-cycle: no triangles (FI 1) but no bridges either.
    g = _graph([("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")])
    r = AgentFIScanner(g).scan()
    assert r.fi == 1.0 and r.bridges == []
    assert articulation_points(g) == set()


def test_compute_fi_matches_sal_torch_semantics():
    rng = np.random.default_rng(0)
    A = (rng.random((12, 12)) < 0.3).astype(int)
    A = np.triu(A, 1)
    A = A + A.T
    common = A @ A
    edges = [(i, j) for i in range(12) for j in range(i + 1, 12) if A[i, j]]
    expected = sum(common[i, j] == 0 for i, j in edges) / len(edges)
    assert compute_fi(A) == pytest.approx(expected)


def test_empty_and_single_node():
    g = AgentGraph()
    g.add_node("claude", "orchestrator")
    r = AgentFIScanner(g).scan()
    assert r.fi == 0.0 and r.edge_count == 0 and r.node_classifications == {"claude": "IMMUNE"}


def test_bridges_on_long_path_no_recursion_limit():
    g = _graph([(f"n{i}", f"n{i + 1}") for i in range(3000)])
    assert len(find_bridges(g)) == 3000


def test_star_sizes():
    for k in (1, 2, 7):
        assert AgentFIScanner(star(k)).scan().fi == 1.0
