# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""Hostile inputs and performance (audit SEC-006, SEC-007, SEC-009, PRF-001..003, PRV-002, TST-003, FUN-005)."""
import json
import os
import random
import time
from pathlib import Path

import pytest
from conftest import _assistant, session_graph

from agent_certify import (
    AgentFIScanner,
    AgentGraph,
    AutoParser,
    Baseline,
    BaselineLearner,
    BlastRadiusAnalyzer,
    ClaudeCodeParser,
    CursorTraceParser,
    OTelExporter,
    SessionWatcher,
    compute_fi,
    load_baseline,
)
from agent_certify.parser.base import session_files
from agent_certify.paths import PathNotAllowed, confine, ensure_state_dir, iter_lines, walk
from agent_certify.scanner import FIStructure, articulation_points
from agent_certify.viz import render_html, script_json


# ------------------------------------------------------------------- paths
def test_confine(tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    assert confine(str(root / "a" / "f.jsonl"), [root]) == (root / "a" / "f.jsonl").resolve()
    assert confine("a/f.jsonl", [root], base=root) == (root / "a" / "f.jsonl").resolve()
    for bad in (str(tmp_path), str(root / ".." / "x"), "../x", "", "a\x00b"):
        with pytest.raises(PathNotAllowed) as exc:
            confine(bad, [root], base=root)
        assert str(exc.value) == "Path not allowed"


def test_confine_never_expands_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AC_TEST_DIR", str(tmp_path / "elsewhere"))
    root = tmp_path / "root"
    root.mkdir()
    p = confine("$AC_TEST_DIR/x", [root], base=root)            # stays a literal name under the root
    assert p == (root / "$AC_TEST_DIR" / "x").resolve()


def test_iter_lines_skips_oversized_lines(tmp_path):
    f = tmp_path / "x.jsonl"
    f.write_bytes(b'{"a": 1}\n' + b"x" * 5000 + b"\n" + b'{"b": 2}\n' + b"\xff\xfe broken utf8\n")
    lines = list(iter_lines(f, max_line=1000))
    assert [n for n, _ in lines] == [1, 2, 3, 4]
    assert lines[1][1] is None                                  # oversized: reported, not loaded
    assert json.loads(lines[2][1]) == {"b": 2}
    assert "broken utf8" in lines[3][1]                         # bad bytes replaced, not fatal


def test_walk_depth_limit(tmp_path):
    deep = tmp_path.joinpath(*[f"d{i}" for i in range(10)])
    deep.mkdir(parents=True)
    seen = [here for here, _, _ in walk(tmp_path, max_depth=3)]
    assert max(len(p.relative_to(tmp_path).parts) for p in seen) == 3


def test_state_dir_gets_a_gitignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    BaselineLearner().save(BaselineLearner().learn_graphs([session_graph("s", {"Bash": 1})]))
    ignore = Path(".agent-certify/.gitignore")
    assert ignore.read_text().strip().endswith("*")
    ensure_state_dir(Path("elsewhere/file.json"))                # other folders get none
    assert not Path("elsewhere/.gitignore").exists()


# ----------------------------------------------------------------- parsers
def test_deeply_nested_json_is_skipped_not_fatal(tmp_path):
    f = tmp_path / "s.jsonl"
    f.write_text("[" * 100_000 + "\n" + json.dumps(_assistant([("t1", "Bash", {})])) + "\n")
    parser = ClaudeCodeParser()
    g = parser.parse(str(f))
    assert "tool:Bash" in g.nodes and parser.skipped_lines == 1 and g.skipped_records == 1


def test_nan_constants_in_records_are_skipped(tmp_path):
    f = tmp_path / "s.jsonl"
    f.write_text('{"type": "assistant", "x": NaN}\n')
    assert ClaudeCodeParser().parse(str(f)).skipped_records == 1


def test_huge_line_is_skipped(tmp_path):
    f = tmp_path / "s.jsonl"
    with open(f, "w") as out:
        out.write('{"type": "user", "pad": "' + "x" * (11 * 1024 * 1024) + '"}\n')
        out.write(json.dumps(_assistant([("t1", "Read", {})])) + "\n")
    g = ClaudeCodeParser().parse(str(f))
    assert g.skipped_records == 1 and "tool:Read" in g.nodes


def test_directory_scan_survives_a_poisoned_file(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "a.jsonl").write_text("[" * 100_000)
    (proj / "b.jsonl").write_text(json.dumps(_assistant([("t", "Bash", {})])) + "\n")
    graphs = AutoParser().parse_directory(str(proj))
    assert len(graphs) == 2 and any("tool:Bash" in g.nodes for g in graphs)


def test_session_file_limit(tmp_path):
    for i in range(12):
        (tmp_path / f"s{i:02d}.jsonl").write_text("")
        os.utime(tmp_path / f"s{i:02d}.jsonl", (1_000_000 + i, 1_000_000 + i))
    kept = session_files(tmp_path, max_files=5)
    assert [p.stem for p in kept] == ["s07", "s08", "s09", "s10", "s11"]        # newest five


def test_trace_search_depth_limit(tmp_path):
    shallow = tmp_path / "a" / ".agent-trace"
    deep = tmp_path.joinpath(*[f"d{i}" for i in range(8)], ".agent-trace")
    shallow.mkdir(parents=True)
    deep.mkdir(parents=True)
    found = CursorTraceParser().find_traces(str(tmp_path))
    assert shallow in found and deep not in found


def test_cursor_large_jsonl_is_streamed(tmp_path, monkeypatch):
    from agent_certify.parser import cursor_trace
    monkeypatch.setattr(cursor_trace, "MAX_DOCUMENT_BYTES", 10)         # force the streaming path
    rec = {"version": "1.0", "id": "x", "timestamp": "2026-10-01T00:00:00Z", "files": [
        {"path": "a.py", "conversations": [{"contributor": {"type": "ai", "model_id": "m"},
                                            "ranges": [{"start_line": 1, "end_line": 3}]}]}]}
    f = tmp_path / "traces.jsonl"
    f.write_text(json.dumps(rec) + "\n{broken\n")
    g = CursorTraceParser().parse(str(f))
    assert "file:a.py" in g.nodes and g.skipped_records == 1


# ------------------------------------------------------------ deserialization
@pytest.mark.parametrize("payload", [
    ["AKIA-SECRET"],
    {"learned_from": "many"},
    "just a string",
])
def test_baseline_from_dict_is_generic(payload):
    with pytest.raises(ValueError) as exc:
        Baseline.from_dict(payload)
    assert str(exc.value) == "Invalid baseline format" and "AKIA" not in str(exc.value)


def test_baseline_rejects_nan_and_wrong_types(tmp_path):
    good = BaselineLearner().learn_graphs([session_graph("s", {"Bash": 1})]).to_dict()
    p = tmp_path / "b.json"
    p.write_text(json.dumps(good).replace('"fi_mean": 1.0', '"fi_mean": NaN'))
    with pytest.raises(ValueError, match="^Invalid baseline format$"):
        load_baseline(p)
    for key, value in (("known_tools", "Bash"), ("tool_frequency", {"Bash": 3}), ("known_links", [["a"]]),
                       ("learned_from", -1), ("session_ids", [1])):
        bad = dict(good, **{key: value})
        with pytest.raises(ValueError, match="^Invalid baseline format$"):
            Baseline.from_dict(bad)
    assert Baseline.from_dict(good).learned_from == 1


def test_graph_from_dict_validation():
    g = session_graph("s", {"Bash": 2})
    assert AgentGraph.from_dict(g.to_dict()).to_dict() == g.to_dict()
    for mutate in (lambda d: d["nodes"].append({"id": "x", "kind": "robot", "name": "x"}),
                   lambda d: d["edges"].append({"source": "claude", "target": "ghost"}),
                   lambda d: d.__setitem__("total_tool_calls", -3),
                   lambda d: d.__setitem__("duration_seconds", float("nan")),
                   lambda d: d["nodes"].append({"id": "y", "kind": "tool", "name": "y", "evil": 1})):
        data = g.to_dict()
        mutate(data)
        with pytest.raises(ValueError, match="^Invalid graph format$"):
            AgentGraph.from_dict(data)
    with pytest.raises(ValueError):
        AgentGraph.from_dict(["not", "a", "dict"])


# -------------------------------------------------------------------- HTML
def test_script_json_escapes_html_breakers():
    text = script_json({"name": "</script><!--<script>alert(1)&"})
    assert "<" not in text and ">" not in text and "&" not in text
    assert json.loads(text) == {"name": "</script><!--<script>alert(1)&"}


def test_html_report_with_hostile_names():
    g = AgentGraph()
    g.add_node("claude", "orchestrator")
    evil = "tool:</script><!--<script>"
    g.add_node(evil, "tool", "</script><!--<script>x")
    g.add_call("claude", evil)
    page = render_html(g)
    script = page.split("<script>", 1)[1]
    assert script.count("</script>") == 1                       # only the real closing tag
    assert "<!--" not in script


# ------------------------------------------------------------- performance
def _random_graph(rng, n, p):
    g = AgentGraph()
    for i in range(n):
        g.add_node(f"n{i}", "agent")
    for i in range(n):
        for j in range(i + 1, n):
            if rng.random() < p:
                g.add_call(f"n{i}", f"n{j}")
                if rng.random() < 0.1:
                    g.add_call(f"n{j}", f"n{i}")
    return g


def test_incremental_fi_and_tarjan_match_brute_force():
    rng = random.Random(7)
    for _ in range(150):
        g = _random_graph(rng, rng.randint(1, 12), rng.choice([0.15, 0.35, 0.6, 0.9]))
        s = FIStructure(g)
        assert s.fi == compute_fi(g.adjacency_matrix()[1])
        base = len(g.connected_components())
        brute_cut = {n for n in g.nodes
                     if len(g.remove_node(n).connected_components()) > base - (0 if g.neighbors(n) else 1)}
        assert articulation_points(g) == brute_cut
        for node in g.nodes:
            assert s.fi_without(node) == compute_fi(g.remove_node(node).adjacency_matrix()[1])
            assert g.connected_components(without=node) == g.remove_node(node).connected_components()


def test_large_graph_scans_quickly():
    rng = random.Random(1)
    g = AgentGraph()
    for i in range(3000):
        g.add_node(f"f{i}", "file")
    while len(g.edges) < 9000:
        a, b = rng.randrange(3000), rng.randrange(3000)
        if a != b:
            g.add_call(f"f{a}", f"f{b}")
    start = time.perf_counter()
    r = AgentFIScanner(g).scan()
    BlastRadiusAnalyzer(g).analyze(r.critical_nodes[0] if r.critical_nodes else "f0")
    assert time.perf_counter() - start < 10                     # was hours before v0.5 (O(n^4), deep copies)


def test_edge_index_follows_replaced_edge_list():
    g = session_graph("s", {"Bash": 1, "Read": 1})
    assert g.get_edge("claude", "tool:Bash") is not None
    g.edges = [e for e in g.edges if e.target != "tool:Bash"]       # replaced from outside
    assert g.get_edge("claude", "tool:Bash") is None
    assert g.neighbors("claude") == {"tool:Read"}


# ---------------------------------------------------------- watcher / otel
def test_watcher_reads_cursor_traces(tmp_path):
    rec = {"version": "1.0", "id": "x", "timestamp": "2026-10-01T00:00:00Z", "tool": {"name": "cursor"},
           "files": [{"path": "a.py", "conversations": [{"contributor": {"type": "ai", "model_id": "m"},
                                                         "ranges": [{"start_line": 1, "end_line": 2}]}]}]}
    f = tmp_path / "traces.jsonl"
    f.write_text(json.dumps(rec) + "\n")
    lines = []
    w = SessionWatcher(str(f), interval=0.05, out=lines.append)
    assert w.poll() and "file:a.py" in w._last_graph.nodes


def test_otel_reports_skipped_records():
    g = session_graph("s", {"Bash": 1})
    g.skipped_records = 4
    span = OTelExporter().export_scan(g, AgentFIScanner(g).scan())
    assert span.attributes["agent_certify.skipped_records"] == 4
