# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from agent_certify import AgentFIScanner, BlastRadiusAnalyzer, CursorTraceParser, Policy, PolicyRule

RECORD_1 = {
    "version": "1.0", "id": "3f2a1c9e-0000-4000-8000-000000000001", "timestamp": "2026-10-20T09:00:00Z",
    "vcs": {"type": "git", "revision": "a1b2c3d"},
    "tool": {"name": "cursor", "version": "2.1.0"},
    "files": [
        {"path": "src/app.py", "conversations": [{
            "url": "https://cursor.com/c/abc",
            "contributor": {"type": "ai", "model_id": "claude-sonnet"},
            "ranges": [{"start_line": 1, "end_line": 40},
                       {"start_line": 41, "end_line": 49, "contributor": {"type": "human"}},
                       {"start_line": 50, "end_line": 60}]}]},
        {"path": "docs/README.md", "conversations": [{
            "contributor": {"type": "human"}, "ranges": [{"start_line": 1, "end_line": 5}]}]},
    ],
}
RECORD_2 = {
    "version": "1.0", "id": "3f2a1c9e-0000-4000-8000-000000000002", "timestamp": "2026-10-21T15:30:00Z",
    "tool": {"name": "cursor", "version": "2.1.0"},
    "files": [{"path": "src/app.py", "conversations": [
        {"contributor": {"type": "ai", "model_id": "gpt-5"}, "ranges": [{"start_line": 70, "end_line": 79}]},
        {"ranges": []},                                       # no contributor, no ranges
    ]}],
}


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "my-repo" / ".agent-trace"
    d.mkdir(parents=True)
    (d / "traces.jsonl").write_text(json.dumps(RECORD_1) + "\n" + json.dumps(RECORD_2) + "\n")
    return tmp_path / "my-repo"


def test_parse_nodes_and_edges(repo):
    g = CursorTraceParser().parse(str(repo / ".agent-trace" / "traces.jsonl"))
    assert set(g.nodes) == {"cursor", "agent:claude-sonnet", "agent:gpt-5", "agent:unknown", "human",
                            "file:src/app.py", "file:docs/README.md"}
    assert g.nodes["cursor"].kind == "orchestrator" and g.nodes["cursor"].metadata["version"] == "2.1.0"
    assert g.nodes["agent:claude-sonnet"].metadata["agentType"] == "claude-sonnet"
    assert g.nodes["file:src/app.py"].kind == "file"
    w = {(e.source, e.target): e.weight for e in g.edges}
    assert w[("agent:claude-sonnet", "file:src/app.py")] == 40 + 11               # lines written
    assert w[("human", "file:src/app.py")] == 9                                  # range-level override
    assert w[("human", "file:docs/README.md")] == 5
    assert w[("agent:gpt-5", "file:src/app.py")] == 10
    assert w[("agent:unknown", "file:src/app.py")] == 1                          # touched, no ranges
    assert {e.source for e in g.edges if e.target.startswith("agent:")} == {"cursor"}
    assert g.project == "my-repo"
    assert g.started_at == "2026-10-20T09:00:00Z" and g.ended_at == "2026-10-21T15:30:00Z"
    assert g.total_messages == 2 and g.total_tool_calls == 5                     # 2 records, 5 ranges


def test_provenance_graph_is_bipartite_so_fi_is_one(repo):
    g = CursorTraceParser().parse(str(repo))
    r = AgentFIScanner(g).scan()
    assert r.fi == 1.0 and len(r.fragile_edges) == r.edge_count
    # The useful views: who touched what, and rules about it.
    blast = BlastRadiusAnalyzer(g).analyze("agent:claude-sonnet")
    assert blast.direct_impact == ["cursor", "file:src/app.py"]
    rule = PolicyRule("forbidden_link", "agent:* → file:src/*", "warning", "AI may not write under src/")
    assert len(Policy([rule]).check(g)) == 3                    # claude-sonnet, gpt-5, unknown


def test_input_forms(tmp_path, repo):
    single = tmp_path / "one.agent-trace"
    single.write_text(json.dumps(RECORD_1))                     # one JSON object
    listed = tmp_path / "many.agent-trace"
    listed.write_text(json.dumps([RECORD_1, RECORD_2]))         # a JSON array
    p = CursorTraceParser()
    assert p.parse(str(single)).session_id == RECORD_1["id"]
    assert "agent:gpt-5" in p.parse(str(listed)).nodes
    for form in (repo, repo / ".agent-trace", repo / ".agent-trace" / "traces.jsonl"):
        assert "agent:gpt-5" in p.parse(str(form)).nodes, form


def test_missing_and_malformed_fields(tmp_path):
    f = tmp_path / "messy.agent-trace"
    f.write_text("\n".join([
        json.dumps({"version": "1.0", "id": "x"}),                               # no files: skipped
        "{not json",                                                              # skipped
        json.dumps({"version": "1.0", "id": "y", "timestamp": "2026-10-22T00:00:00Z", "files": [
            {"conversations": []},                                                # no path: skipped
            {"path": "a.py"},                                                     # no conversations
            {"path": "b.py", "conversations": ["oops", {"contributor": {"type": "robot"},
                                                       "ranges": [{"start_line": 3}, "bad"]}]},
        ]}),
    ]))
    parser = CursorTraceParser()
    g = parser.parse(str(f))
    assert set(g.nodes) == {"agent-trace", "file:a.py", "file:b.py", "agent:unknown"}
    assert g.nodes["agent-trace"].kind == "orchestrator"                         # no tool block
    assert {(e.source, e.target): e.weight for e in g.edges}[("agent:unknown", "file:b.py")] == 1
    assert parser.skipped == 5


def test_empty_and_missing(tmp_path):
    empty = tmp_path / "empty.agent-trace"
    empty.write_text("")
    g = CursorTraceParser().parse(str(empty))
    assert list(g.nodes) == ["agent-trace"] and g.edges == []
    with pytest.raises(FileNotFoundError):
        CursorTraceParser().parse(str(tmp_path / "nothing.agent-trace"))


def test_find_traces_skips_vendored_dirs(tmp_path, repo):
    (repo / "node_modules" / "pkg" / ".agent-trace").mkdir(parents=True)
    (repo / "sub").mkdir()
    (repo / "sub" / "x.agent-trace").write_text(json.dumps(RECORD_1))
    found = CursorTraceParser().find_traces(str(repo))
    assert [p.relative_to(repo).as_posix() for p in found] == [".agent-trace", "sub/x.agent-trace"]
