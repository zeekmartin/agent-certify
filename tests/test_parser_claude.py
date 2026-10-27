# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
import json

from agent_certify import AgentFIScanner, ClaudeCodeParser


def test_parse_session_with_subagent(session_dir):
    parser = ClaudeCodeParser()
    g = parser.parse(str(session_dir / "sess-1.jsonl"))

    assert set(g.nodes) == {"human", "claude", "tool:Bash", "tool:Read", "tool:Grep", "agent:sub1"}
    assert g.nodes["tool:Bash"].call_count == 3          # 2 from claude, 1 from the sub-agent
    assert g.nodes["tool:Bash"].error_count == 1
    assert g.nodes["tool:Read"].call_count == 1          # re-streamed block counted once
    assert g.nodes["agent:sub1"].kind == "agent"
    assert g.nodes["agent:sub1"].metadata["agentType"] == "Explore"
    assert g.total_tool_calls == 6
    assert parser.skipped_lines == 1
    assert g.duration_seconds == 30 * 60

    edges = {(e.source, e.target): e for e in g.edges}
    assert set(edges) == {
        ("human", "claude"), ("claude", "tool:Bash"), ("claude", "tool:Read"), ("claude", "agent:sub1"),
        ("agent:sub1", "tool:Bash"), ("agent:sub1", "tool:Grep"),
    }
    assert edges[("claude", "tool:Bash")].weight == 2
    assert edges[("claude", "tool:Bash")].errors == 1
    assert edges[("agent:sub1", "tool:Bash")].weight == 1


def test_shared_tool_creates_triangle(session_dir):
    g = ClaudeCodeParser().parse(str(session_dir / "sess-1.jsonl"))
    r = AgentFIScanner(g).scan()
    # claude - sub1 - Bash is the only triangle: 3 of 6 links are supported.
    assert r.edge_count == 6
    assert r.fi == 0.5
    assert {b.key for b in r.bridges} == {
        frozenset(("human", "claude")), frozenset(("claude", "tool:Read")), frozenset(("agent:sub1", "tool:Grep"))}


def test_without_subagents(session_dir):
    g = ClaudeCodeParser(include_subagents=False).parse(str(session_dir / "sess-1.jsonl"))
    assert "tool:Grep" not in g.nodes
    assert g.nodes["agent:sub1"].call_count == 1        # still linked via meta.json


def test_empty_and_toolless_files(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    g = ClaudeCodeParser().parse(str(empty))
    assert list(g.nodes) == ["claude"] and g.edges == []

    chat = tmp_path / "chat.jsonl"
    chat.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": "hi"}}) + "\n"
                    + json.dumps({"type": "assistant", "message": {"role": "assistant",
                                                                   "content": [{"type": "text", "text": "hello"}]}}))
    g = ClaudeCodeParser().parse(str(chat))
    assert set(g.nodes) == {"claude", "human"}
    assert g.total_tool_calls == 0 and g.total_messages == 2


def test_task_management_tools_are_not_spawns(tmp_path):
    f = tmp_path / "s.jsonl"
    f.write_text(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "a", "name": "TaskStop", "input": {"task_id": "x"}},
        {"type": "tool_use", "id": "b", "name": "Task", "input": {"prompt": "do"}},
    ]}}))
    g = ClaudeCodeParser().parse(str(f))
    assert g.nodes["tool:TaskStop"].kind == "tool"
    assert g.nodes["agent:b"].kind == "agent"


def test_parse_directory_skips_subagent_files(session_dir):
    graphs = ClaudeCodeParser().parse_directory(str(session_dir))
    assert [g.session_id for g in graphs] == ["sess-1"]
    # Given the parent of project folders, it descends one level.
    graphs = ClaudeCodeParser().parse_directory(str(session_dir.parent))
    assert [g.session_id for g in graphs] == ["sess-1"]
