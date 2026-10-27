import json

import pytest

from agent_certify.graph import AgentGraph


def star(n_tools: int = 4) -> AgentGraph:
    """1 orchestrator -> n tools, no cross-links."""
    g = AgentGraph(session_id="star")
    g.add_node("claude", "orchestrator")
    for i in range(n_tools):
        g.add_node(f"tool:t{i}", "tool", f"t{i}")
        g.add_call("claude", f"tool:t{i}")
    return g


@pytest.fixture
def star_graph():
    return star()


def _assistant(tool_uses, ts="2026-10-01T10:00:00Z", **extra):
    content = [{"type": "tool_use", "id": i, "name": n, "input": inp} for i, n, inp in tool_uses]
    return {"type": "assistant", "timestamp": ts, "message": {"role": "assistant", "content": content}, **extra}


def _results(pairs, ts="2026-10-01T10:00:05Z"):
    content = [{"type": "tool_result", "tool_use_id": i, "content": "ok", "is_error": err} for i, err in pairs]
    return {"type": "user", "timestamp": ts, "message": {"role": "user", "content": content}}


def _prompt(text, ts="2026-10-01T10:00:00Z"):
    return {"type": "user", "timestamp": ts, "message": {"role": "user", "content": text}}


@pytest.fixture
def session_dir(tmp_path):
    """A synthetic Claude Code project with one session and one sub-agent.

    Main: human prompt; Bash x2 (one error), Read x1, Agent spawn (sub-1);
    a re-streamed duplicate of the Read block; one malformed line.
    Sub-agent sub-1: Bash x1, Grep x1.
    """
    proj = tmp_path / "-home-me-proj"
    proj.mkdir()
    sid = "sess-1"
    main = [
        _prompt("please fix the bug", ts="2026-10-01T10:00:00Z"),
        _assistant([("t1", "Bash", {"command": "ls"}), ("t2", "Read", {"file_path": "x"})]),
        _assistant([("t2", "Read", {"file_path": "x"})]),       # same block re-streamed
        _results([("t1", False), ("t2", False)]),
        _assistant([("t3", "Bash", {"command": "false"})]),
        _results([("t3", True)]),
        _assistant([("t4", "Agent", {"description": "search", "subagent_type": "Explore", "prompt": "find"})]),
        _results([("t4", False)], ts="2026-10-01T10:30:00Z"),
        {"type": "file-history-snapshot", "snapshot": {}},
    ]
    lines = [json.dumps(r) for r in main]
    lines.insert(3, "{not json")
    (proj / f"{sid}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    sub = proj / sid / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-sub1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "search", "toolUseId": "t4", "spawnDepth": 1}))
    sub_lines = [
        {"type": "user", "isSidechain": True, "agentId": "sub1", "message": {"role": "user", "content": "find"}},
        _assistant([("s1", "Bash", {"command": "grep"}), ("s2", "Grep", {"pattern": "x"})], isSidechain=True),
        _results([("s1", False), ("s2", False)]),
    ]
    (sub / "agent-sub1.jsonl").write_text("\n".join(json.dumps(r) for r in sub_lines) + "\n", encoding="utf-8")
    return proj
