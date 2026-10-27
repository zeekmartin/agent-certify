# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
import json

import pytest
from test_cursor_parser import RECORD_1, RECORD_2

from agent_certify import AutoParser, BaselineLearner
from agent_certify.cli import main
from agent_certify.parser.auto import CLAUDE, CURSOR, MCP_LOG, detect_format


@pytest.fixture
def mixed(session_dir):
    """A Claude Code project folder that also holds Cursor traces and an MCP log."""
    trace_dir = session_dir / ".agent-trace"
    trace_dir.mkdir()
    (trace_dir / "traces.jsonl").write_text(json.dumps(RECORD_1) + "\n")
    (session_dir / "exported.agent-trace").write_text(json.dumps(RECORD_2))
    (session_dir / "mcp.jsonl").write_text(json.dumps(
        {"debug": "Calling MCP tool: getDiagnostics", "timestamp": "t", "sessionId": "s", "cwd": "/x"}) + "\n")
    return session_dir


def test_detect_by_content(mixed, tmp_path):
    assert detect_format(mixed / "sess-1.jsonl") == CLAUDE
    assert detect_format(mixed / ".agent-trace" / "traces.jsonl") == CURSOR      # .jsonl, but a trace
    assert detect_format(mixed / "exported.agent-trace") == CURSOR
    assert detect_format(mixed / ".agent-trace") == CURSOR
    assert detect_format(mixed / "mcp.jsonl") == MCP_LOG
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert detect_format(empty) == CLAUDE                                       # v0.1 behaviour kept


def test_unknown_format(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    with pytest.raises(ValueError, match="Unknown format"):
        AutoParser().parse(str(f))
    with pytest.raises(ValueError, match="directory"):
        detect_format(tmp_path)


def test_parse_routes_files(mixed):
    auto = AutoParser()
    claude = auto.parse(str(mixed / "sess-1.jsonl"))
    assert auto.last_format == CLAUDE and "agent:sub1" in claude.nodes
    cursor = auto.parse(str(mixed / ".agent-trace" / "traces.jsonl"))
    assert auto.last_format == CURSOR and "file:src/app.py" in cursor.nodes
    mcp = auto.parse(str(mixed / "mcp.jsonl"))
    # Outside an mcp-logs-<server> folder the server name is unknown.
    assert auto.last_format == MCP_LOG and "tool:mcp__unknown__getDiagnostics" in mcp.nodes


def test_directory_with_mixed_files(mixed):
    graphs = AutoParser().parse_directory(str(mixed))
    kinds = sorted("cursor" if "cursor" in g.nodes else "claude" for g in graphs)
    # sess-1 (with its sub-agent read inside it), the .agent-trace dir and the exported trace; no MCP log.
    assert kinds == ["claude", "cursor", "cursor"]
    assert not any(g.session_id == "agent-sub1" for g in graphs)
    merged = AutoParser().parse(str(mixed))
    assert {"claude", "cursor", "file:src/app.py", "tool:Bash"} <= set(merged.nodes)


def test_claude_only_directory_unchanged(session_dir):
    graphs = AutoParser().parse_directory(str(session_dir.parent))               # projects root: one level down
    assert [g.session_id for g in graphs] == ["sess-1"]


def test_cli_and_learn_auto_detect(mixed, capsys):
    assert main(["scan", str(mixed / ".agent-trace"), "--no-baseline", "--no-policy"]) == 0
    out = capsys.readouterr().out
    assert "file:src/app.py" in out and "Fragility Index  1.0000" in out
    baseline = BaselineLearner().learn([str(mixed)])
    assert baseline.learned_from == 3
    assert ("cursor", "agent:claude-sonnet") in baseline.known_links
