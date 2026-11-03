# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
import json

import pytest
from test_cursor_parser import RECORD_1, RECORD_2

from agent_certify import AutoParser, BaselineLearner
from agent_certify.cli import main
from agent_certify.parser.auto import CLAUDE, CREWAI, CURSOR, LANGGRAPH, MCP_LOG, detect_format


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


# ------------------------------------------- CrewAI and LangGraph (v0.6.1)
@pytest.fixture
def every_format(mixed):
    """The mixed project folder, plus a CrewAI log and a LangGraph trace."""
    from test_crewai_parser import RUN
    from test_langgraph_parser import EVENTS

    (mixed / "crew-run.json").write_text(json.dumps(RUN), encoding="utf-8")
    (mixed / "lg-trace.jsonl").write_text("\n".join(json.dumps(r) for r in EVENTS) + "\n", encoding="utf-8")
    (mixed / "package.json").write_text(json.dumps({"name": "not-a-log"}), encoding="utf-8")
    return mixed


def test_detect_crewai_and_langgraph(every_format):
    assert detect_format(every_format / "crew-run.json") == CREWAI
    assert detect_format(every_format / "lg-trace.jsonl") == LANGGRAPH
    assert detect_format(every_format / "package.json") == CLAUDE      # a dict, but nothing claims it
    assert detect_format(every_format / "sess-1.jsonl") == CLAUDE      # unchanged by the new probes


def test_json_suffix_is_accepted_and_other_suffixes_are_not(tmp_path):
    notes = tmp_path / "notes.yaml"
    notes.write_text("a: 1")
    with pytest.raises(ValueError, match="expected .jsonl, .json or .agent-trace"):
        detect_format(notes)


def test_pretty_printed_jsonl_falls_back_to_a_document_read(tmp_path):
    """A .jsonl file that is really one indented JSON array is still detected."""
    from test_langgraph_parser import DEBUG

    f = tmp_path / "trace.jsonl"
    f.write_text(json.dumps(DEBUG, indent=2), encoding="utf-8")
    assert detect_format(f) == LANGGRAPH
    assert AutoParser().parse(str(f)).has_data


def test_parse_routes_the_new_formats(every_format):
    auto = AutoParser()
    crew = auto.parse(str(every_format / "crew-run.json"))
    assert auto.last_format == CREWAI and "agent:Researcher" in crew.nodes
    lg = auto.parse(str(every_format / "lg-trace.jsonl"))
    assert auto.last_format == LANGGRAPH and "agent:tools" in lg.nodes


def test_directory_scan_picks_up_every_format(every_format):
    graphs = AutoParser().parse_directory(str(every_format))
    sources = sorted(
        "crewai" if "crew" in g.nodes else
        "langgraph" if "graph" in g.nodes else
        "cursor" if "cursor" in g.nodes else "claude"
        for g in graphs)
    # sess-1, the crew log, the LangGraph trace, the .agent-trace dir and the exported trace.
    assert sources == ["claude", "crewai", "cursor", "cursor", "langgraph"]
    assert not any(g.session_id == "package" for g in graphs)          # package.json holds no session
    merged = AutoParser().parse(str(every_format))
    assert {"claude", "crew", "graph", "cursor"} <= set(merged.nodes)


def test_learn_across_frameworks(every_format):
    baseline = BaselineLearner().learn([str(every_format)])
    assert baseline.learned_from == 5
    assert {"Bash", "search_web", "search"} <= baseline.known_tools    # Claude Code, CrewAI, LangGraph
