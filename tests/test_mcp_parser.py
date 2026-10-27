import json

import pytest

from agent_certify import ClaudeCodeParser, MCPLogsParser
from agent_certify.cli import main
from agent_certify.parser import mcp_logs
from agent_certify.parser.mcp_logs import project_key


def _log(path, session, messages, ts="2026-10-27T10:00:00.000Z"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.writelines(json.dumps({kind: text, "timestamp": ts, "sessionId": session, "cwd": "/home/me/proj"}) + "\n" for kind, text in messages)


def _call(tool):
    return ("debug", f"Calling MCP tool: {tool}")


def _ok(tool):
    return ("debug", f"Tool '{tool}' completed successfully in 12ms")


def _fail(tool):
    return ("debug", f"Tool '{tool}' failed after 0s: Not connected")


@pytest.fixture
def cache(tmp_path, session_dir):
    """Synthetic claude-cli-nodejs cache for the session_dir project (-home-me-proj / sess-1)."""
    root = tmp_path / "cache"
    proj = root / session_dir.name
    _log(proj / "mcp-logs-ide" / "2026-10-27T10-00-00-000Z.jsonl", "sess-1", [
        ("debug", "Starting connection with timeout of 30000ms"),
        _call("getDiagnostics"), _ok("getDiagnostics"),
        _call("getDiagnostics"), _fail("getDiagnostics"),
        _call("getDiagnostics"), _ok("getDiagnostics"),
        _call("openDiff"),
    ])
    _log(proj / "mcp-logs-ide" / "2026-10-27T11-00-00-000Z.jsonl", "another-session", [_call("getDiagnostics")] * 5)
    _log(proj / "mcp-logs-claude-ai-Gmail" / "2026-10-27T10-00-00-000Z.jsonl", "sess-1", [
        ("debug", "claude.ai proxy transport created successfully"), ("error", "Authentication required")])
    (proj / "mcp-logs-ide" / "2026-10-27T10-00-00-000Z.jsonl").open("a").write("{broken\n")
    _log(root / "other-project" / "mcp-logs-ide" / "x.jsonl", "sess-9", [_call("close_tab")])
    return root


def test_find_logs(cache):
    mcp = MCPLogsParser(roots=[cache])
    assert len(mcp.find_logs()) == 4
    assert len(mcp.find_logs("-home-me-proj")) == 3
    assert mcp.find_logs("no-such-project") == []
    assert MCPLogsParser(roots=[cache / "missing"]).find_logs() == []


def test_project_key():
    assert project_key(r"H:\agent-certify") == "H--agent-certify"
    assert project_key("/home/me/proj") == "-home-me-proj"
    assert project_key("C--dev-topostability") == "C--dev-topostability"


def test_parse_single_log(cache):
    mcp = MCPLogsParser(roots=[cache])
    g = mcp.parse(str(cache / "-home-me-proj" / "mcp-logs-ide" / "2026-10-27T10-00-00-000Z.jsonl"))
    assert set(g.nodes) == {"claude", "tool:mcp__ide__getDiagnostics", "tool:mcp__ide__openDiff"}
    diag = g.nodes["tool:mcp__ide__getDiagnostics"]
    assert diag.call_count == 3 and diag.error_count == 1
    assert diag.metadata["mcp_server"] == "ide"
    assert g.total_tool_calls == 4
    assert g.session_id == "sess-1"
    assert mcp.skipped_lines == 1


def test_log_without_tool_calls(cache):
    g = MCPLogsParser().parse(str(cache / "-home-me-proj" / "mcp-logs-claude-ai-Gmail" /
                                  "2026-10-27T10-00-00-000Z.jsonl"))
    assert list(g.nodes) == ["claude"] and g.edges == []


def test_enrich_adds_session_calls_only(cache, session_dir):
    graph = ClaudeCodeParser().parse(str(session_dir / "sess-1.jsonl"))
    mcp = MCPLogsParser(roots=[cache])
    enriched = mcp.enrich(graph)
    assert mcp.added_calls == 4                               # 3 + 1 from sess-1; another-session ignored
    assert enriched.nodes["tool:mcp__ide__getDiagnostics"].call_count == 3
    assert enriched.nodes["tool:mcp__ide__getDiagnostics"].error_count == 1
    assert [n for n in enriched.nodes if n == "claude"] == ["claude"]       # orchestrator shared
    assert enriched.total_tool_calls == graph.total_tool_calls + 4
    assert set(graph.nodes) < set(enriched.nodes)
    assert "tool:mcp__ide__openDiff" not in graph.nodes                     # original untouched


def test_enrich_does_not_double_count_transcript_calls(tmp_path):
    # The transcript already shows 1 Gmail search; the server log shows 2 calls.
    proj = tmp_path / "projects" / "-p"
    proj.mkdir(parents=True)
    (proj / "s1.jsonl").write_text(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "mcp__claude_ai_Gmail__search", "input": {}}]}}) + "\n")
    root = tmp_path / "cache"
    _log(root / "-p" / "mcp-logs-claude-ai-Gmail" / "x.jsonl", "s1", [_call("search"), _call("search")])
    graph = ClaudeCodeParser().parse(str(proj / "s1.jsonl"))
    mcp = MCPLogsParser(roots=[root])
    enriched = mcp.enrich(graph)
    tools = [n for n in enriched.nodes if n.startswith("tool:")]
    assert tools == ["tool:mcp__claude_ai_Gmail__search"]     # matched despite claude-ai vs claude_ai spelling
    assert enriched.nodes[tools[0]].call_count == 2 and mcp.added_calls == 1


def test_enrich_with_no_logs(session_dir, tmp_path):
    graph = ClaudeCodeParser().parse(str(session_dir / "sess-1.jsonl"))
    mcp = MCPLogsParser(roots=[tmp_path / "nothing-here"])
    enriched = mcp.enrich(graph)
    assert mcp.added_calls == 0
    assert set(enriched.nodes) == set(graph.nodes)


def test_enrich_from_explicit_dir(cache, session_dir):
    graph = ClaudeCodeParser().parse(str(session_dir / "sess-1.jsonl"))
    enriched = MCPLogsParser(roots=[]).enrich(graph, str(cache / "-home-me-proj"))
    assert "tool:mcp__ide__openDiff" in enriched.nodes


def test_cli_include_mcp(cache, session_dir, monkeypatch, capsys):
    monkeypatch.setattr(mcp_logs, "default_roots", lambda: [cache])
    session = str(session_dir / "sess-1.jsonl")
    assert main(["scan", session, "--include-mcp", "--no-baseline"]) == 0
    captured = capsys.readouterr()
    assert "tool:mcp__ide__getDiagnostics" in captured.out
    assert "MCP logs: 4 call(s) added" in captured.err
    assert main(["scan", session, "--no-baseline"]) == 0
    assert "mcp__ide" not in capsys.readouterr().out


def test_cli_learn_include_mcp_makes_mcp_tools_known(cache, session_dir, monkeypatch, capsys):
    monkeypatch.setattr(mcp_logs, "default_roots", lambda: [cache])
    session = str(session_dir / "sess-1.jsonl")
    assert main(["learn", session]) == 0                      # transcript-only baseline
    assert main(["scan", session, "--include-mcp"]) == 0
    assert "New tool never seen: mcp__ide__getDiagnostics" in capsys.readouterr().out

    assert main(["learn", session, "--include-mcp"]) == 0     # same data sources on both sides
    capsys.readouterr()
    assert main(["scan", session, "--include-mcp"]) == 0
    assert "No anomalies" in capsys.readouterr().out
