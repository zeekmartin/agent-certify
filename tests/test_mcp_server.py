# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
import io
import json
import os
import shutil
import subprocess
import sys

import pytest

from agent_certify import AgentCertifyMCPServer, BaselineLearner, Policy, PolicyRule
from agent_certify.mcp_server import ToolError, find_current_session


@pytest.fixture
def server(session_dir):
    """Server whose 'current session' resolves to the synthetic sess-1 (project -home-me-proj)."""
    return AgentCertifyMCPServer(projects_root=session_dir.parent, cwd="/home/me/proj", env={})


def rpc(server, method, params=None, msg_id=1):
    msg = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        msg["params"] = params
    return server.handle(msg)


def call(server, name, **arguments):
    """tools/call -> (payload or error text, isError)."""
    reply = rpc(server, "tools/call", {"name": name, "arguments": arguments})
    result = reply["result"]
    text = result["content"][0]["text"]
    return (text if result.get("isError") else json.loads(text)), bool(result.get("isError"))


# ---------------------------------------------------------------- protocol
def test_initialize(server):
    reply = rpc(server, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "1"}})
    r = reply["result"]
    assert reply["id"] == 1 and reply["jsonrpc"] == "2.0"
    assert r["protocolVersion"] == "2025-03-26"                   # a supported version is echoed
    assert r["serverInfo"]["name"] == "agent-certify"
    assert r["capabilities"]["tools"] == {"listChanged": False}
    assert "topology_summary" in r["instructions"]
    unknown = rpc(server, "initialize", {"protocolVersion": "1999-01-01"})
    assert unknown["result"]["protocolVersion"] == "2025-06-18"   # otherwise our latest


def test_notifications_get_no_reply(server):
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}) is None
    assert server.handle({"jsonrpc": "2.0", "method": "tools/list"}) is None    # any id-less message


def test_tools_list(server):
    tools = {t["name"]: t for t in rpc(server, "tools/list")["result"]["tools"]}
    assert set(tools) == {"scan_topology", "check_anomalies", "blast_radius", "check_policy", "topology_summary"}
    for t in tools.values():
        assert t["description"] and t["inputSchema"]["type"] == "object"
        assert "session_path" in t["inputSchema"]["properties"]
    assert tools["blast_radius"]["inputSchema"]["required"] == ["node"]
    assert tools["scan_topology"]["inputSchema"]["properties"]["perspective"]["enum"] == [
        "engineering", "risk", "compliance", "monitoring", "classic"]       # COD-001: matches the handler


def test_protocol_errors(server):
    assert rpc(server, "resources/list")["error"]["code"] == -32601
    unknown_tool = rpc(server, "tools/call", {"name": "delete_everything", "arguments": {}})
    assert unknown_tool["error"]["code"] == -32602 and "Unknown tool" in unknown_tool["error"]["message"]
    assert server.handle({"id": 5, "method": "tools/list"})["error"]["code"] == -32600   # no "jsonrpc"
    assert server.handle_line("{not json")["error"]["code"] == -32700
    assert server.handle_line("{not json")["id"] is None
    assert rpc(server, "ping")["result"] == {}


def test_batch(server):
    replies = server.handle_line(json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]))
    assert [r["id"] for r in replies] == [1, 2]


# -------------------------------------------------------------------- tools
def test_scan_topology_auto_detects_session(server):
    data, err = call(server, "scan_topology")
    assert not err
    assert data["session"] == "-home-me-proj/sess-1"                      # SEC-001: a label, never a path
    assert data["session_source"] == "newest session of project -home-me-proj"
    assert data["fi"] == 0.5 and data["node_count"] == 6 and data["edge_count"] == 6
    assert data["bridge_count"] == 3 and data["components"] == 1
    assert data["articulation_points"] == ["agent:sub1", "claude"]
    by_id = {n["id"]: n for n in data["nodes"]}
    assert by_id["claude"]["classification"] == "KEYSTONE"
    assert by_id["tool:Bash"]["calls"] == 3 and by_id["tool:Bash"]["errors"] == 1
    assert {"source": "human", "target": "claude"} in data["bridges"]
    assert "Fragility Index is 0.50" in data["summary"]
    assert "No baseline" not in data["summary"]                    # structure only


def test_scan_topology_perspective_and_bad_input(server, session_dir):
    data, _ = call(server, "scan_topology", perspective="risk",
                   session_path=str(session_dir / "sess-1.jsonl"))
    assert data["summary"].startswith("This session has 6 nodes")          # named, not "your current"
    assert {n["id"]: n["classification"] for n in data["nodes"]}["claude"] == "HIGH RISK"
    msg, err = call(server, "scan_topology", perspective="astrology")
    assert err and "Unknown perspective" in msg
    msg, err = call(server, "scan_topology", session_path=str(session_dir / "missing.jsonl"))
    assert err and "Session not found" in msg
    msg, err = call(server, "scan_topology", sessoin_path="typo")
    assert err and "Unknown argument" in msg


def test_topology_summary_reads_naturally(server):
    data, err = call(server, "topology_summary")
    assert not err
    text = data["summary"]
    assert text.startswith("Your current session has 6 nodes (1 orchestrator, 1 sub-agent, 3 tools, the human) "
                           "and 6 links.")
    assert "3 of 6 links have no backup path" in text
    assert "sub-agents sharing tools" in text
    assert "1 sub-agent (Explore) shares 1 tool with the orchestrator (Bash)" in text
    assert "Other keystones: Bash and the Explore sub-agent." in text     # Bash closes the only triangle
    assert "The orchestrator (claude) is the main keystone: if it fails, the system fragments" in text
    assert "Most-used tool: Bash (3 calls, 1 failed)." in text
    assert "No baseline at .agent-certify/baseline.json" in text
    assert "No policy at .agent-certify/policy.json." in text


def test_summary_with_baseline_and_policy(server, session_dir):
    BaselineLearner().save(BaselineLearner().learn([str(session_dir / "sess-1.jsonl")]))
    Policy([PolicyRule("forbidden_tool", "Grep", "critical", "no grep")]).save()
    text = call(server, "topology_summary")[0]["summary"]
    assert "No anomalies detected against the baseline of 1 sessions." in text
    assert "1 policy violation: CRITICAL FORBIDDEN tool used: Grep." in text


def test_blast_radius(server):
    data, err = call(server, "blast_radius", node="claude")
    assert not err
    assert data["compromised"] == "claude"
    assert data["system_fragmented"] is True and data["fragment_count"] == 3
    assert data["direct_impact"] == ["agent:sub1", "human", "tool:Bash", "tool:Read"]
    assert "Single point of failure" in data["recommendation"]
    bash, _ = call(server, "blast_radius", node="bash")              # resolved by name
    assert bash["compromised"] == "tool:Bash" and bash["system_fragmented"] is False
    msg, err = call(server, "blast_radius", node="nope")
    assert err and "no node named 'nope'" in msg
    msg, err = call(server, "blast_radius")
    assert err and "Missing required argument" in msg


def test_check_anomalies(server, session_dir):
    msg, err = call(server, "check_anomalies")
    assert err and "No baseline at .agent-certify/baseline.json" in msg and "agent-certify learn" in msg
    BaselineLearner().save(BaselineLearner().learn([str(session_dir / "sess-1.jsonl")]))
    data, err = call(server, "check_anomalies")
    assert not err and data["anomaly_count"] == 0 and data["learned_from"] == 1
    other = session_dir / "other.jsonl"
    other.write_text(json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "id": "x", "name": "deploy", "input": {}}]}}) + "\n")
    data, _ = call(server, "check_anomalies", session_path=str(other))
    assert any(a["category"] == "new_tool" and a["severity"] == "critical" for a in data["anomalies"])


def test_check_policy(server, tmp_path):
    msg, err = call(server, "check_policy")
    assert err and "suggest-policy" in msg
    path = Policy([PolicyRule("forbidden_tool", "Grep", "critical", "no grep"),
                   PolicyRule("max_sub_agents", "0", "warning", "no sub-agents")]).save(tmp_path / "p.json")
    data, err = call(server, "check_policy", policy_path=str(path))
    assert not err and data["violation_count"] == 2 and data["rule_count"] == 2
    assert data["violations"][0] == {"rule_kind": "forbidden_tool", "target": "Grep", "severity": "critical",
                                     "message": "FORBIDDEN tool used: Grep",
                                     "observed": "Tool Grep was used (1 calls)"}


def test_structured_content_by_protocol_version(server):
    rpc(server, "initialize", {"protocolVersion": "2025-06-18"})
    assert "structuredContent" in rpc(server, "tools/call", {"name": "scan_topology"})["result"]
    rpc(server, "initialize", {"protocolVersion": "2024-11-05"})
    assert "structuredContent" not in rpc(server, "tools/call", {"name": "scan_topology"})["result"]


# ------------------------------------------------------- session detection
def test_session_from_env(session_dir):
    (session_dir / "aaa.jsonl").write_text("")
    path, how = find_current_session(session_dir.parent, cwd="/elsewhere", env={"CLAUDE_CODE_SESSION_ID": "sess-1"})
    assert path.name == "sess-1.jsonl" and how == "CLAUDE_CODE_SESSION_ID=sess-1"
    path, _ = find_current_session(session_dir.parent, cwd="/elsewhere", env={"CLAUDE_SESSION_ID": "aaa"})
    assert path.name == "aaa.jsonl"


def test_session_fallbacks(session_dir, tmp_path):
    # PRV-001: no machine-wide fallback; another project's session is never picked.
    os.utime(session_dir / "sess-1.jsonl", (2_000_000_000, 2_000_000_000))
    with pytest.raises(ToolError, match="No session found in the current project"):
        find_current_session(session_dir.parent, cwd="/not/a/project", env={})
    with pytest.raises(ToolError, match="No Claude Code projects folder"):
        find_current_session(tmp_path / "none", env={})
    empty = tmp_path / "empty-root"
    empty.mkdir()
    with pytest.raises(ToolError, match="No session found"):
        find_current_session(empty, env={})


# --------------------------------------------------------------- transport
def test_run_over_stdio_streams(server, capsys):
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "topology_summary"}},
    ]
    stdin = io.BytesIO(("\n".join(json.dumps(r) for r in requests) + "\n\n").encode())
    stdout = io.BytesIO()
    server.run(stdin, stdout)
    raw = stdout.getvalue()
    assert b"\r\n" not in raw                                          # bare \n framing, also on Windows
    replies = [json.loads(line) for line in raw.decode().splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert "Your current session" in json.loads(replies[1]["result"]["content"][0]["text"])["summary"]


def test_stray_prints_do_not_corrupt_the_protocol(server, monkeypatch, capsys):
    def noisy(**kw):
        print("debug noise")                                           # e.g. from a library
        return {"ok": True}
    monkeypatch.setitem(server._handlers, "topology_summary", noisy)
    stdout = io.BytesIO()
    server.run(io.BytesIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "topology_summary"}}).encode() + b"\n"), stdout)
    assert json.loads(stdout.getvalue())["result"]["content"][0]["text"].strip().startswith("{")
    assert "debug noise" in capsys.readouterr().err


def test_handler_crash_is_reported_not_fatal(server, monkeypatch):
    def broken(**kw):
        raise RuntimeError("boom")
    monkeypatch.setitem(server._handlers, "scan_topology", broken)
    msg, err = call(server, "scan_topology")
    assert err and "scan_topology failed (ref " in msg and "boom" not in msg   # OBS-001: no exception text
    assert rpc(server, "ping")["result"] == {}                          # still serving


def test_cli_mcp_subprocess(session_dir):
    """`agent-certify mcp` as a real child process, the way Claude Code launches it."""
    env = dict(os.environ, CLAUDE_CODE_SESSION_ID="sess-1", USERPROFILE=str(session_dir.parent.parent),
               HOME=str(session_dir.parent.parent))
    claude_dir = session_dir.parent.parent / ".claude" / "projects"       # a fake home for the child
    shutil.copytree(session_dir, claude_dir / session_dir.name)
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "scan_topology"}}]
    proc = subprocess.run([sys.executable, "-m", "agent_certify.cli", "mcp"], env=env, timeout=60, check=False,
                          input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True,
                          encoding="utf-8")
    replies = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]
    assert len(replies[1]["result"]["tools"]) == 5
    assert replies[2]["result"]["structuredContent"]["fi"] == 0.5
