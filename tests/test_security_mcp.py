# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""MCP server against untrusted arguments (audit SEC-001, SEC-005, SEC-006, OBS-001, PRV-001)."""
import json
import logging
import os
import time
from pathlib import Path

import pytest

from agent_certify import AgentCertifyMCPServer

SECRET = "hunter2-do-not-leak"


@pytest.fixture
def server(session_dir):
    return AgentCertifyMCPServer(projects_root=session_dir.parent, cwd="/home/me/proj", env={})


def call(server, name, **arguments):
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}})
    return reply, json.dumps(reply)


def error_text(reply) -> str:
    assert reply["result"].get("isError"), reply
    return reply["result"]["content"][0]["text"]


# --------------------------------------------------------- environment variables
@pytest.mark.parametrize("arg", ["$TEST_SECRET", "${TEST_SECRET}", "%TEST_SECRET%", "~/$TEST_SECRET",
                                 "x/%TEST_SECRET%/y.jsonl"])
@pytest.mark.parametrize("tool", ["scan_topology", "topology_summary", "check_anomalies", "check_policy"])
def test_env_vars_are_never_expanded_or_echoed(server, monkeypatch, arg, tool):
    monkeypatch.setenv("TEST_SECRET", SECRET)
    _, raw = call(server, tool, session_path=arg)
    assert SECRET not in raw


@pytest.mark.parametrize("field,tool", [("baseline_path", "check_anomalies"), ("policy_path", "check_policy")])
def test_env_vars_in_artifact_paths(server, monkeypatch, field, tool):
    monkeypatch.setenv("TEST_SECRET", SECRET)
    for arg in ("$TEST_SECRET", "%TEST_SECRET%"):
        _, raw = call(server, tool, **{field: arg})
        assert SECRET not in raw


# ------------------------------------------------------------------ confinement
WINDOWS_PATHS = ["C:\\Windows\\System32\\config\\SAM", "C:\\", "\\\\server\\share\\x.jsonl"]


@pytest.mark.parametrize("arg", ["/etc/passwd", "../../etc/passwd", "../../../../../../etc/passwd", "/"])
def test_paths_outside_the_roots_are_refused(server, arg):
    reply, _raw = call(server, "scan_topology", session_path=arg)
    assert error_text(reply) == "Path not allowed"


@pytest.mark.parametrize("arg", WINDOWS_PATHS)
def test_windows_style_paths(server, arg):
    # On Windows these are absolute paths outside the roots. On POSIX a backslash is an ordinary
    # character, so each is one oddly named file inside the working directory: nothing escapes.
    text = error_text(call(server, "scan_topology", session_path=arg)[0])
    assert text == "Path not allowed" if os.name == "nt" else text == "Session not found"


def test_artifact_paths_outside_the_roots_are_refused(server):
    reply, _ = call(server, "check_anomalies", baseline_path="/etc/shadow")
    assert error_text(reply) == "Path not allowed"
    outside = "C:\\Windows\\System32\\config\\SAM" if os.name == "nt" else "/etc/passwd"
    reply, _ = call(server, "check_policy", policy_path=outside)
    assert error_text(reply) == "Path not allowed"


def test_error_messages_hold_no_resolved_path(server, session_dir, tmp_path):
    for arg in ("missing.jsonl", str(session_dir / "nope.jsonl"), "../../etc/passwd"):
        reply, _raw = call(server, "scan_topology", session_path=arg)
        text = error_text(reply)
        assert text in ("Session not found", "Path not allowed")
        for leak in (str(tmp_path), str(Path.cwd()), str(Path.home()), "etc"):
            assert leak not in text


def test_existence_oracle_limited_to_the_roots(server):
    # Outside the roots, an existing and a missing file give the same answer.
    a = error_text(call(server, "scan_topology", session_path=str(Path(os.__file__)))[0])
    b = error_text(call(server, "scan_topology", session_path="/definitely/not/here.jsonl")[0])
    assert a == b == "Path not allowed"


def test_symlink_escaping_a_root_is_refused(server, session_dir, tmp_path):
    outside = tmp_path.parent / f"outside-{tmp_path.name}.jsonl"
    outside.write_text("{}\n")
    link = session_dir / "link.jsonl"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")
    try:
        assert error_text(call(server, "scan_topology", session_path=str(link))[0]) == "Path not allowed"
    finally:
        outside.unlink()


def test_allowed_paths_still_work(server, session_dir):
    reply, _ = call(server, "scan_topology", session_path=str(session_dir / "sess-1.jsonl"))
    data = json.loads(reply["result"]["content"][0]["text"])
    assert data["fi"] == 0.5
    assert data["session"] == str(session_dir / "sess-1.jsonl")      # the caller's own argument, as given
    reply, _ = call(server, "scan_topology", session_path="~/../" + "x")   # ~ expands, then confinement applies
    assert error_text(reply) in ("Path not allowed", "Session not found")


# ---------------------------------------------------------- artifact contents
def test_arbitrary_json_is_not_echoed(server, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("secrets.json").write_text(json.dumps(["AKIA-LEAK-1", "ghp_LEAK2"]))
    Path("dict.json").write_text(json.dumps({"api_key": "LEAK3", "rules": "nope"}))
    for field, tool in (("baseline_path", "check_anomalies"), ("policy_path", "check_policy")):
        for name in ("secrets.json", "dict.json"):
            reply, raw = call(server, tool, **{field: name})
            assert error_text(reply) == f"Invalid {field.split('_')[0]} format"
            assert "LEAK" not in raw and "api_key" not in raw


def test_session_contents_errors_are_generic(server, session_dir):
    bad = session_dir / "notes.txt"
    bad.write_text("SECRET-CONTENT")
    reply, raw = call(server, "scan_topology", session_path=str(bad))
    assert error_text(reply) == "Session could not be read (unsupported or malformed file)"
    assert "SECRET-CONTENT" not in raw and "notes.txt" not in error_text(reply)


# --------------------------------------------------- failures, timeouts, logs
def test_unexpected_failure_logged_with_reference(server, monkeypatch, caplog):
    def broken(**kw):
        raise RuntimeError(f"internal detail {SECRET}")
    monkeypatch.setitem(server._handlers, "scan_topology", broken)
    with caplog.at_level(logging.ERROR, logger="agent_certify.mcp_server"):
        reply, raw = call(server, "scan_topology")
    text = error_text(reply)
    assert SECRET not in raw
    ref = text.split("ref ")[1].split(";")[0]
    record = next(r for r in caplog.records if ref in r.getMessage())
    assert record.exc_info and SECRET in str(record.exc_info[1])      # full detail stays server-side


def test_request_timeout(session_dir, monkeypatch):
    server = AgentCertifyMCPServer(projects_root=session_dir.parent, cwd="/home/me/proj", env={},
                                   request_timeout=0.2)

    def slow(**kw):
        time.sleep(2)
        return {}
    monkeypatch.setitem(server._handlers, "scan_topology", slow)
    start = time.monotonic()
    reply, _ = call(server, "scan_topology")
    assert error_text(reply) == "Request timed out after 0.2 s"
    assert time.monotonic() - start < 1.5
    assert server.handle({"jsonrpc": "2.0", "id": 2, "method": "ping"})["result"] == {}


def test_non_string_arguments_rejected(server):
    reply, _ = call(server, "scan_topology", session_path=["a", "b"])
    assert error_text(reply) == "Every argument must be a string"


def test_protocol_errors_echo_nothing(server):
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": f"x/{SECRET}"})
    assert SECRET not in json.dumps(reply)
    assert server.handle_line("[" * 100_000)["error"]["code"] == -32700          # deep nesting: parse error


def test_no_machine_wide_fallback(session_dir):
    # PRV-001: from an unrelated working directory, no other project's session is read.
    server = AgentCertifyMCPServer(projects_root=session_dir.parent, cwd="/unrelated/project", env={})
    reply, _ = call(server, "topology_summary")
    assert error_text(reply) == "No session found in the current project; pass session_path explicitly."
