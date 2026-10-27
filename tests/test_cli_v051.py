# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""v0.5.1 UX fixes: files with no usable data, one warning per file, keygen default, verify hints."""
import json
import logging
from pathlib import Path

import pytest
from conftest import _assistant

from agent_certify import AgentCertifyMCPServer
from agent_certify.cli import VERIFY_HINT, main

NO_DATA = {
    "empty.jsonl": "",
    "dot.jsonl": ".\r\n",                                 # what `echo. > empty.jsonl` writes on Windows
    "string.jsonl": '"ceci nest pas du json"\r\n',
    "text.jsonl": "ceci nest pas du json\n{broken\n",
    "blank.jsonl": "\n\n   \n",
}


# ------------------------------------------------------------ no usable data
@pytest.mark.parametrize("name", list(NO_DATA))
@pytest.mark.parametrize("command", [["scan"], ["blast", "--node", "claude"], ["certify"]])
def test_no_readable_records_exits_1(tmp_path, capsys, name, command):
    f = tmp_path / name
    f.write_text(NO_DATA[name], encoding="utf-8")
    args = [command[0], str(f), *command[1:]]
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == f"No readable records in {name}"        # printed by Python, exit status 1
    captured = capsys.readouterr()
    assert "Fragility Index" not in captured.out and "WARNING" not in captured.err


def test_no_readable_records_exit_status_is_1(tmp_path):
    import subprocess
    import sys
    f = tmp_path / "empty.jsonl"
    f.write_text("")
    proc = subprocess.run([sys.executable, "-m", "agent_certify.cli", "scan", str(f)], capture_output=True,
                          text=True, check=False)
    assert proc.returncode == 1
    assert proc.stderr.strip() == "No readable records in empty.jsonl" and proc.stdout == ""


def test_directory_leaves_out_unusable_files(session_dir, capsys):
    (session_dir / "empty.jsonl").write_text("")
    assert main(["scan", str(session_dir), "--no-baseline", "--no-policy"]) == 0
    captured = capsys.readouterr()
    assert "1 file(s) with no readable records left out" in captured.err
    assert "Session   sess-1" in captured.out


def test_directory_with_nothing_usable(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    (d / "a.jsonl").write_text("")
    (d / "b.jsonl").write_text("{broken\n")
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(d)])
    assert exc.value.code == "No readable records in proj"


def test_mcp_refuses_sessions_without_data(session_dir):
    (session_dir / "empty.jsonl").write_text("")
    server = AgentCertifyMCPServer(projects_root=session_dir.parent, cwd="/home/me/proj", env={})
    reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "scan_topology", "arguments": {"session_path": str(session_dir / "empty.jsonl")}}})
    assert reply["result"]["isError"]
    assert reply["result"]["content"][0]["text"] == "No readable records in the session"


# ------------------------------------------------------- one warning per file
def test_one_warning_per_file(tmp_path, capsys, caplog):
    f = tmp_path / "partial.jsonl"
    f.write_text(json.dumps(_assistant([("t1", "Bash", {})])) + "\n{broken\nnot json either\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert main(["scan", str(f), "--no-baseline", "--no-policy"]) == 0
    err = capsys.readouterr().err
    assert err.strip() == "WARNING: partial.jsonl: 2 of 3 records unreadable, skipped"
    assert not [r for r in caplog.records if r.name.startswith("agent_certify.parser")]   # parsers stay quiet


def test_clean_file_prints_no_warning(session_dir, capsys):
    clean = session_dir / "clean.jsonl"
    clean.write_text(json.dumps(_assistant([("t1", "Bash", {})])) + "\n")
    assert main(["scan", str(clean), "--no-baseline", "--no-policy"]) == 0
    assert capsys.readouterr().err == ""


# ------------------------------------------------------------- keygen / verify
def test_keygen_default_file_name(capsys):
    assert main(["keygen"]) == 0
    assert Path("agent-certify.key").is_file() and Path("agent-certify.key.pub").is_file()
    assert "private key: agent-certify.key" in capsys.readouterr().out


@pytest.fixture
def issued(session_dir):
    session = str(session_dir / "sess-1.jsonl")
    main(["keygen"])
    main(["certify", session, "--key", "agent-certify.key", "-o", "s.cert.json"])
    return session


@pytest.mark.parametrize("argv", [
    ["{session}", "s.cert.json", "--public-key", "agent-certify.key.pub"],   # reversed
    ["{session}", "--public-key", "agent-certify.key.pub"],                  # session only (the user's mistake)
    ["--public-key", "agent-certify.key.pub"],                               # nothing
    ["s.cert.json", "--public-key", "agent-certify.key.pub"],                # certificate only
])
def test_verify_hint(issued, capsys, argv):
    capsys.readouterr()
    args = ["verify", *[a.format(session=issued) for a in argv]]
    assert main(args) == 2
    assert VERIFY_HINT in capsys.readouterr().err
    assert VERIFY_HINT == "Hint: usage is 'verify CERTIFICATE SESSION --public-key KEY'"


def test_verify_right_order_still_passes(issued, capsys):
    assert main(["verify", "s.cert.json", issued, "--public-key", "agent-certify.key.pub"]) == 0
    assert "Verification: PASS" in capsys.readouterr().out
