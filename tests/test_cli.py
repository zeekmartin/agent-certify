# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
import json

from agent_certify.cli import main


def test_scan_formats(session_dir, tmp_path, capsys):
    session = str(session_dir / "sess-1.jsonl")
    assert main(["scan", session]) == 0
    assert "Fragility Index  0.5000" in capsys.readouterr().out

    assert main(["scan", session, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["scan"]["fi"] == 0.5

    assert main(["scan", session, "--format", "markdown"]) == 0
    assert "| `tool:Bash` |" in capsys.readouterr().out

    out = tmp_path / "g.html"
    assert main(["scan", str(session_dir), "--format", "html", "-o", str(out)]) == 0
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>") and "<svg" in page and '"tool:Bash"' in page
    assert "http" not in page.split("<script>")[0].split("</style>")[1]     # no external assets


def test_blast(session_dir, capsys):
    assert main(["blast", str(session_dir), "--node", "claude"]) == 0
    assert "Fragmented after isolation: True" in capsys.readouterr().out


def test_certify_and_verify(session_dir, tmp_path, capsys):
    key, cert = tmp_path / "k", tmp_path / "c.json"
    session = str(session_dir / "sess-1.jsonl")
    assert main(["keygen", str(key)]) == 0
    assert main(["certify", session, "--key", str(key), "-o", str(cert)]) == 0
    assert main(["verify", str(cert), session, "--public-key", str(key) + ".pub"]) == 0

    # Same session without its sub-agent's transcript: topology drifted.
    (session_dir / "sess-1" / "subagents" / "agent-sub1.jsonl").unlink()
    capsys.readouterr()
    assert main(["verify", str(cert), session]) == 1
    assert "certified link(s) gone" in capsys.readouterr().out
