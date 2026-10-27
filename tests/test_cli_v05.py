# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""CLI behaviour added by the v0.5 audit fixes (SEC-002, SEC-003, SEC-004, FUN-001, FUN-002, OBS-002)."""
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from conftest import _assistant, _results

from agent_certify import AgentCertificate, BaselineLearner, Policy, PolicyRule
from agent_certify.cli import main
from agent_certify.parser import ClaudeCodeParser

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


# ------------------------------------------------------------------ keygen
@posix_only
def test_keygen_private_key_is_0600(tmp_path):
    key = tmp_path / "k"
    assert main(["keygen", str(key)]) == 0
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(str(key) + ".pub").stat().st_mode) == 0o644


def test_keygen_refuses_to_overwrite(tmp_path):
    key = tmp_path / "k"
    assert main(["keygen", str(key)]) == 0
    first = key.read_text()
    with pytest.raises(SystemExit, match="exists"):
        main(["keygen", str(key)])
    assert key.read_text() == first
    assert main(["keygen", str(key), "--force"]) == 0
    assert key.read_text() != first


def test_keygen_never_writes_through_a_symlink(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("important")
    link = tmp_path / "k"
    try:
        os.symlink(victim, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")
    with pytest.raises(SystemExit):
        main(["keygen", str(link)])
    assert victim.read_text() == "important"
    assert main(["keygen", str(link), "--force"]) == 0          # --force replaces the link itself
    assert victim.read_text() == "important" and not link.is_symlink()


@posix_only
def test_certify_warns_about_readable_key(session_dir, tmp_path, capsys):
    key = tmp_path / "k"
    main(["keygen", str(key)])
    key.chmod(0o644)
    capsys.readouterr()
    main(["certify", str(session_dir / "sess-1.jsonl"), "--key", str(key), "-o", str(tmp_path / "c.json")])
    assert "accessible by other users" in capsys.readouterr().err


# ------------------------------------------------------------------ verify
@pytest.fixture
def issued(session_dir, tmp_path):
    key, cert = tmp_path / "k", tmp_path / "c.json"
    main(["keygen", str(key)])
    main(["certify", str(session_dir / "sess-1.jsonl"), "--key", str(key), "-o", str(cert), "--system-id", "s1"])
    return {"session": str(session_dir / "sess-1.jsonl"), "key": str(key), "pub": str(key) + ".pub",
            "cert": str(cert)}


def test_verify_requires_a_public_key(issued, capsys):
    assert main(["verify", issued["cert"], issued["session"]]) == 2
    assert "needs --public-key" in capsys.readouterr().err
    assert main(["verify", issued["cert"], issued["session"], "--public-key", issued["pub"]]) == 0


def test_verify_allow_unsigned_warns(session_dir, tmp_path, capsys):
    cert = tmp_path / "u.json"
    main(["certify", str(session_dir / "sess-1.jsonl"), "-o", str(cert)])
    assert "UNSIGNED" in capsys.readouterr().err
    assert main(["verify", str(cert), str(session_dir / "sess-1.jsonl"), "--allow-unsigned"]) == 0
    assert "--allow-unsigned: the certificate's signature is NOT checked" in capsys.readouterr().err


def test_verify_unsigned_with_key_fails(session_dir, tmp_path, issued, capsys):
    cert = tmp_path / "u.json"
    main(["certify", str(session_dir / "sess-1.jsonl"), "-o", str(cert)])
    assert main(["verify", str(cert), issued["session"], "--public-key", issued["pub"]]) == 1
    assert "Certificate is not signed" in capsys.readouterr().out


def test_verify_bad_public_key_file(issued, tmp_path):
    bad = tmp_path / "bad.pub"
    bad.write_text("not a key")
    with pytest.raises(SystemExit, match="Ed25519 public key"):
        main(["verify", issued["cert"], issued["session"], "--public-key", str(bad)])


def test_verify_expiry_flags(issued, session_dir, tmp_path, capsys):
    old = datetime.now(timezone.utc) - timedelta(days=400)
    g = ClaudeCodeParser().parse(issued["session"])
    priv = Path(issued["key"]).read_text().strip()
    expired = tmp_path / "old.json"
    AgentCertificate.create(g, signing_key=priv, validity_days=30, now=old).save(expired)
    assert main(["verify", str(expired), issued["session"], "--public-key", issued["pub"]]) == 1
    assert "Certificate expired on" in capsys.readouterr().out
    assert main(["verify", str(expired), issued["session"], "--public-key", issued["pub"], "--ignore-expiry"]) == 0


def test_verify_expected_system_id(issued):
    base = ["verify", issued["cert"], issued["session"], "--public-key", issued["pub"]]
    assert main(base + ["--expect-system-id", "s1"]) == 0
    assert main(base + ["--expect-system-id", "prod"]) == 1


def test_certify_validity_days(session_dir, tmp_path):
    out = tmp_path / "c.json"
    main(["certify", str(session_dir / "sess-1.jsonl"), "-o", str(out), "--validity-days", "7"])
    cert = AgentCertificate.load(out)
    span = datetime.strptime(cert.not_after, "%Y-%m-%dT%H:%M:%SZ") - datetime.strptime(cert.not_before,
                                                                                        "%Y-%m-%dT%H:%M:%SZ")
    assert span == timedelta(days=7)


def test_verify_unreadable_certificate(tmp_path, issued):
    junk = tmp_path / "junk.json"
    junk.write_text("[1,2,3]")
    with pytest.raises(SystemExit, match="not a readable agent-certify certificate"):
        main(["verify", str(junk), issued["session"], "--public-key", issued["pub"]])


# ---------------------------------------------------------------- fail-on
@pytest.fixture
def warning_only(session_dir):
    """A baseline under which sess-1 has only a warning (a never-seen link), no critical finding."""
    b = BaselineLearner().learn([str(session_dir / "sess-1.jsonl")])
    b.known_links.discard(("claude", "tool:Read"))
    BaselineLearner().save(b)
    return str(session_dir / "sess-1.jsonl")


def test_fail_on_critical_default(session_dir, warning_only):
    other = session_dir / "other.jsonl"
    other.write_text(json.dumps(_assistant([("x", "deploy", {})])) + "\n")
    assert main(["scan", str(other)]) == 2                              # critical: new tool
    assert main(["scan", str(other), "--fail-on", "never"]) == 0
    assert main(["scan", warning_only]) == 0                            # warning only
    assert main(["scan", warning_only, "--fail-on", "warning"]) == 2
    assert main(["scan", warning_only, "--fail-on", "never"]) == 0


def test_fail_on_policy_violation(session_dir):
    Policy([PolicyRule("forbidden_tool", "Grep", "warning", "")]).save()
    session = str(session_dir / "sess-1.jsonl")
    assert main(["scan", session, "--no-baseline"]) == 0                # a warning violation
    assert main(["scan", session, "--no-baseline", "--fail-on", "warning"]) == 2
    Policy([PolicyRule("forbidden_tool", "Grep", "critical", "")]).save()
    assert main(["scan", session, "--no-baseline"]) == 2


# ----------------------------------------------------------- FUN-002 / OBS-002
def test_policy_evaluated_per_session_in_text(session_dir, capsys):
    (session_dir / "sess-2.jsonl").write_text(json.dumps(_assistant([("x", "Grep", {})])) + "\n"
                                              + json.dumps(_results([("x", False)])) + "\n")
    Policy([PolicyRule("forbidden_tool", "Grep", "critical", "no grep")]).save()
    assert main(["scan", str(session_dir), "--no-baseline"]) == 2
    out = capsys.readouterr().out
    header = out.splitlines()[0]
    assert "VIOLATIONS" in header
    rows = {line.split()[0]: line for line in out.splitlines()[1:3]}
    assert rows["sess-1"].endswith("1 critical") and rows["sess-2"].endswith("1 critical")
    assert "sess-2: [CRITICAL] FORBIDDEN tool used: Grep" in out
    assert "(1 rules, evaluated per session)" in out


def test_policy_per_session_in_markdown_and_html(session_dir, tmp_path, capsys):
    (session_dir / "sess-2.jsonl").write_text(json.dumps(_assistant([("x", "Grep", {})])) + "\n")
    Policy([PolicyRule("forbidden_tool", "Grep", "warning", "no grep")]).save()
    assert main(["scan", str(session_dir), "--no-baseline", "--format", "markdown"]) == 0
    md = capsys.readouterr().out
    assert "### Per session" in md and "`sess-2`: **WARNING** FORBIDDEN tool used: Grep" in md
    out = tmp_path / "r.html"
    main(["scan", str(session_dir), "--no-baseline", "--format", "html", "-o", str(out)])
    page = out.read_text(encoding="utf-8")
    assert "Per session" in page and "FORBIDDEN tool used: Grep" in page


def test_skipped_records_reported(session_dir, capsys):
    session = session_dir / "sess-1.jsonl"
    with open(session, "a", encoding="utf-8") as f:
        f.write("{broken\n" * 10)                                       # 11 bad lines in total
    assert main(["scan", str(session), "--no-baseline", "--no-policy"]) == 0
    captured = capsys.readouterr()
    assert "Skipped records  11" in captured.out
    assert "11 of" in captured.err and "could not be read" in captured.err
    main(["scan", str(session), "--no-baseline", "--no-policy", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["scan"]["skipped_records"] == 11
