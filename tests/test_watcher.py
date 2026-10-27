import json
import os
import threading
import time

import pytest
from conftest import _assistant, _prompt, _results

from agent_certify import Baseline, Policy, PolicyRule, SessionWatcher
from agent_certify.cli import main
from agent_certify.watcher import latest_session


def _baseline(**kw) -> Baseline:
    fields = {
        "learned_from": 5, "period_start": "", "period_end": "", "fi_mean": 1.0, "fi_std": 0.1,
        "node_count_mean": 3.0, "node_count_std": 1.0, "edge_count_mean": 2.0, "edge_count_std": 1.0,
        "known_tools": {"Bash", "Read"}, "tool_frequency": {"Bash": 1.0, "Read": 1.0},
        "sub_agent_count_mean": 0.0, "sub_agent_count_std": 0.0, "max_sub_agents_seen": 0,
        "error_rate_mean": 0.0, "error_rate_std": 0.1,
        "known_links": {("human", "claude"), ("claude", "tool:Bash"), ("claude", "tool:Read")},
        "bridge_count_mean": 2.0, "bridge_count_std": 1.0, "created_at": "",
    }
    fields.update(kw)
    return Baseline(**fields)


class Session:
    """A transcript file that grows the way Claude Code writes it."""

    def __init__(self, path):
        self.path = path
        self.n = 0

    def append(self, *records, raw: str = ""):
        with open(self.path, "a", encoding="utf-8") as f:
            f.writelines(json.dumps(r) + "\n" for r in records)
            f.write(raw)

    def call(self, *names):
        uses = []
        for name in names:
            self.n += 1
            uses.append((f"c{self.n}", name, {}))
        self.append(_assistant(uses), _results([(i, False) for i, _, _ in uses]))


@pytest.fixture
def session(tmp_path):
    s = Session(tmp_path / "live.jsonl")
    s.append(_prompt("go"))
    s.call("Bash", "Read")
    return s


def _watcher(path, lines, **kw):
    return SessionWatcher(str(path), interval=0.05, out=lines.append, **kw)


def test_detects_growth_and_new_nodes(session):
    lines = []
    w = _watcher(session.path, lines)
    assert w.poll() is True
    assert w.history[-1]["nodes"] == 4                       # human, claude, Bash, Read
    assert w.poll() is False                                  # nothing changed: no rescan
    session.call("Grep")
    assert w.poll() is True
    assert w.history[-1]["new_nodes"] == ["tool:Grep"]
    assert any("New node appeared: tool:Grep" in line for line in lines)
    assert w.history[-1]["calls"] == 3


def test_anomalies_against_baseline_reported_once(session):
    seen = []
    w = _watcher(session.path, [], baseline=_baseline(), on_anomaly=seen.append)
    w.poll()
    assert seen == []                                         # matches the baseline
    session.call("deploy")
    w.poll()
    assert [(a.severity, a.category, a.value) for a in seen] == [("critical", "new_tool", "deploy")]
    session.call("deploy", "Bash")                            # same anomaly again: not repeated
    w.poll()
    assert [a.value for a in seen if a.category == "new_tool"] == ["deploy"]


def test_policy_violations(session):
    policy = Policy(rules=[PolicyRule("forbidden_tool", "deploy*", "critical", "no deploys")])
    lines, hits = [], []
    w = _watcher(session.path, lines, policy=policy)
    w.poll()
    session.call("deploy_staging")
    w.poll()
    assert any("[CRITICAL] POLICY VIOLATION: FORBIDDEN tool used: deploy_staging" in line for line in lines)

    w2 = _watcher(session.path, [], policy=policy, on_policy_violation=hits.append)
    w2.poll()
    assert [v.rule.target for v in hits] == ["deploy*"]


def test_waits_for_file_to_appear(tmp_path):
    lines = []
    path = tmp_path / "later.jsonl"
    w = _watcher(path, lines)
    assert w.poll() is False and w.poll() is False
    assert sum("Waiting for" in line for line in lines) == 1
    Session(path).call("Bash")
    assert w.poll() is True
    assert w.history[-1]["calls"] == 1


def test_half_written_line_is_skipped_then_read(session):
    w = _watcher(session.path, [])
    w.poll()
    record = json.dumps(_assistant([("late", "Glob", {})]))
    session.append(raw=record[:20])                           # writer is mid-line
    assert w.poll() is True                                   # no crash
    assert "tool:Glob" not in w._last_graph.nodes
    session.append(raw=record[20:] + "\n")
    w.poll()
    assert "tool:Glob" in w._last_graph.nodes


def test_subagent_growth_triggers_rescan(session):
    w = _watcher(session.path, [])
    w.poll()
    sub = session.path.parent / "live" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-x1.jsonl").write_text(json.dumps(_assistant([("s1", "WebSearch", {})])) + "\n")
    assert w.poll() is True
    assert "tool:WebSearch" in w._last_graph.nodes


def test_threaded_watch_until_stopped(session):
    lines = []
    w = SessionWatcher(str(session.path), interval=0.05, out=lines.append, baseline=_baseline())
    t = threading.Thread(target=w.watch, daemon=True)
    t.start()

    def wait_for(n):
        deadline = time.monotonic() + 5
        while len(w.history) < n and time.monotonic() < deadline:
            time.sleep(0.02)
        assert len(w.history) >= n

    wait_for(1)
    session.call("Grep")
    wait_for(2)
    session.call("deploy")
    wait_for(3)
    w.stop()
    t.join(timeout=5)
    assert not t.is_alive()
    assert [h["new_nodes"] for h in w.history[:3]] == [[], ["tool:Grep"], ["tool:deploy"]]
    assert any(a.category == "new_tool" for a in w.history[2]["anomalies"])
    assert lines[0].startswith("Watching") and "Baseline: loaded (5 sessions)" in lines
    assert any(line.startswith("Final state:") for line in lines)


def test_max_scans_and_final_report(session):
    lines = []
    SessionWatcher(str(session.path), interval=0.05, out=lines.append, max_scans=1, perspective="risk").watch()
    assert any(line.startswith("Final state: 4 nodes") for line in lines)
    assert any("HIGH RISK: claude" in line for line in lines)


def test_latest_session(tmp_path):
    old, new = tmp_path / "old.jsonl", tmp_path / "new.jsonl"
    old.write_text("")
    new.write_text("")
    os.utime(old, (1_000_000, 1_000_000))
    assert latest_session(tmp_path) == new
    assert latest_session(tmp_path / "missing") is None


def test_cli_watch_directory(session, capsys):
    assert main(["watch", str(session.path.parent), "--interval", "0.05", "--scans", "1", "--no-baseline"]) == 0
    out = capsys.readouterr().out
    assert "live.jsonl" in out and "Nodes: 4" in out and "Final state" in out


def test_invalid_interval(session):
    with pytest.raises(ValueError):
        SessionWatcher(str(session.path), interval=0)


def test_duration_stops_a_quiet_session(session):
    lines = []
    start = time.monotonic()
    SessionWatcher(str(session.path), interval=0.05, out=lines.append, max_scans=99, max_seconds=0.3).watch()
    assert time.monotonic() - start < 3
    assert any(line.startswith("Final state:") for line in lines)     # one scan, then the clock ran out
