# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""Live monitoring of an active Claude Code session.

The transcript is append-only. The watcher polls its size (plus the sizes of
its sub-agent transcripts) and, when anything grew, re-parses the session,
rescans it and reports:

  * a status line (nodes, links, FI and its change, tool calls)
  * nodes that appeared since the previous scan
  * anomalies against a baseline (critical and warning)
  * policy violations

Each anomaly or violation is reported once, when it first appears (again only
if its severity changes), not on every scan. A file that does not exist yet is
waited for; a half-written last line is skipped until it is complete.
No file-system notification library: plain size polling.

Any format :class:`~agent_certify.parser.AutoParser` reads can be watched: a
Claude Code transcript, a Cursor ``traces.jsonl`` or an MCP server log.

Known limitation (v0.5): every change triggers a full re-parse and rescan of
the session, so the cost of each scan grows with the session's length. The
scan itself is near-linear since v0.5, which keeps this practical for long
sessions; incremental parsing from the last file offset is planned.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from agent_certify.anomaly import AnomalyDetector
from agent_certify.baseline import Baseline
from agent_certify.graph import AgentGraph
from agent_certify.parser.auto import AutoParser
from agent_certify.policy import Policy, PolicyViolation
from agent_certify.scanner import HIGH, AgentFIScanner, Perspective


def latest_session(directory: str | Path) -> Path | None:
    """The most recently modified session transcript in a project folder."""
    files = [f for f in Path(directory).glob("*.jsonl") if f.is_file()]
    return max(files, key=lambda f: f.stat().st_mtime) if files else None


class SessionWatcher:
    """Watch an active session JSONL file and report structural changes.

    Usage::

        SessionWatcher(path, baseline=b, policy=p, interval=30).watch()   # blocks until Ctrl+C

    In a thread, call :meth:`stop` to end it; ``max_scans`` ends it after that
    many scans, ``max_seconds`` after that much time (scans only happen when the
    session grows, so a quiet session needs the latter). ``history`` keeps one
    summary dict per scan. ``on_scan(graph, result, report, violations, started_at)`` is
    called after every scan with all of that scan's anomalies (an
    :class:`AnomalyReport`, or None without a baseline) and policy violations
    (a list, or None without a policy), not only the newly reported ones.
    """

    def __init__(
        self,
        session_path: str,
        baseline: Baseline | None = None,
        policy: Policy | None = None,
        interval: float = 30.0,
        on_anomaly: Callable | None = None,
        on_policy_violation: Callable | None = None,
        perspective: str = "engineering",
        max_scans: int | None = None,
        max_seconds: float | None = None,
        out: Callable[[str], None] = print,
        on_scan: Callable | None = None,
    ):
        if interval <= 0:
            raise ValueError("interval must be positive")
        Perspective.labels(perspective)
        self.session_path = Path(session_path)
        self.baseline = baseline
        self.policy = policy
        self.interval = interval
        self.on_anomaly = on_anomaly or self._default_print
        self.on_policy_violation = on_policy_violation or self._print_violation
        self.perspective = perspective
        self.max_scans = max_scans
        self.max_seconds = max_seconds
        self.out = out
        self.on_scan = on_scan
        self.history: list[dict] = []
        self._stop = threading.Event()
        self._last_size: int | None = None
        self._last_graph: AgentGraph | None = None
        self._last_fi: float | None = None
        self._last_result = None
        self._reported: dict[tuple, str] = {}
        self._waiting_said = False

    # ------------------------------------------------------------------ api
    def watch(self) -> None:
        """Block and watch until Ctrl+C, :meth:`stop`, or ``max_scans``."""
        self.out(f"Watching {self.session_path} (every {self.interval:g}s, Ctrl+C to stop)")
        self.out("Baseline: " + (f"loaded ({self.baseline.learned_from} sessions)" if self.baseline else "none"))
        self.out("Policy: " + (f"loaded ({len(self.policy.rules)} rules)" if self.policy else "none"))
        self.out("─" * 60)
        deadline = time.monotonic() + self.max_seconds if self.max_seconds is not None else None
        try:
            while not self._stop.is_set():
                self.poll()
                if self.max_scans is not None and len(self.history) >= self.max_scans:
                    break
                if deadline is not None:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        break
                    self._sleep(min(self.interval, left))
                else:
                    self._sleep(self.interval)
        except KeyboardInterrupt:
            self.out("\nStopped watching.")
        self._final_report()

    def stop(self) -> None:
        self._stop.set()

    def _sleep(self, seconds: float) -> None:
        # Short slices: Ctrl+C is not delivered during Event.wait() on Windows.
        end = time.monotonic() + seconds
        while not self._stop.is_set():
            left = end - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(0.2, left))

    def poll(self) -> bool:
        """One check: scan if the session grew. Returns True when it scanned."""
        size = self._size()
        if size is None:
            if not self._waiting_said:
                self.out(f"Waiting for {self.session_path} to appear...")
                self._waiting_said = True
            return False
        if size == self._last_size:
            return False
        self._last_size = size
        self._scan_and_report()
        return True

    # ------------------------------------------------------------ internals
    def _size(self) -> int | None:
        """Combined size of the transcript and its sub-agent transcripts (None if absent)."""
        if not self.session_path.is_file():
            return None
        total = self.session_path.stat().st_size
        sub = self.session_path.parent / self.session_path.stem / "subagents"
        if sub.is_dir():
            total += sum(f.stat().st_size for f in sub.glob("agent-*.jsonl"))
        return total

    def _scan_and_report(self) -> None:
        """Parse, scan, detect anomalies, check policy."""
        # A half-written last line is normal while the file grows: keep the parsers quiet about it.
        loggers = [logging.getLogger(f"agent_certify.parser.{m}") for m in ("claude_code", "cursor_trace", "mcp_logs")]
        levels = [lg.level for lg in loggers]
        for lg in loggers:
            lg.setLevel(logging.ERROR)
        started = datetime.now(timezone.utc)
        try:
            graph = AutoParser().parse(str(self.session_path))
        finally:
            for lg, level in zip(loggers, levels):
                lg.setLevel(level)
        result = AgentFIScanner(graph, perspective=self.perspective).scan()

        fi_str = f"FI: {result.fi:.4f}"
        if self._last_fi is not None and abs(result.fi - self._last_fi) > 1e-12:
            fi_str += f" (Δ {result.fi - self._last_fi:+.4f})"
        stamp = time.strftime("%H:%M:%S")
        self.out(f"[{stamp}] Nodes: {len(graph.nodes):<3} Links: {result.edge_count:<3} {fi_str}   "
                 f"Calls: {graph.total_tool_calls}")

        new_nodes = sorted(set(graph.nodes) - set(self._last_graph.nodes)) if self._last_graph else []
        for nid in new_nodes:
            role = graph.role(nid)
            self.out(f"  ⚡ New node appeared: {nid}" + (f" ({role})" if role != nid else ""))

        anomalies, report, all_violations = [], None, None
        if self.baseline:
            report = AnomalyDetector(self.baseline).detect(graph, result)
            for a in report.anomalies:
                if a.severity in ("critical", "warning") and self._is_new(("anomaly", a.category, self._ident(a)),
                                                                          a.severity):
                    anomalies.append(a)
                    self.on_anomaly(a)
        violations = []
        if self.policy:
            all_violations = self.policy.check(graph)
            for v in all_violations:
                if self._is_new(("policy", v.rule.kind, v.rule.target, v.message), v.severity):
                    violations.append(v)
                    self.on_policy_violation(v)

        self.history.append({"time": stamp, "nodes": len(graph.nodes), "links": result.edge_count,
                             "fi": result.fi, "calls": graph.total_tool_calls, "new_nodes": new_nodes,
                             "anomalies": anomalies, "violations": violations})
        self._last_graph, self._last_fi, self._last_result = graph, result.fi, result
        if self.on_scan:
            self.on_scan(graph, result, report, all_violations, started)

    @staticmethod
    def _ident(a) -> str:
        # Categorical anomalies are distinct per value; numeric ones (FI, error rate...) are one stream.
        return str(a.value) if a.category in ("new_tool", "new_link") else ""

    def _is_new(self, key: tuple, severity: str) -> bool:
        if self._reported.get(key) == severity:
            return False
        self._reported[key] = severity
        return True

    def _final_report(self) -> None:
        """Print summary when watch stops."""
        if self._last_graph is None:
            self.out("No scans completed.")
            return
        r = self._last_result
        self.out(f"Final state: {len(self._last_graph.nodes)} nodes, {r.edge_count} links, FI: {self._last_fi:.4f} "
                 f"({len(self.history)} scan(s))")
        top = [n for n, lvl in r.node_levels.items() if lvl == HIGH]
        if top:
            self.out(f"  {Perspective.labels(self.perspective)[HIGH]}: {', '.join(sorted(top))}")

    def _default_print(self, item) -> None:
        self.out(f"  [{item.severity.upper()}] {item.message}")

    def _print_violation(self, v: PolicyViolation) -> None:
        self.out(f"  [{v.severity.upper()}] POLICY VIOLATION: {v.message}")
