# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""Anomaly detection against a learned baseline.

Each check compares one aspect of a session with the :class:`Baseline`:

==============  =========================================  ======================
check           flags                                      severity
==============  =========================================  ======================
new_tool        a tool never seen in the baseline          critical
new_link        an invocation path never seen (by role)    warning
fi_deviation    FI more than 2 sigma from the mean         warning; critical past
                                                           3 sigma when FI *rose*
error_rate      error rate more than 2 sigma *above*       warning; critical past
                                                           3 sigma
sub_agents      more sub-agents than ever seen, or 2 sigma  warning; critical when
                above the mean                             above max *and* 3 sigma
node_count      node count more than 2 sigma from mean     info; warning past 3
==============  =========================================  ======================

A falling FI means added redundancy (usually sub-agents sharing tools), a
structural change worth knowing about but not a risk in itself, so it never
goes past warning. When the baseline never varied on a metric (std 0), z is
undefined: any difference is reported with ``z_score=None`` at the lower
severity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from agent_certify.baseline import Baseline, node_role
from agent_certify.graph import AgentGraph
from agent_certify.scanner import ScanResult

CRITICAL, WARNING, INFO = "critical", "warning", "info"
_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
_CATEGORICAL = {"new_tool", "new_link"}
_EPS = 1e-9


@dataclass
class Anomaly:
    """A single detected anomaly."""
    severity: str          # "critical", "warning", "info"
    category: str          # "new_tool", "fi_deviation", "error_rate", "new_link", "sub_agents", "node_count"
    message: str           # human-readable description
    value: float | str     # the observed value
    baseline_value: str    # what the baseline says (e.g., "0.87 ± 0.12")
    z_score: float | None  # how many std deviations from mean (None for categorical)
    detail: str = ""       # context: why it may have happened

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnomalyReport:
    """All anomalies detected in a session compared to baseline."""
    session_id: str
    anomalies: list[Anomaly]
    baseline_source: str       # path to baseline.json
    learned_from: int = 0

    @property
    def has_critical(self) -> bool:
        return any(a.severity == CRITICAL for a in self.anomalies)

    def count(self, severity: str) -> int:
        return sum(1 for a in self.anomalies if a.severity == severity)

    @property
    def summary(self) -> str:
        if not self.anomalies:
            return f"No anomalies against baseline of {self.learned_from} session(s)"
        parts = [f"{self.count(s)} {s}" for s in (CRITICAL, WARNING, INFO) if self.count(s)]
        return f"{len(self.anomalies)} anomal{'y' if len(self.anomalies) == 1 else 'ies'} ({', '.join(parts)})"

    def to_dict(self) -> dict:
        return {"session_id": self.session_id, "baseline_source": self.baseline_source,
                "learned_from": self.learned_from, "summary": self.summary,
                "has_critical": self.has_critical, "anomalies": [a.to_dict() for a in self.anomalies]}

    def __str__(self) -> str:
        if not self.anomalies:
            return f"✓  {self.summary}"
        lines = [f"⚠  ANOMALIES DETECTED ({len(self.anomalies)}):", ""]
        for a in self.anomalies:
            tag = f"[{a.severity.upper()}]"
            lines.append(f"{tag:<11}{a.message}")
            if a.category in _CATEGORICAL:      # numeric messages already carry baseline and z
                lines.append(f"{'':<11}Baseline: {a.baseline_value}")
            if a.detail:
                lines.append(f"{'':<11}{a.detail}")
            lines.append("")
        return "\n".join(lines).rstrip()


def _z(value: float, mean: float, std: float) -> float | None:
    return (value - mean) / std if std > _EPS else None


def _pm(mean: float, std: float, pct: bool = False) -> str:
    return f"{mean:.1%} ± {std:.1%}" if pct else f"{mean:.2f} ± {std:.2f}"


class AnomalyDetector:
    """Compare a session scan against a learned baseline.

    Usage::

        detector = AnomalyDetector(load_baseline(".agent-certify/baseline.json"))
        report = detector.detect(graph, AgentFIScanner(graph).scan())
        report.has_critical
    """

    def __init__(self, baseline: Baseline, source: str = ""):
        self.baseline = baseline
        self.source = source

    def detect(self, graph: AgentGraph, scan_result: ScanResult) -> AnomalyReport:
        """Run all anomaly checks."""
        anomalies = []
        anomalies += self._check_new_tools(graph)
        anomalies += self._check_new_links(graph)
        anomalies += self._check_fi(scan_result, graph)
        anomalies += self._check_error_rate(graph)
        anomalies += self._check_sub_agents(graph)
        anomalies += self._check_node_count(graph)
        anomalies.sort(key=lambda a: _ORDER[a.severity])
        return AnomalyReport(session_id=graph.session_id or "", anomalies=anomalies,
                             baseline_source=self.source, learned_from=self.baseline.learned_from)

    # --------------------------------------------------------------- checks
    def _new_tool_names(self, graph: AgentGraph) -> set[str]:
        return {n.name for n in graph.nodes.values() if n.kind == "tool"} - self.baseline.known_tools

    def _check_new_tools(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag any tool not in baseline.known_tools. Severity: critical."""
        out = []
        for name in sorted(self._new_tool_names(graph)):
            nid = next(i for i, n in graph.nodes.items() if n.kind == "tool" and n.name == name)
            callers = sorted({e.source for e in graph.edges if e.target == nid})
            out.append(Anomaly(
                CRITICAL, "new_tool", f"New tool never seen: {name}", name,
                f"not in {len(self.baseline.known_tools)} known tools", None,
                f"{graph.nodes[nid].call_count} call(s) by {', '.join(callers) or '-'}"))
        return out

    def _check_new_links(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag any (source, target) link not in baseline.known_links. Severity: warning.

        Links to a new tool are covered by the new_tool anomaly and not repeated.
        """
        new_tools = {f"tool:{t}" for t in self._new_tool_names(graph)}
        links = {(node_role(graph, e.source), node_role(graph, e.target)) for e in graph.edges}
        out = []
        for s, t in sorted(links - self.baseline.known_links):
            if s in new_tools or t in new_tools:
                continue
            out.append(Anomaly(WARNING, "new_link", f"New communication path: {s} -> {t}", f"{s} -> {t}",
                               f"not among {len(self.baseline.known_links)} known links", None))
        return out

    def _check_fi(self, scan_result: ScanResult, graph: AgentGraph | None = None) -> list[Anomaly]:
        """Flag if FI deviates > 2 std from baseline mean.

        Severity: warning past 2 sigma; critical past 3 sigma only when FI rose
        (redundancy lost).
        """
        b = self.baseline
        fi = scan_result.fi
        z = _z(fi, b.fi_mean, b.fi_std)
        if z is None:
            if abs(fi - b.fi_mean) <= _EPS:
                return []
            severity = WARNING
        elif abs(z) <= 2:
            return []
        else:
            severity = CRITICAL if z > 3 else WARNING
        if fi < b.fi_mean:
            agents = sum(1 for n in graph.nodes.values() if n.kind == "agent") if graph else 0
            detail = ("Sub-agents detected — shared tools add triangles; structural change expected"
                      if agents else "More redundant than usual: new cross-links between agents or tools")
        else:
            detail = "Redundancy lost: more links without a backup path than usual"
        return [Anomaly(severity, "fi_deviation",
                        f"FI deviation: {fi:.2f} (baseline: {_pm(b.fi_mean, b.fi_std)}"
                        + ("" if z is None else f", z = {z:+.1f}") + ")",
                        fi, _pm(b.fi_mean, b.fi_std), z, detail)]

    def _check_error_rate(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag if error rate is > 2 std above baseline. Warning past 2 sigma, critical past 3."""
        if not graph.total_tool_calls:
            return []
        b = self.baseline
        rate = sum(n.error_count for n in graph.nodes.values()) / graph.total_tool_calls
        z = _z(rate, b.error_rate_mean, b.error_rate_std)
        if z is None:
            if rate <= b.error_rate_mean + _EPS:
                return []
            severity = WARNING
        elif z <= 2:
            return []
        else:
            severity = CRITICAL if z > 3 else WARNING
        return [Anomaly(severity, "error_rate",
                        f"Error rate: {rate:.1%} (baseline: {_pm(b.error_rate_mean, b.error_rate_std, pct=True)}"
                        + ("" if z is None else f", z = {z:+.1f}") + ")",
                        rate, _pm(b.error_rate_mean, b.error_rate_std, pct=True), z,
                        f"Elevated error rate across {graph.total_tool_calls} tool calls")]

    def _check_sub_agents(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag if sub-agent count exceeds max_seen or is > 2 std above the mean.

        Severity: warning; critical when above max_seen and more than 3 sigma.
        """
        b = self.baseline
        count = sum(1 for n in graph.nodes.values() if n.kind == "agent")
        z = _z(count, b.sub_agent_count_mean, b.sub_agent_count_std)
        above_max = count > b.max_sub_agents_seen
        if not above_max and (z is None or z <= 2):
            return []
        severity = CRITICAL if above_max and z is not None and z > 3 else WARNING
        types = sorted({node_role(graph, n) for n, node in graph.nodes.items() if node.kind == "agent"})
        return [Anomaly(severity, "sub_agents",
                        f"Sub-agents: {count} (baseline: {_pm(b.sub_agent_count_mean, b.sub_agent_count_std)}, "
                        f"max seen {b.max_sub_agents_seen})",
                        count, f"{_pm(b.sub_agent_count_mean, b.sub_agent_count_std)}, max {b.max_sub_agents_seen}",
                        z, f"Types: {', '.join(types)}")]

    def _check_node_count(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag if total node count deviates > 2 std. Info past 2 sigma, warning past 3."""
        b = self.baseline
        count = len(graph.nodes)
        z = _z(count, b.node_count_mean, b.node_count_std)
        if z is None:
            if abs(count - b.node_count_mean) <= _EPS:
                return []
            severity = INFO
        elif abs(z) <= 2:
            return []
        else:
            severity = WARNING if abs(z) > 3 else INFO
        return [Anomaly(severity, "node_count",
                        f"Node count: {count} (baseline: {_pm(b.node_count_mean, b.node_count_std)}"
                        + ("" if z is None else f", z = {z:+.1f}") + ")",
                        count, _pm(b.node_count_mean, b.node_count_std), z,
                        "System is larger than usual" if count > b.node_count_mean else "System is smaller than usual")]
