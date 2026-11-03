# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Anomaly detection against a learned baseline.

Each check compares one aspect of a session with the :class:`Baseline`:

==============  =========================================  ======================
check           flags                                      severity
==============  =========================================  ======================
new_tool        a tool never seen in the baseline, or one   critical
                the operator rejected
new_link        an invocation path never seen (by role)    warning
fi_deviation    FI more than 2 sigma from the mean         warning; critical past
                                                           3 sigma when FI *rose*
error_rate      error rate more than 2 sigma *above*       warning; critical past
                                                           3 sigma
sub_agents      more sub-agents than ever seen, or 2 sigma  warning; critical when
                above the mean                             above max *and* 3 sigma
node_count      node count more than 2 sigma from mean     info; warning past 3
call_volume_    a tool, or one link to it, called more      warning past 3 sigma;
spike           often than 3 sigma above the mean          critical past 5
new_domain      a network destination never seen, and not   critical
                accepted
rejected_domain a destination matching a rejected pattern  critical
==============  =========================================  ======================

**Call volume** answers a question the other checks do not: not *whether* a
tool was used but *how much*. A tool whose calls jump from 50 to 500 is known,
reaches no new path and may fail no more often than usual, so until v0.7 it
passed every check — the injection benchmark measured that blind spot before
this check closed it.

Volume is compared per link first and per tool second, and a tool is not
reported when a link to it already is: if one agent is responsible, the
message should name that agent rather than the tool everyone shares. A tool or
link the baseline never saw has no volume to deviate from, and is the business
of ``new_tool`` / ``new_link`` instead. Only increases are reported — a quiet
session is not a risk.

**Network destinations** come from the session's own logs (see
:mod:`agent_certify.domains`). ``accepted_domains`` and ``rejected_domains``
are patterns, with the precedence that applies to tools: a rejected pattern
fires even for a host the baseline has learned, and even if a pattern accepts
it too.

Three baseline overrides change what ``new_tool`` and ``new_link`` consider
normal, and they are decisions rather than statistics, so they win over what was
learned: ``accepted_tools`` silences a tool, ``rejected_tools`` makes one fire
however often it has been seen, and ``accepted_links`` silences one
(source role, target role) pair. Acceptance of a link is **scoped** — if a tool
is new and only some of its callers are covered by an accepted link, the
``new_tool`` anomaly still fires and names the callers that are not.

A falling FI means added redundancy (usually sub-agents sharing tools), a
structural change worth knowing about but not a risk in itself, so it never
goes past warning. When the baseline never varied on a metric (std 0), z is
undefined: any difference is reported with ``z_score=None`` at the lower
severity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from agent_certify.baseline import Baseline, link_volume, node_role
from agent_certify.domains import matching_pattern
from agent_certify.graph import AgentGraph
from agent_certify.scanner import ScanResult

CRITICAL, WARNING, INFO = "critical", "warning", "info"
_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
_CATEGORICAL = {"new_tool", "new_link", "new_domain", "rejected_domain"}
_EPS = 1e-9

#: Call volume past this many deviations above the mean is a warning, and past
#: :data:`VOLUME_SIGMA_CRITICAL` a critical.
VOLUME_SIGMA_WARNING = 3.0
VOLUME_SIGMA_CRITICAL = 5.0

#: When a baseline never varied on a key (one session, or always the same
#: count), there is no sigma to compare against. A multiple of the mean stands
#: in for it: the same fallback the other checks make at the lower severity.
VOLUME_RATIO_WARNING = 2.0


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
        anomalies += self._check_call_volume(graph)
        anomalies += self._check_domains(graph)
        anomalies.sort(key=lambda a: _ORDER[a.severity])
        return AnomalyReport(session_id=graph.session_id or "", anomalies=anomalies,
                             baseline_source=self.source, learned_from=self.baseline.learned_from)

    # --------------------------------------------------------------- checks
    def _uncovered_callers(self, graph: AgentGraph, tool_id: str) -> list[str]:
        """Caller roles of ``tool_id`` that no accepted link covers.

        This is what makes ``baseline accept --link`` scoped: approving
        ``agent:Build -> tool:deploy_staging`` leaves every other caller of that
        tool uncovered, so the tool still gets flagged and the message says who
        is responsible.
        """
        accepted = self.baseline.accepted_links
        callers = {node_role(graph, e.source) for e in graph.edges if e.target == tool_id}
        return sorted(c for c in callers if (c, tool_id) not in accepted)

    def _new_tool_names(self, graph: AgentGraph) -> set[str]:
        """Tools that should be flagged, after the operator's decisions are applied.

        A rejected tool is returned even when the baseline has learned it, which
        is the whole point of rejecting: a re-learn that saw it in every session
        must not make it normal.
        """
        b = self.baseline
        present = {n.name for n in graph.nodes.values() if n.kind == "tool"}
        return (present - b.known_tools - b.accepted_tools) | (present & b.rejected_tools)

    def _check_new_tools(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag any tool the baseline does not vouch for. Severity: critical."""
        out = []
        for name in sorted(self._new_tool_names(graph)):
            nid = next(i for i, n in graph.nodes.items() if n.kind == "tool" and n.name == name)
            rejected = name in self.baseline.rejected_tools
            uncovered = self._uncovered_callers(graph, nid)
            if not rejected and not uncovered:
                continue        # every caller is covered by an accepted link
            callers = sorted({e.source for e in graph.edges if e.target == nid})
            detail = f"{graph.nodes[nid].call_count} call(s) by {', '.join(callers) or '-'}"
            if rejected:
                message = f"Rejected tool used: {name}"
                reference = "explicitly rejected by the operator"
                detail += " — rejected, so it stays an anomaly across re-learns"
            else:
                message = f"New tool never seen: {name}"
                reference = f"not in {len(self.baseline.known_tools)} known tools"
                if self.baseline.accepted_links:
                    detail += f" — not covered by an accepted link: {', '.join(uncovered)}"
            out.append(Anomaly(CRITICAL, "new_tool", message, name, reference, None, detail))
        return out

    def _check_new_links(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag any (source, target) link the baseline does not allow. Severity: warning.

        Allowed means learned (``known_links``) or accepted (``accepted_links``).
        Links to a flagged tool are covered by the new_tool anomaly and not
        repeated.
        """
        new_tools = {f"tool:{t}" for t in self._new_tool_names(graph)}
        links = {(node_role(graph, e.source), node_role(graph, e.target)) for e in graph.edges}
        allowed = self.baseline.known_links | self.baseline.accepted_links
        out = []
        for s, t in sorted(links - allowed):
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

    # ------------------------------------------------------------ volume
    def _volume_verdict(self, count: int, stats: dict) -> tuple[str, float | None, str] | None:
        """(severity, z, how the baseline reads) for a count, or None when it is normal.

        Past :data:`VOLUME_SIGMA_WARNING` deviations above the mean it is a
        warning, past :data:`VOLUME_SIGMA_CRITICAL` a critical. With no
        deviation to compare against, :data:`VOLUME_RATIO_WARNING` times the
        mean stands in, reported at warning with no z-score — the same thing
        the other checks do when the baseline never varied.
        """
        mean, std = float(stats.get("mean", 0.0)), float(stats.get("std", 0.0))
        sessions = int(stats.get("sessions", 0) or 0)
        if std > _EPS:
            z = (count - mean) / std
            if z <= VOLUME_SIGMA_WARNING:
                return None
            # Both bounds are exclusive, as "past 3 sigma" and "past 5" say:
            # exactly 5.0 sigma is a warning, not a critical.
            severity = CRITICAL if z > VOLUME_SIGMA_CRITICAL else WARNING
            return severity, z, f"{mean:.0f} ± {std:.0f}"
        if mean <= _EPS or count <= VOLUME_RATIO_WARNING * mean:
            return None
        return WARNING, None, (f"{mean:.0f} in {sessions} session(s), no variation to compare against; "
                               f"flagged past {VOLUME_RATIO_WARNING:g}x")

    def _volume_anomaly(self, subject: str, count: int, stats: dict, detail: str) -> Anomaly | None:
        verdict = self._volume_verdict(count, stats)
        if verdict is None:
            return None
        severity, z, reference = verdict
        sigma = f", {z:.1f}σ" if z is not None else ""
        return Anomaly(severity, "call_volume_spike",
                       f"{subject} called {count} times (baseline: {reference}{sigma})",
                       count, reference, z, detail)

    def _check_call_volume(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag tools and links used far more than the baseline ever saw.

        Links are checked first, and a link spike replaces the tool-level one
        only when it adds something: if a tool has several callers, naming the
        one responsible is the useful message, and the innocent callers are
        still compared against their own links. When a tool has a single
        caller, the two carry identical information and the anomaly is reported
        about the tool.
        """
        caller_roles: dict[str, set[str]] = {}
        for e in graph.edges:
            caller_roles.setdefault(e.target, set()).add(node_role(graph, e.source))
        out, explained = [], set()
        for key, count in sorted(link_volume(graph).items()):
            stats = self.baseline.volume("link", key)
            if stats is None:
                continue                       # an unlearned link is new_link's business
            source, target = key.split(" -> ", 1)
            # `target` comes from a link_volume key, so it is a *role*, while
            # caller_roles is keyed by node *id*. The lookup is valid because a
            # tool's role is its id (see :meth:`AgentGraph.role`), which is also why
            # this branch only applies to "tool:" targets.
            if target.startswith("tool:") and len(caller_roles.get(target, ())) < 2:
                continue                       # one caller: the tool-level anomaly says the same thing
            anomaly = self._volume_anomaly(f"Link {key}", count, stats,
                                           f"{source} alone accounts for this; other callers of "
                                           f"{target} are compared separately")
            if anomaly is not None:
                out.append(anomaly)
                if target.startswith("tool:"):
                    explained.add(target[len("tool:"):])
        for node in sorted(graph.nodes.values(), key=lambda n: n.id):
            if node.kind != "tool" or node.name in explained:
                continue
            stats = self.baseline.volume("tool", node.name)
            if stats is None:
                continue                       # an unlearned tool is new_tool's business
            node_callers = sorted({e.source for e in graph.edges if e.target == node.id})
            anomaly = self._volume_anomaly(f"Tool {node.name}", node.call_count, stats,
                                           f"called by {', '.join(node_callers) or '-'}")
            if anomaly is not None:
                out.append(anomaly)
        return out

    # ------------------------------------------------------------ domains
    def _check_domains(self, graph: AgentGraph) -> list[Anomaly]:
        """Flag network destinations that are new, or that an operator rejected.

        A rejected pattern wins over everything learned or accepted, exactly as
        a rejected tool does: the point of rejecting a destination is that no
        amount of traffic to it makes it normal.

        The messages say "network destination … in tool call" and not "HTTP
        call … detected", because that is all that was seen: a host name among
        a tool call's arguments (or its result, when the arguments already
        pointed somewhere). No connection is observed, no name is resolved, the
        scheme need not be HTTP — ``ws://``, ``ftp://`` and a bare
        ``{"host": …}`` field all land here — and nothing says the call
        succeeded or was even attempted.
        """
        b = self.baseline
        out = []
        for domain in sorted(graph.seen_domains):
            callers = graph.domain_callers(domain)
            detail = f"reached by {', '.join(callers)}" if callers else "no caller recorded"
            rejected = matching_pattern(domain, b.rejected_domains)
            if rejected:
                unknown = "not in baseline, " if domain not in b.known_domains else ""
                out.append(Anomaly(CRITICAL, "rejected_domain",
                                   f"Network destination {domain} in tool call — {unknown}"
                                   f"matches rejected pattern {rejected}",
                                   domain, f"rejected pattern {rejected}", None,
                                   detail + " — rejected, so it stays an anomaly across re-learns"))
                continue
            if domain in b.known_domains or matching_pattern(domain, b.accepted_domains):
                continue
            out.append(Anomaly(CRITICAL, "new_domain",
                               f"Network destination {domain} in tool call — not in baseline",
                               domain, f"not among {len(b.known_domains)} known destination(s)", None, detail))
        return out

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
