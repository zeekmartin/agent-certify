# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Run the injection benchmark and report what the detector caught.

:class:`BenchmarkRunner` takes clean sessions and a baseline, asks
:class:`~agent_certify.benchmark.injector.AnomalyInjector` for every fault that
applies to each session, runs the anomaly checks over the result and counts:

* **detection rate** — injected faults reported with the expected anomaly
  category, at the expected severity or worse;
* **false negative rate** — the rest of them (1 − detection rate);
* **false positive rate** — clean sessions, with nothing injected, that the
  checks flag anyway;
* **blind spots** — faults no check covers, counted separately so they neither
  inflate the detection rate nor disappear from the report.

**The baseline must not have been learned from the sessions being tested.** A
baseline learned from exactly the sessions it is then run against reports
nothing on them by construction, and the false positive rate comes out zero
without that meaning anything. :func:`learn_holdout` does the split: it learns
from every other session and benchmarks on the ones left out.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agent_certify.anomaly import CRITICAL, INFO, WARNING, AnomalyDetector, AnomalyReport
from agent_certify.baseline import Baseline, BaselineLearner
from agent_certify.benchmark.injector import ANOMALY_TYPES, AnomalyInjector, Injection
from agent_certify.graph import AgentGraph
from agent_certify.scanner import AgentFIScanner

#: Severities from most to least serious; a fault expected at one is detected at any above it.
SEVERITY_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}


def _rate(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


def _pct(value: float) -> str:
    return f"{value:6.1%}"


@dataclass
class TypeResult:
    """What the checks did with one injected anomaly type, over every trial."""
    kind: str
    expected_category: str | None
    min_severity: str | None
    trials: int = 0
    detected: int = 0
    severities: dict[str, int] = field(default_factory=dict)   # severity -> times the expected anomaly came back
    missed: list[str] = field(default_factory=list)            # session ids where it was not reported
    extra_anomalies: int = 0                                   # other anomalies reported alongside
    note: str = ""

    @property
    def is_blind_spot(self) -> bool:
        return self.expected_category is None

    @property
    def detection_rate(self) -> float:
        return _rate(self.detected, self.trials)

    @property
    def expected(self) -> str:
        if self.is_blind_spot:
            return "(blind spot)"
        return f"{self.expected_category}/{(self.min_severity or '')[:4]}"

    def to_dict(self) -> dict:
        return {"kind": self.kind, "expected_category": self.expected_category,
                "min_severity": self.min_severity, "trials": self.trials, "detected": self.detected,
                "detection_rate": self.detection_rate, "blind_spot": self.is_blind_spot,
                "severities": dict(sorted(self.severities.items())), "missed": self.missed,
                "extra_anomalies": self.extra_anomalies, "note": self.note}


@dataclass
class BenchmarkResult:
    """Per-type and overall results of one benchmark run."""
    per_type: list[TypeResult]
    clean_sessions: int = 0
    clean_flagged: int = 0                     # clean sessions with at least one anomaly
    clean_anomalies: int = 0                   # anomalies over all clean sessions
    learned_from: int = 0

    @property
    def covered(self) -> list[TypeResult]:
        """Types a check is supposed to catch (blind spots excluded)."""
        return [t for t in self.per_type if not t.is_blind_spot]

    @property
    def blind_spots(self) -> list[str]:
        return [t.kind for t in self.per_type if t.is_blind_spot]

    @property
    def trials(self) -> int:
        return sum(t.trials for t in self.covered)

    @property
    def detected(self) -> int:
        return sum(t.detected for t in self.covered)

    @property
    def detection_rate(self) -> float:
        return _rate(self.detected, self.trials)

    @property
    def false_negative_rate(self) -> float:
        return 1.0 - self.detection_rate if self.trials else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Clean sessions flagged, over clean sessions run."""
        return _rate(self.clean_flagged, self.clean_sessions)

    def to_dict(self) -> dict:
        return {"clean_sessions": self.clean_sessions, "clean_flagged": self.clean_flagged,
                "clean_anomalies": self.clean_anomalies, "learned_from": self.learned_from,
                "trials": self.trials, "detected": self.detected,
                "detection_rate": self.detection_rate, "false_negative_rate": self.false_negative_rate,
                "false_positive_rate": self.false_positive_rate, "blind_spots": self.blind_spots,
                "per_type": [t.to_dict() for t in self.per_type]}

    def table(self) -> str:
        """The run as a summary table, for a terminal or a CI log."""
        width = 86
        head = (f"Anomaly injection benchmark — {self.clean_sessions} clean session(s) "
                f"against a baseline of {self.learned_from}")
        lines = [head, "=" * width,
                 f"{'anomaly type':<16}{'expected':<20}{'trials':>7}{'detected':>10}{'rate':>9}  severity",
                 "-" * width]
        for t in self.per_type:
            if t.is_blind_spot:
                severity = "not covered by any check" if not t.detected else "reported anyway"
            else:
                severity = ", ".join(f"{n} {s}" for s, n in sorted(t.severities.items(), key=lambda kv: SEVERITY_ORDER[kv[0]]))
                severity = severity or "-"
            lines.append(f"{t.kind:<16}{t.expected:<20}{t.trials:>7}{t.detected:>10}"
                         f"{_pct(t.detection_rate):>9}  {severity}")
        plural = "y" if self.clean_anomalies == 1 else "ies"
        totals = (f"detection rate {_pct(self.detection_rate).strip()} ({self.detected}/{self.trials})   "
                  f"false negatives {_pct(self.false_negative_rate).strip()}   "
                  f"false positives {_pct(self.false_positive_rate).strip()} "
                  f"({self.clean_flagged}/{self.clean_sessions} clean, "
                  f"{self.clean_anomalies} anomal{plural})")
        lines += ["-" * width, totals]
        if self.blind_spots:
            lines.append("blind spots: " + ", ".join(self.blind_spots)
                         + " — injected and not reported, because no check covers the fault")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.table()


class BenchmarkRunner:
    """Inject every anomaly type into every clean session and score the detector.

    Usage::

        train, test, baseline = learn_holdout(sessions)
        result = BenchmarkRunner(test, baseline).run()
        print(result.table())
        result.detection_rate, result.false_positive_rate
    """

    def __init__(self, sessions: list[AgentGraph], baseline: Baseline,
                 injector: AnomalyInjector | None = None, source: str = "benchmark"):
        if not sessions:
            raise ValueError("no sessions to benchmark")
        self.sessions = list(sessions)
        self.baseline = baseline
        self.injector = injector or AnomalyInjector()
        self.source = source

    def run(self) -> BenchmarkResult:
        """Run the full suite: the clean sessions first, then every injection."""
        results: dict[str, TypeResult] = {}
        clean_flagged = clean_anomalies = 0
        for session in self.sessions:
            report = self.detect(session, self.baseline)
            clean_anomalies += len(report.anomalies)
            clean_flagged += bool(report.anomalies)
            for injection in self.injector.injections(session, self.baseline):
                self._score(results.setdefault(injection.kind, _result_for(injection)), injection)
        order = {kind: i for i, kind in enumerate(ANOMALY_TYPES)}
        per_type = sorted(results.values(), key=lambda t: (t.is_blind_spot, order.get(t.kind, len(order)), t.kind))
        return BenchmarkResult(per_type=per_type, clean_sessions=len(self.sessions), clean_flagged=clean_flagged,
                               clean_anomalies=clean_anomalies, learned_from=self.baseline.learned_from)

    def detect(self, graph: AgentGraph, baseline: Baseline) -> AnomalyReport:
        """Run every anomaly check on one graph."""
        return AnomalyDetector(baseline, self.source).detect(graph, AgentFIScanner(graph).scan())

    # ------------------------------------------------------------ internals
    def _score(self, result: TypeResult, injection: Injection) -> None:
        report = self.detect(injection.graph, injection.baseline or self.baseline)
        result.trials += 1
        hit = next((a for a in report.anomalies
                    if a.category == injection.expected_category
                    and SEVERITY_ORDER[a.severity] <= SEVERITY_ORDER[injection.min_severity or a.severity]), None)
        if injection.is_blind_spot:
            result.detected += bool(report.anomalies)       # anything reported at all is a surprise
            result.extra_anomalies += len(report.anomalies)
            for a in report.anomalies:
                result.severities[a.severity] = result.severities.get(a.severity, 0) + 1
            return
        if hit is None:
            result.missed.append(injection.graph.session_id or "")
        else:
            result.detected += 1
            result.severities[hit.severity] = result.severities.get(hit.severity, 0) + 1
        result.extra_anomalies += len(report.anomalies) - (1 if hit else 0)


def _result_for(injection: Injection) -> TypeResult:
    return TypeResult(kind=injection.kind, expected_category=injection.expected_category,
                      min_severity=injection.min_severity, note=injection.note)


def learn_holdout(sessions: list[AgentGraph], stride: int = 2) -> tuple[list[AgentGraph], list[AgentGraph], Baseline]:
    """Split ``sessions`` into training and held-out sets and learn a baseline from the training one.

    Every ``stride``-th session is held out, so both sets span whatever the
    sessions vary in rather than one set getting all of the small ones.
    Returns ``(train, test, baseline)``.
    """
    if len(sessions) < stride + 1:
        raise ValueError(f"need at least {stride + 1} sessions to hold one out, got {len(sessions)}")
    test = [g for i, g in enumerate(sessions) if i % stride == stride - 1]
    train = [g for i, g in enumerate(sessions) if i % stride != stride - 1]
    return train, test, BaselineLearner().learn_graphs(train)
