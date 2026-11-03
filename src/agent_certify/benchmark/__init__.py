# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Anomaly injection benchmark: what the detector actually catches.

A detector that has never been measured is a claim, not a feature. This
package injects faults whose answer is known into clean sessions and scores
:mod:`agent_certify.anomaly` against them:

* :class:`~agent_certify.benchmark.injector.AnomalyInjector` — one method per
  fault (new tool, error spike, new agent, volume spike, forbidden tool,
  foreign domain, shell-command domain), each returning a copy of the session
  with that fault in it;
* :class:`~agent_certify.benchmark.runner.BenchmarkRunner` — injects every
  fault into every session, runs the checks and reports detection rate, false
  positive rate, false negative rate and blind spots, per fault type;
* :mod:`agent_certify.benchmark.synthetic` — varied clean sessions, so the
  suite runs with no logs at hand.

Run the whole thing with ``python -m agent_certify.benchmark`` (add
``--format json`` for a machine-readable report, or ``--sessions PATH`` to
benchmark against real logs instead of synthetic ones).

Two results are worth knowing before reading any number.

**Call volume was a blind spot, and is covered since v0.7.0.** Until then no
check read how *often* a tool was called, so a tool called ten times as usual
was not reported; the benchmark measured that gap for one release rather than
leaving the case out, and ``call_volume_spike`` closed it. The injection stays
in the suite, now as a covered fault.

**One blind spot is open: a host named in a shell command.** Extraction reads
destinations from URLs and from fields that name a host, so
``{"command": "curl -sS collector.example.net/x"}`` — a bare host inside an
argument that names no destination — reaches nobody's baseline and fires no
anomaly. That is a deliberate trade (see :mod:`agent_certify.domains`: a
domain-looking word anywhere is not a destination), and the ``shell_domain``
injection measures it instead of asserting it. It is counted separately so it
neither inflates the detection rate nor drops out of the report, and it turns
into a detection the day extraction reaches that far.
"""
from agent_certify.benchmark.injector import (
    ANOMALY_TYPES,
    BLIND_SPOTS,
    AnomalyInjector,
    Injection,
)
from agent_certify.benchmark.runner import (
    SEVERITY_ORDER,
    BenchmarkResult,
    BenchmarkRunner,
    TypeResult,
    learn_holdout,
)
from agent_certify.benchmark.synthetic import clean_session, clean_sessions

__all__ = ["ANOMALY_TYPES", "BLIND_SPOTS", "SEVERITY_ORDER", "AnomalyInjector", "BenchmarkResult", "BenchmarkRunner",
           "Injection", "TypeResult", "clean_session", "clean_sessions", "learn_holdout"]
