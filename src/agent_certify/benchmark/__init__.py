# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Anomaly injection benchmark: what the detector actually catches.

A detector that has never been measured is a claim, not a feature. This
package injects faults whose answer is known into clean sessions and scores
:mod:`agent_certify.anomaly` against them:

* :class:`~agent_certify.benchmark.injector.AnomalyInjector` — one method per
  fault (new tool, error spike, new agent, volume spike, forbidden tool), each
  returning a copy of the session with that fault in it;
* :class:`~agent_certify.benchmark.runner.BenchmarkRunner` — injects every
  fault into every session, runs the checks and reports detection rate, false
  positive rate, false negative rate and blind spots, per fault type;
* :mod:`agent_certify.benchmark.synthetic` — varied clean sessions, so the
  suite runs with no logs at hand.

Run the whole thing with ``python -m agent_certify.benchmark`` (add
``--format json`` for a machine-readable report, or ``--sessions PATH`` to
benchmark against real logs instead of synthetic ones).

One result is worth knowing before reading any number: **no check reads call
volume**, so a tool called ten times as often as usual is not reported. The
benchmark counts that as a blind spot rather than leaving the case out.
"""
from agent_certify.benchmark.injector import ANOMALY_TYPES, AnomalyInjector, Injection
from agent_certify.benchmark.runner import (
    SEVERITY_ORDER,
    BenchmarkResult,
    BenchmarkRunner,
    TypeResult,
    learn_holdout,
)
from agent_certify.benchmark.synthetic import clean_session, clean_sessions

__all__ = ["ANOMALY_TYPES", "SEVERITY_ORDER", "AnomalyInjector", "BenchmarkResult", "BenchmarkRunner",
           "Injection", "TypeResult", "clean_session", "clean_sessions", "learn_holdout"]
