# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Run the anomaly injection benchmark and print the summary table.

Injects every fault in :mod:`agent_certify.benchmark.injector` into every clean
session, runs the anomaly checks against a baseline learned from the sessions
that were held back, and reports detection rate, false positive rate, false
negative rate and blind spots per fault type.

    python scripts/benchmark.py                          # 12 synthetic sessions
    python scripts/benchmark.py --count 40               # more of them
    python scripts/benchmark.py --sessions ~/.claude/projects/C--dev-x
    python scripts/benchmark.py --format json > bench.json

The same suite runs as ``python -m agent_certify.benchmark``; this script is
the copy that comes with the repository, so the numbers in CHANGELOG and README
can be reproduced from a checkout.
"""
import sys

from agent_certify.benchmark.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
