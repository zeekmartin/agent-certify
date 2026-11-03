# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""``python -m agent_certify.benchmark`` — run the injection suite and print the table.

With no arguments it benchmarks against synthetic sessions
(:mod:`agent_certify.benchmark.synthetic`), which needs no logs and gives the
same numbers on every machine. ``--sessions PATH`` benchmarks against real
sessions instead: a directory or file in any format the
:class:`~agent_certify.parser.AutoParser` reads.

Either way the baseline is learned from a *held-out* part of the sessions, never
from the ones it is then measured on; see
:func:`~agent_certify.benchmark.runner.learn_holdout`.
"""
from __future__ import annotations

import argparse
import json
import sys

from agent_certify import __version__
from agent_certify.benchmark.runner import BenchmarkRunner, learn_holdout
from agent_certify.benchmark.synthetic import clean_sessions
from agent_certify.graph import AgentGraph
from agent_certify.paths import expand_cli


def _load(path: str) -> list[AgentGraph]:
    from agent_certify.parser import AutoParser

    p = expand_cli(path)
    parser = AutoParser()
    if p.is_dir():
        graphs = parser.parse_directory(str(p))
    elif p.is_file():
        graphs = [parser.parse(str(p))]
    else:
        raise FileNotFoundError(p)
    return [g for g in graphs if g.has_data]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent_certify.benchmark",
                                 description="Inject known anomalies into clean sessions and score the detector.")
    ap.add_argument("--sessions", metavar="PATH",
                    help="directory or file of real sessions to benchmark against (default: synthetic)")
    ap.add_argument("--count", type=int, default=12, metavar="N",
                    help="number of synthetic sessions to generate (default: 12)")
    ap.add_argument("--seed", type=int, help="jitter the synthetic call counts with this seed")
    ap.add_argument("--stride", type=int, default=2, metavar="N",
                    help="hold out every Nth session for testing, learn from the rest (default: 2)")
    ap.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    ap.add_argument("--version", action="version", version=f"agent-certify {__version__}")
    args = ap.parse_args(argv)

    try:
        sessions = _load(args.sessions) if args.sessions else clean_sessions(args.count, seed=args.seed)
        if not sessions:
            print(f"No usable sessions found in {args.sessions}", file=sys.stderr)
            return 1
        train, test, baseline = learn_holdout(sessions, stride=args.stride)
        result = BenchmarkRunner(test, baseline).run()
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        print(f"Cannot read sessions: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Cannot benchmark: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps({"sessions": len(sessions), "learned_from": len(train), **result.to_dict()}, indent=2))
    else:
        print(result.table())
    return 0


if __name__ == "__main__":        # pragma: no cover
    sys.exit(main())
