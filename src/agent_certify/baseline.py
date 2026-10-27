# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Statistical baseline learned from past sessions.

A :class:`Baseline` summarises what "normal" looks like for a system: the
spread of FI, size, bridges, sub-agent use and error rate over N sessions, and
the set of tools and invocation links ever seen. :mod:`agent_certify.anomaly`
compares new sessions against it.

Sub-agent ids are unique per spawn, so links are recorded by *role*: an agent
node becomes ``agent:<type>`` (``agent:Explore``, ``agent:general-purpose``).
Tools and the orchestrator keep their ids. Standard deviations are population
deviations, so a baseline learned from one session has std 0.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import MISSING, asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from agent_certify.graph import AgentGraph
from agent_certify.paths import ensure_state_dir
from agent_certify.scanner import AgentFIScanner, ScanResult

DEFAULT_BASELINE_PATH = Path(".agent-certify") / "baseline.json"


def node_role(graph: AgentGraph, node_id: str) -> str:
    """Stable identity of a node across sessions (agents by type); see :meth:`AgentGraph.role`."""
    return graph.role(node_id)


def session_features(graph: AgentGraph, scan: ScanResult | None = None) -> dict:
    """The per-session numbers a baseline is built from."""
    scan = scan or AgentFIScanner(graph).scan()
    errors = sum(n.error_count for n in graph.nodes.values())
    return {
        "fi": scan.fi,
        "nodes": scan.node_count,
        "edges": scan.edge_count,
        "bridges": len(scan.bridges),
        "tools": {n.name for n in graph.nodes.values() if n.kind == "tool"},
        "sub_agents": sum(1 for n in graph.nodes.values() if n.kind == "agent"),
        "error_rate": errors / graph.total_tool_calls if graph.total_tool_calls else None,
        "links": {(node_role(graph, e.source), node_role(graph, e.target)) for e in graph.edges},
    }


@dataclass
class Baseline:
    """Statistical baseline learned from N sessions."""
    learned_from: int                    # number of sessions
    period_start: str                    # ISO timestamp of earliest session
    period_end: str                      # ISO timestamp of latest session

    # Structural stats
    fi_mean: float
    fi_std: float
    node_count_mean: float
    node_count_std: float
    edge_count_mean: float
    edge_count_std: float

    # Tool usage
    known_tools: set[str]                # all tools seen across sessions
    tool_frequency: dict[str, float]     # tool -> fraction of sessions it appears in

    # Agent patterns
    sub_agent_count_mean: float
    sub_agent_count_std: float
    max_sub_agents_seen: int

    # Error rates
    error_rate_mean: float               # errors / total_calls
    error_rate_std: float

    # Topology
    known_links: set[tuple[str, str]]    # all (source, target) role links seen
    bridge_count_mean: float
    bridge_count_std: float

    # Metadata
    created_at: str
    version: str = "0.2.0"
    fi_min: float = 0.0
    fi_max: float = 0.0
    session_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["known_tools"] = sorted(self.known_tools)
        d["known_links"] = sorted(list(link) for link in self.known_links)
        d["tool_frequency"] = dict(sorted(self.tool_frequency.items(), key=lambda kv: (-kv[1], kv[0])))
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Baseline:
        """Build a baseline from untrusted JSON data, checking every field.

        Raises ``ValueError("Invalid baseline format")``; the message deliberately
        names no field or value, since the data may not be a baseline at all.
        """
        try:
            _check(isinstance(data, dict))
            names = {f.name for f in fields(cls)}
            required = {f.name for f in fields(cls) if f.default is MISSING and f.default_factory is MISSING}
            _check(set(data) <= names and required <= set(data))
            for key in ("learned_from", "max_sub_agents_seen"):
                _check(_is_count(data[key]))
            for key in ("fi_mean", "fi_std", "node_count_mean", "node_count_std", "edge_count_mean",
                        "edge_count_std", "sub_agent_count_mean", "sub_agent_count_std", "error_rate_mean",
                        "error_rate_std", "bridge_count_mean", "bridge_count_std", "fi_min", "fi_max"):
                if key in data:
                    _check(_is_number(data[key]) and data[key] >= 0)
            for key in ("period_start", "period_end", "created_at", "version"):
                if key in data:
                    _check(isinstance(data[key], str))
            _check(isinstance(data["known_tools"], list) and all(isinstance(t, str) for t in data["known_tools"]))
            _check(isinstance(data["tool_frequency"], dict)
                   and all(isinstance(k, str) and _is_number(v) and 0 <= v <= 1
                           for k, v in data["tool_frequency"].items()))
            _check(isinstance(data["known_links"], list)
                   and all(isinstance(link, list) and len(link) == 2 and all(isinstance(x, str) for x in link)
                           for link in data["known_links"]))
            ids = data.get("session_ids", [])
            _check(isinstance(ids, list) and all(isinstance(x, str) for x in ids))
            data = dict(data)
            data["known_tools"] = set(data["known_tools"])
            data["known_links"] = {tuple(link) for link in data["known_links"]}
            return cls(**data)
        except (TypeError, KeyError, AttributeError):
            raise ValueError("Invalid baseline format") from None


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    a = np.asarray(values, dtype=float)
    return float(a.mean()), float(a.std())


class BaselineLearner:
    """Learn a statistical baseline from multiple sessions.

    Usage::

        learner = BaselineLearner()
        baseline = learner.learn(["~/.claude/projects/C--dev-myproject/"])
        learner.save(baseline)                      # .agent-certify/baseline.json
        baseline = learner.load(".agent-certify/baseline.json")
    """

    def __init__(self, parser=None):
        """If parser is None, auto-detect each input's format (Claude Code, Cursor Agent Trace)."""
        if parser is None:
            from agent_certify.parser import AutoParser
            parser = AutoParser()
        self.parser = parser

    def learn(self, paths: list[str]) -> Baseline:
        """Learn baseline from a list of JSONL session files or directories."""
        if isinstance(paths, (str, os.PathLike)):
            paths = [paths]
        graphs = []
        for raw in paths:
            p = Path(str(raw)).expanduser()      # environment variables are the CLI's job, not the library's
            if p.is_dir():
                graphs += self.parser.parse_directory(str(p))
            elif p.is_file():
                graphs.append(self.parser.parse(str(p)))
            else:
                raise FileNotFoundError(p)
        return self.learn_graphs(graphs)

    def learn_graphs(self, graphs: list[AgentGraph]) -> Baseline:
        """Learn baseline from already-parsed graphs."""
        if not graphs:
            raise ValueError("no sessions to learn from")
        feats = [session_features(g) for g in graphs]
        n = len(feats)

        fi_mean, fi_std = _mean_std([f["fi"] for f in feats])
        nodes_mean, nodes_std = _mean_std([f["nodes"] for f in feats])
        edges_mean, edges_std = _mean_std([f["edges"] for f in feats])
        bridges_mean, bridges_std = _mean_std([f["bridges"] for f in feats])
        agents_mean, agents_std = _mean_std([f["sub_agents"] for f in feats])
        err_mean, err_std = _mean_std([f["error_rate"] for f in feats if f["error_rate"] is not None])

        tool_sessions: dict[str, int] = {}
        for f in feats:
            for t in f["tools"]:
                tool_sessions[t] = tool_sessions.get(t, 0) + 1
        starts = [g.started_at for g in graphs if g.started_at]
        ends = [g.ended_at for g in graphs if g.ended_at]
        from agent_certify import __version__

        return Baseline(
            learned_from=n,
            period_start=min(starts) if starts else "",
            period_end=max(ends) if ends else "",
            fi_mean=fi_mean, fi_std=fi_std,
            node_count_mean=nodes_mean, node_count_std=nodes_std,
            edge_count_mean=edges_mean, edge_count_std=edges_std,
            known_tools=set(tool_sessions),
            tool_frequency={t: c / n for t, c in tool_sessions.items()},
            sub_agent_count_mean=agents_mean, sub_agent_count_std=agents_std,
            max_sub_agents_seen=max(f["sub_agents"] for f in feats),
            error_rate_mean=err_mean, error_rate_std=err_std,
            known_links=set().union(*(f["links"] for f in feats)),
            bridge_count_mean=bridges_mean, bridge_count_std=bridges_std,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            version=__version__,
            fi_min=min(f["fi"] for f in feats),
            fi_max=max(f["fi"] for f in feats),
            session_ids=[g.session_id or "" for g in graphs],
        )

    def save(self, baseline: Baseline, path: str | os.PathLike | None = None) -> Path:
        """Save baseline as JSON, by default to .agent-certify/baseline.json."""
        p = Path(path) if path is not None else DEFAULT_BASELINE_PATH
        ensure_state_dir(p)
        p.write_text(json.dumps(baseline.to_dict(), indent=2), encoding="utf-8")
        return p

    def load(self, path: str | os.PathLike) -> Baseline:
        """Load baseline from JSON."""
        return load_baseline(path)


def load_baseline(path: str | os.PathLike) -> Baseline:
    """Read a baseline written by :meth:`BaselineLearner.save`; NaN and Infinity are rejected."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ValueError("Invalid baseline format") from None
    return Baseline.from_dict(data)


def _reject_constant(name: str):
    raise ValueError("Invalid baseline format")


def _check(ok: bool) -> None:
    if not ok:
        raise ValueError("Invalid baseline format")


def _is_count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
