"""Policy engine: explicit organisational rules for an agent system.

Anomalies say "this is unusual". A policy says "this is not allowed" (or "this
must be there"), whatever the statistics. A session can have both.

Rule kinds:

==================  ==============================  =================================
kind                target                          violated when
==================  ==============================  =================================
``forbidden_tool``  tool pattern                    a matching tool is used
``forbidden_link``  ``"source-pattern → target"``    a matching link exists
``max_sub_agents``  integer                         more sub-agents than that
``required_tool``   tool pattern                    no matching tool is used
==================  ==============================  =================================

Patterns are shell-style globs (``*``, ``?``), case-insensitive, matched
against a node's id (``tool:Bash``), its type (``agent:Explore``) and its name
(``Bash``). So ``bash``, ``tool:Bash`` and ``B*`` all match Bash, and
``agent:*`` matches every sub-agent. Links accept ``→`` or ``->``.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path

from agent_certify.baseline import Baseline
from agent_certify.graph import AgentGraph

DEFAULT_POLICY_PATH = Path(".agent-certify") / "policy.json"
KINDS = ("forbidden_tool", "forbidden_link", "max_sub_agents", "required_tool")
SEVERITIES = ("critical", "warning")


def _split_link(target: str) -> tuple[str, str]:
    for arrow in ("→", "->"):
        if arrow in target:
            source, dest = target.split(arrow, 1)
            return source.strip(), dest.strip()
    raise ValueError(f"link target {target!r} needs 'source → target' (or 'source -> target')")


def matches(pattern: str, graph: AgentGraph, node_id: str) -> bool:
    """True when ``pattern`` matches the node's id, type or name."""
    p = pattern.lower()
    node = graph.nodes[node_id]
    return any(fnmatchcase(c.lower(), p) for c in (node_id, graph.role(node_id), node.name))


@dataclass
class PolicyRule:
    """A single policy rule."""
    kind: str              # "forbidden_tool", "forbidden_link", "max_sub_agents", "required_tool"
    target: str            # tool pattern, link "source → target", or number
    severity: str          # "critical", "warning"
    message: str           # human description

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"unknown rule kind {self.kind!r}; expected one of {', '.join(KINDS)}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"rule severity must be one of {', '.join(SEVERITIES)}, not {self.severity!r}")
        if self.kind == "forbidden_link":
            _split_link(self.target)
        if self.kind == "max_sub_agents":
            int(self.target)

    def describe(self) -> str:
        label = {"forbidden_tool": "FORBIDDEN", "forbidden_link": "FORBIDDEN LINK",
                 "max_sub_agents": "MAX SUB-AGENTS", "required_tool": "REQUIRED"}[self.kind]
        return f"{label}: {self.target}"


@dataclass
class PolicyViolation:
    """A detected policy violation."""
    rule: PolicyRule
    observed: str          # what was actually seen
    severity: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Policy:
    """A set of rules for an agent system."""
    rules: list[PolicyRule]
    generated_from: str | None = None  # baseline description if auto-generated
    created_at: str | None = None

    def check(self, graph: AgentGraph) -> list[PolicyViolation]:
        """Check all rules against a graph. Return violations."""
        violations = []
        tools = [nid for nid, n in graph.nodes.items() if n.kind == "tool"]
        for rule in self.rules:
            if rule.kind == "forbidden_tool":
                for nid in tools:
                    if matches(rule.target, graph, nid):
                        name = graph.nodes[nid].name
                        violations.append(PolicyViolation(
                            rule=rule,
                            observed=f"Tool {name} was used ({graph.nodes[nid].call_count} calls)",
                            severity=rule.severity,
                            message=f"FORBIDDEN tool used: {name}"))
            elif rule.kind == "forbidden_link":
                source, target = _split_link(rule.target)
                for edge in graph.edges:
                    if matches(source, graph, edge.source) and matches(target, graph, edge.target):
                        violations.append(PolicyViolation(
                            rule=rule,
                            observed=f"Link {edge.source} → {edge.target} exists ({edge.weight} calls)",
                            severity=rule.severity,
                            message=f"FORBIDDEN link: {edge.source} → {edge.target}"))
            elif rule.kind == "max_sub_agents":
                agent_count = sum(1 for n in graph.nodes.values() if n.kind == "agent")
                max_allowed = int(rule.target)
                if agent_count > max_allowed:
                    violations.append(PolicyViolation(
                        rule=rule,
                        observed=f"{agent_count} sub-agents (max: {max_allowed})",
                        severity=rule.severity,
                        message=f"Too many sub-agents: {agent_count} > {max_allowed}"))
            elif rule.kind == "required_tool" and not any(matches(rule.target, graph, nid) for nid in tools):
                violations.append(PolicyViolation(
                    rule=rule,
                    observed=f"Tool {rule.target} not found",
                    severity=rule.severity,
                    message=f"REQUIRED tool missing: {rule.target}"))
        violations.sort(key=lambda v: SEVERITIES.index(v.severity))
        return violations

    def to_dict(self) -> dict:
        return {"rules": [asdict(r) for r in self.rules], "generated_from": self.generated_from,
                "created_at": self.created_at}

    def save(self, path: str | os.PathLike | None = None) -> Path:
        """Write the policy as human-editable JSON (default: .agent-certify/policy.json)."""
        p = Path(path) if path is not None else DEFAULT_POLICY_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | os.PathLike) -> Policy:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError(f"{path} is not an agent-certify policy (no 'rules' list)")
        return cls(rules=[PolicyRule(**r) for r in data["rules"]],
                   generated_from=data.get("generated_from"), created_at=data.get("created_at"))


class PolicyGenerator:
    """Auto-generate a draft policy from a learned baseline.

    The draft is deliberately conservative: a human edits it, adds FORBIDDEN
    rules (``deploy_production``, ``agent:* → *database*``...), adjusts
    thresholds and deletes rules they don't want. New tools and new links are
    already flagged by anomaly detection, so the draft does not repeat them.
    """

    def suggest(self, baseline: Baseline) -> Policy:
        """Generate conservative policy rules from baseline statistics.

        - tools seen in every session -> REQUIRED (warning)
        - sub-agents: more than baseline max + 1 -> warning, max + 3 -> critical
        """
        rules = []
        for tool, freq in sorted(baseline.tool_frequency.items()):
            if freq >= 1.0:
                rules.append(PolicyRule(
                    kind="required_tool", target=tool, severity="warning",
                    message=f"{tool} is expected in every session (seen in {freq:.0%} of sessions)"))
        rules.append(PolicyRule(
            kind="max_sub_agents", target=str(baseline.max_sub_agents_seen + 1), severity="warning",
            message=f"Baseline max was {baseline.max_sub_agents_seen}"))
        rules.append(PolicyRule(
            kind="max_sub_agents", target=str(baseline.max_sub_agents_seen + 3), severity="critical",
            message=f"Far exceeds baseline max of {baseline.max_sub_agents_seen}"))
        return Policy(
            rules=rules,
            generated_from=f"baseline ({baseline.learned_from} sessions)",
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
