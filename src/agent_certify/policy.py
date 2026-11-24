# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Policy engine: explicit organisational rules for an agent system.

Anomalies say "this is unusual". A policy says "this is not allowed" (or "this
must be there"), whatever the statistics. A session can have both.

Rule kinds:

====================  ============================  =================================
kind                  target                        violated when
====================  ============================  =================================
``forbidden_tool``    tool pattern                  a matching tool is used
``forbidden_link``    ``"source-pattern → target"``  a matching link exists
``max_sub_agents``    integer                       more sub-agents than that
``required_tool``     tool pattern                  no matching tool is used
``forbidden_region``  country codes, comma-         a destination is in one of
                      separated (``"CN,RU"``)       those countries
====================  ============================  =================================

Patterns are shell-style globs (``*``, ``?``), case-insensitive, matched
against a node's id (``tool:Bash``), its type (``agent:Explore``) and its name
(``Bash``). So ``bash``, ``tool:Bash`` and ``B*`` all match Bash, and
``agent:*`` matches every sub-agent. Links accept ``→`` or ``->``.

**Regions.** ``forbidden_region`` reads the countries of the session's network
destinations (:mod:`agent_certify.regions`) and fires on the ones it is given.
Its target is a list of ISO 3166-1 alpha-2 codes; which codes belong there is
an organisation's decision, so no list is built in, and
:class:`PolicyGenerator` never drafts this rule. The violation says **how** the
country was determined — a ccTLD, a local address database, or a name resolved
over the network — because the three are not equally strong.

A destination whose country cannot be determined is **ignored** by default: a
``.com`` is nothing but a name unless something resolves it, and failing a
session for every unresolvable host would make the rule unusable. Set
``unknown_region`` to ``"warning"`` on the rule to hear about them instead.

The region of a destination is decided **offline** unless the operator asks for
more: a resolver is passed in by whoever has one (``agent-certify scan
--geoip-db``, and ``--resolve-dns`` for names), and the default resolver reads
ccTLDs and nothing else. :meth:`Policy.check` never resolves a name on its own,
which is what lets the MCP server call it (``SECURITY.md`` §1).
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
from agent_certify.paths import ensure_state_dir
from agent_certify.regions import OFFLINE, RegionResolver

DEFAULT_POLICY_PATH = Path(".agent-certify") / "policy.json"
KINDS = ("forbidden_tool", "forbidden_link", "max_sub_agents", "required_tool", "forbidden_region")
SEVERITIES = ("critical", "warning")

#: What a ``forbidden_region`` rule does about a destination whose country is
#: unknown: nothing (the default), or report it at warning.
UNKNOWN_REGION_ACTIONS = ("ignore", "warning")


def split_regions(target: str) -> list[str]:
    """``"CN, ru,BY"`` as ``["BY", "CN", "RU"]``. Raises ``ValueError`` on anything else.

    Codes are upper-cased and sorted so a rule reads the same however it was
    typed, and the error names what was expected: a rule an operator cannot
    spell is worse than one they are told how to spell.
    """
    codes = sorted({code.strip().upper() for code in (target or "").split(",") if code.strip()})
    if not codes:
        raise ValueError('forbidden_region needs country codes, e.g. "CN,RU" (ISO 3166-1 alpha-2)')
    bad = [code for code in codes if len(code) != 2 or not code.isalpha()]
    if bad:
        raise ValueError(f"not ISO 3166-1 alpha-2 country code(s): {', '.join(bad)}; "
                         'expected two letters each, e.g. "CN,RU"')
    return codes


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
    kind: str              # one of KINDS
    target: str            # tool pattern, link "source → target", number, or country codes
    severity: str          # "critical", "warning"
    message: str           # human description
    #: ``forbidden_region`` only: what to do about a destination whose country
    #: is unknown — ``"ignore"`` (the default) or ``"warning"``.
    unknown_region: str = "ignore"

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"unknown rule kind {self.kind!r}; expected one of {', '.join(KINDS)}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"rule severity must be one of {', '.join(SEVERITIES)}, not {self.severity!r}")
        if self.unknown_region not in UNKNOWN_REGION_ACTIONS:
            raise ValueError(f"unknown_region must be one of {', '.join(UNKNOWN_REGION_ACTIONS)}, "
                             f"not {self.unknown_region!r}")
        if self.kind == "forbidden_link":
            _split_link(self.target)
        if self.kind == "max_sub_agents":
            int(self.target)
        if self.kind == "forbidden_region":
            split_regions(self.target)

    @property
    def regions(self) -> list[str]:
        """The country codes of a ``forbidden_region`` rule."""
        return split_regions(self.target) if self.kind == "forbidden_region" else []

    def describe(self) -> str:
        label = {"forbidden_tool": "FORBIDDEN", "forbidden_link": "FORBIDDEN LINK",
                 "max_sub_agents": "MAX SUB-AGENTS", "required_tool": "REQUIRED",
                 "forbidden_region": "FORBIDDEN REGION"}[self.kind]
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

    def check(self, graph: AgentGraph, regions: RegionResolver | None = None) -> list[PolicyViolation]:
        """Check all rules against a graph. Return violations.

        ``regions`` decides the country of a destination for
        ``forbidden_region`` rules. The default resolves **offline** and reads
        ccTLDs only: a caller that has a local address database, or has been
        told to resolve names, passes its own
        (:class:`~agent_certify.regions.RegionResolver`). Nothing here reaches
        the network on its own.
        """
        violations = []
        tools = [nid for nid, n in graph.nodes.items() if n.kind == "tool"]
        resolver = regions or OFFLINE
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
            elif rule.kind == "forbidden_region":
                violations += self._region_violations(rule, graph, resolver)
            elif rule.kind == "required_tool" and not any(matches(rule.target, graph, nid) for nid in tools):
                violations.append(PolicyViolation(
                    rule=rule,
                    observed=f"Tool {rule.target} not found",
                    severity=rule.severity,
                    message=f"REQUIRED tool missing: {rule.target}"))
        violations.sort(key=lambda v: SEVERITIES.index(v.severity))
        return violations

    @staticmethod
    def _region_violations(rule: PolicyRule, graph: AgentGraph,
                           resolver: RegionResolver) -> list[PolicyViolation]:
        """One violation per destination in a forbidden country (and, if asked, per unknown one)."""
        forbidden = set(rule.regions)
        out = []
        for host in sorted(graph.seen_domains):
            region = resolver.region(host)
            callers = ", ".join(graph.domain_callers(host)) or "caller not recorded"
            if region.country in forbidden:
                out.append(PolicyViolation(
                    rule=rule, severity=rule.severity,
                    observed=f"{host} is in {region.describe()}, reached by {callers}",
                    message=f"FORBIDDEN region {region.country}: {host} ({region.describe()})"))
            elif not region.known and rule.unknown_region == "warning":
                out.append(PolicyViolation(
                    rule=rule, severity="warning",
                    observed=f"{host} reached by {callers}; no ccTLD, no address database match"
                             + ("" if resolver.resolve_dns else ", and names are not resolved"),
                    message=f"Region unknown for {host}: cannot say whether it is in {rule.target}"))
        return out

    def to_dict(self) -> dict:
        # unknown_region is written only when it is not the default, so a policy
        # file keeps the four fields it has always had unless a rule needs the fifth.
        return {"rules": [{k: v for k, v in asdict(r).items()
                           if k != "unknown_region" or v != "ignore"} for r in self.rules],
                "generated_from": self.generated_from, "created_at": self.created_at}

    def save(self, path: str | os.PathLike | None = None) -> Path:
        """Write the policy as human-editable JSON (default: .agent-certify/policy.json)."""
        p = Path(path) if path is not None else DEFAULT_POLICY_PATH
        ensure_state_dir(p)
        p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | os.PathLike) -> Policy:
        """Read a policy file. Raises ``ValueError`` for anything that is not a valid policy.

        Errors about individual rules name the rule's kind or severity (useful to
        whoever edits the file); the MCP server replaces every load error with a
        generic message.
        """
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ValueError("Invalid policy format (not JSON)") from None
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ValueError("Invalid policy format (no 'rules' list)")  # noqa: TRY004 — one error type for bad files
        for key in ("generated_from", "created_at"):
            if data.get(key) is not None and not isinstance(data[key], str):
                raise ValueError("Invalid policy format")
        required = {"kind", "target", "severity", "message"}
        allowed = required | {"unknown_region"}
        rules = []
        for r in data["rules"]:
            if not (isinstance(r, dict) and required <= set(r) <= allowed
                    and all(isinstance(v, str) for v in r.values())):
                raise ValueError("Invalid policy format (each rule needs string kind, target, severity, message)")
            rules.append(PolicyRule(**r))
        return cls(rules=rules, generated_from=data.get("generated_from"), created_at=data.get("created_at"))


def _reject_constant(name: str):
    raise ValueError("Invalid policy format")


class PolicyGenerator:
    """Auto-generate a draft policy from a learned baseline.

    The draft is deliberately conservative: a human edits it, adds FORBIDDEN
    rules (``deploy_production``, ``agent:* → *database*``...), adjusts
    thresholds and deletes rules they don't want. New tools and new links are
    already flagged by anomaly detection, so the draft does not repeat them.

    It never drafts a ``forbidden_region`` rule. Which countries an
    organisation will not send data to is a decision with legal weight, and
    nothing in a baseline implies it: a tool that guessed at that list would be
    making the decision for its operator, and would be wrong somewhere.
    """

    def suggest(self, baseline: Baseline) -> Policy:
        """Generate conservative policy rules from baseline statistics.

        - tools seen in every session -> REQUIRED (warning), unless rejected
        - sub-agents: more than baseline max + 1 -> warning, max + 3 -> critical
        """
        rules = []
        for tool, freq in sorted(baseline.tool_frequency.items()):
            # A rejected tool must never become normal, and a REQUIRED rule is
            # the strongest possible statement that it is.
            if tool in baseline.rejected_tools:
                continue
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
