# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Anomaly injection: put a known fault into a clean session.

Detection is only worth what it catches, and the only way to know what a
detector catches is to hand it faults whose answer you already have. Each
injector here takes a parsed session, returns a **copy** with one fault in it,
and says which anomaly that fault should produce:

=====================  =================================  =====================
injector               fault                              should be reported as
=====================  =================================  =====================
``inject_new_tool``    a tool the baseline never saw      ``new_tool``, critical
``inject_error_spike`` failures on existing calls until   ``error_rate``,
                       the error rate reaches ``rate``    warning or worse
``inject_new_agent``   an agent of an unseen type, with   ``new_link``, warning
                       a link to a known tool             or worse
``inject_volume_spike````factor`` times as many calls to  ``call_volume_spike``,
                       one tool                           warning or worse
``inject_forbidden_    a tool the operator rejected       ``new_tool``, critical
tool``                 (needs :meth:`AnomalyInjector.
                       forbid` on the baseline)
``inject_foreign_      a network destination the          ``new_domain``,
domain``               baseline never saw                 critical
=====================  =================================  =====================

The volume spike was a measured blind spot until v0.7.0: no check read how
*often* a tool was called, only whether it was known, who called it and how
often it failed, so a session calling ``Bash`` 500 times instead of 50 passed
clean. The benchmark reported it as a miss for one release, and
``call_volume_spike`` now closes it. The case stays in the suite, which is the
point of keeping a measured gap rather than an omitted one.

Injections are deterministic: errors are spread over the edges in a fixed
order, so the same session always yields the same injected copy and a benchmark
run is reproducible. Every injector raises ``ValueError`` when the fault cannot
be injected into the session it is given (a new tool that is already there, an
error spike on a session with no calls), rather than returning an unchanged
graph that would quietly count as a miss.
"""
from __future__ import annotations

import copy
import math
from dataclasses import dataclass, field

from agent_certify.anomaly import CRITICAL, WARNING
from agent_certify.baseline import Baseline
from agent_certify.domains import normalise_pattern
from agent_certify.graph import AgentGraph

#: Default names for the things injections add. They name the benchmark on
#: purpose: if one shows up in a report of real traffic, it came from here.
NEW_TOOL = "bench_unseen_tool"
NEW_AGENT = "bench_unseen_agent"
FOREIGN_DOMAIN = "api.unknown.cn"

#: Every anomaly type the benchmark covers, in report order.
ANOMALY_TYPES = ("new_tool", "error_spike", "new_agent", "volume_spike", "forbidden_tool",
                 "foreign_domain")


@dataclass
class Injection:
    """One injected session and the anomaly it is expected to produce.

    ``expected_category`` is None for a fault no check covers (a blind spot),
    in which case the expected outcome is that nothing is reported.
    ``min_severity`` is the *least* severe report that still counts as a
    detection: a fault expected at warning is also detected when it comes back
    critical.
    """
    kind: str
    graph: AgentGraph
    expected_category: str | None = None
    min_severity: str | None = None
    baseline: Baseline | None = None          # overrides the benchmark's baseline for this injection
    note: str = ""
    detail: dict = field(default_factory=dict)

    @property
    def is_blind_spot(self) -> bool:
        """True when no check covers this fault, so the expected outcome is silence."""
        return self.expected_category is None


class AnomalyInjector:
    """Inject known faults into clean sessions.

    Usage::

        injector = AnomalyInjector()
        noisy = injector.inject_error_spike(session, rate=0.15)
        for injection in injector.injections(session, baseline):
            injection.kind, injection.graph, injection.expected_category

    Every method leaves its input untouched and returns a deep copy with the
    fault in it. The copy's ``session_id`` gets a ``+<kind>`` suffix, and each
    node or edge the injection added carries ``metadata["injected"] = "<kind>"``,
    so an injected graph is never mistaken for a real one.
    """

    def __init__(self, new_tool: str = NEW_TOOL, new_agent: str = NEW_AGENT,
                 foreign_domain: str = FOREIGN_DOMAIN):
        self.new_tool = new_tool
        self.new_agent = new_agent
        self.foreign_domain = foreign_domain

    # ------------------------------------------------------------ injectors
    def inject_new_tool(self, session: AgentGraph, tool_name: str | None = None) -> AgentGraph:
        """Add a call to a tool the session never used (and a baseline never saw)."""
        name = tool_name or self.new_tool
        g = self._copy(session, "new_tool")
        nid = f"tool:{name}"
        if nid in g.nodes:
            raise ValueError(f"{name!r} is already a tool in this session; pick a name it does not use")
        caller = self._caller(g)
        g.add_node(nid, "tool", name, injected="new_tool")
        g.add_call(caller, nid)
        g.total_tool_calls += 1
        return g

    def inject_error_spike(self, session: AgentGraph, rate: float = 0.15) -> AgentGraph:
        """Fail existing invocations until the session's error rate reaches ``rate``.

        No new node or edge appears: only the error counts move, which is what
        a degrading dependency looks like.
        """
        if not 0 < rate <= 1:
            raise ValueError(f"rate must be in (0, 1], got {rate!r}")
        g = self._copy(session, "error_spike")
        if not g.total_tool_calls:
            raise ValueError("session has no tool calls; nothing to fail")
        have = sum(n.error_count for n in g.nodes.values())
        need = math.ceil(rate * g.total_tool_calls) - have
        if need <= 0:
            raise ValueError(f"session already fails {have}/{g.total_tool_calls} calls, at or above {rate:.0%}")
        capacity = sum(max(0, e.weight - e.errors) for e in g.edges)
        if need > capacity:
            raise ValueError(f"need {need} more failed call(s) to reach {rate:.0%}, "
                             f"but only {capacity} invocation(s) can still fail")
        left = need
        while left:                                   # round-robin in edge order, so the result is reproducible
            for edge in g.edges:
                if not left:
                    break
                if edge.errors < edge.weight:
                    g.record_error(edge.source, edge.target)
                    left -= 1
        g.nodes[self._caller(g)].metadata["injected"] = "error_spike"
        return g

    def inject_new_agent(self, session: AgentGraph, agent_name: str | None = None) -> AgentGraph:
        """Add an agent of a type the baseline never saw, calling a tool it knows.

        The link to a known tool is what makes this realistic — and detectable:
        a brand-new agent type creates invocation paths
        (``orchestrator -> agent:<type>``, ``agent:<type> -> tool:<known>``)
        that no baseline has learned.
        """
        name = agent_name or self.new_agent
        g = self._copy(session, "new_agent")
        nid = f"agent:{name}"
        # The id and the type are both checked: a Claude Code sub-agent's id is
        # unique per spawn and its type lives in the metadata, so an id that is
        # free does not mean the type is new — and only a new type produces the
        # unseen invocation paths this injection is meant to test.
        types = {n.metadata.get("agentType") for n in g.nodes.values() if n.kind == "agent"}
        if nid in g.nodes or name in types:
            raise ValueError(f"{name!r} is already an agent type in this session; pick one it does not use")
        caller = self._caller(g)
        g.add_node(nid, "agent", name, agentType=name, injected="new_agent")
        g.add_call(caller, nid)
        g.total_tool_calls += 1
        busiest = self._busiest_tool(g)
        if busiest:
            g.add_call(nid, busiest)
            g.total_tool_calls += 1
        return g

    def inject_volume_spike(self, session: AgentGraph, tool: str, factor: int = 10) -> AgentGraph:
        """Multiply the calls to one tool by ``factor``, changing nothing else.

        ``tool`` is a node id or a display name (``"tool:Bash"`` or ``"Bash"``).
        Nothing else moves: no new node, no new link, no extra failure — the
        only thing out of place is how much the tool is used, which is what
        ``call_volume_spike`` reads.
        """
        if factor <= 1:
            raise ValueError(f"factor must be greater than 1, got {factor!r}")
        g = self._copy(session, "volume_spike")
        nid = g.resolve(tool)                         # KeyError when the session never used it
        if g.nodes[nid].kind != "tool":
            raise ValueError(f"{tool!r} is a {g.nodes[nid].kind}, not a tool")
        added = 0
        for edge in g.edges:
            if edge.target != nid:
                continue
            extra = edge.weight * (factor - 1)
            edge.weight += extra
            added += extra
        if not added:
            raise ValueError(f"nothing calls {tool!r} in this session")
        g.nodes[nid].call_count += added
        g.nodes[nid].metadata["injected"] = "volume_spike"
        g.total_tool_calls += added
        return g

    def inject_forbidden_tool(self, session: AgentGraph, tool_name: str) -> AgentGraph:
        """Use a tool the operator has rejected.

        The rejection lives in the baseline, not in the session, so pair this
        with :meth:`forbid`::

            graph = injector.inject_forbidden_tool(session, "deploy_prod")
            baseline = injector.forbid(baseline, "deploy_prod")

        A tool the session already calls is left where it is (the fault is the
        rejection, not the call); one it does not call is added.
        """
        name = (tool_name or "").strip()
        if not name:
            raise ValueError("tool_name is required: a forbidden tool has to be named")
        g = self._copy(session, "forbidden_tool")
        nid = f"tool:{name}"
        if nid not in g.nodes:
            caller = self._caller(g)
            g.add_node(nid, "tool", name)
            g.add_call(caller, nid)
            g.total_tool_calls += 1
        g.nodes[nid].metadata["injected"] = "forbidden_tool"
        return g

    def inject_foreign_domain(self, session: AgentGraph, domain: str | None = None) -> AgentGraph:
        """Point an existing tool at a network destination the baseline never saw.

        Nothing structural changes — the same tools, the same links, the same
        call counts — which is the case for it: a tool reconfigured to talk to
        another host looks identical in the topology, and only the recorded
        destination gives it away.
        """
        name = (domain or self.foreign_domain).strip().lower()
        if not name:
            raise ValueError("domain is required: a foreign destination has to be named")
        g = self._copy(session, "foreign_domain")
        if name in g.seen_domains:
            raise ValueError(f"{name!r} is already a destination in this session; pick one it does not use")
        target = self._busiest_tool(g) or self._caller(g)
        g.record_domains(target, {name})
        g.nodes[target].metadata["injected"] = "foreign_domain"
        return g

    # ------------------------------------------------------------- baseline
    @staticmethod
    def forbid_domain(baseline: Baseline, pattern: str) -> Baseline:
        """A copy of ``baseline`` in which ``pattern`` is a rejected destination.

        The destination is also marked known, for the same reason
        :meth:`forbid` marks a rejected tool known: otherwise the anomaly
        measured would be ``new_domain``, and the operator's decision would
        never be exercised.
        """
        b = copy.deepcopy(baseline)
        stored = normalise_pattern(pattern)
        b.rejected_domains = set(b.rejected_domains) | {stored}
        b.accepted_domains = set(b.accepted_domains) - {stored}
        if not stored.startswith("*."):
            b.known_domains = set(b.known_domains) | {stored}
        return b

    @staticmethod
    def forbid(baseline: Baseline, tool_name: str) -> Baseline:
        """A copy of ``baseline`` in which ``tool_name`` is rejected *and* known.

        Known as well as rejected on purpose: a tool the baseline never saw
        would be a ``new_tool`` anomaly anyway, and then the benchmark would be
        measuring the wrong check. Here the only reason to report it is the
        operator's decision.
        """
        b = copy.deepcopy(baseline)
        b.known_tools = set(b.known_tools) | {tool_name}
        b.rejected_tools = set(b.rejected_tools) | {tool_name}
        b.accepted_tools = set(b.accepted_tools) - {tool_name}
        return b

    # ------------------------------------------------------------- registry
    def injections(self, session: AgentGraph, baseline: Baseline) -> list[Injection]:
        """Every injection this module can make into ``session``, with its expected anomaly.

        Faults that do not apply to the session are left out (and named in the
        returned list's absence rather than raising): a session with no tool
        calls gets no error spike, one with no tools no volume spike.
        """
        out: list[Injection] = []
        self._add(out, "new_tool", lambda: self.inject_new_tool(session), "new_tool", CRITICAL,
                  f"a tool named {self.new_tool!r}, never seen in the baseline")
        self._add(out, "error_spike", lambda: self.inject_error_spike(session), "error_rate", WARNING,
                  "existing calls failed until the error rate reaches 15%")
        self._add(out, "new_agent", lambda: self.inject_new_agent(session), "new_link", WARNING,
                  f"an agent of unseen type {self.new_agent!r} calling a known tool")
        busiest = self._busiest_tool(session)
        if busiest:
            name = session.nodes[busiest].name
            self._add(out, "volume_spike", lambda: self.inject_volume_spike(session, busiest, factor=10),
                      "call_volume_spike", WARNING, f"10x the calls to {name!r}")
            self._add(out, "forbidden_tool", lambda: self.inject_forbidden_tool(session, name),
                      "new_tool", CRITICAL, f"{name!r} rejected by the operator",
                      baseline=self.forbid(baseline, name))
        self._add(out, "foreign_domain", lambda: self.inject_foreign_domain(session),
                  "new_domain", CRITICAL, f"a tool pointed at {self.foreign_domain}")
        return out

    @staticmethod
    def _add(out: list, kind: str, build, category, severity, note, baseline: Baseline | None = None) -> None:
        try:
            graph = build()
        except (ValueError, KeyError):
            return                      # this fault does not apply to this session
        out.append(Injection(kind=kind, graph=graph, expected_category=category, min_severity=severity,
                             baseline=baseline, note=note))

    # ------------------------------------------------------------ internals
    @staticmethod
    def _copy(session: AgentGraph, kind: str) -> AgentGraph:
        g = copy.deepcopy(session)
        g.session_id = f"{session.session_id or 'session'}+{kind}"
        return g

    @staticmethod
    def _caller(g: AgentGraph) -> str:
        """The node a new call comes from: the orchestrator, or the first agent when there is none."""
        for kind in ("orchestrator", "agent"):
            found = sorted(nid for nid, n in g.nodes.items() if n.kind == kind)
            if found:
                return found[0]
        raise ValueError("session has no orchestrator or agent to attribute a call to")

    @staticmethod
    def _busiest_tool(g: AgentGraph) -> str | None:
        """The most-called tool, by call count then by id, so the choice is deterministic."""
        tools = [(n.call_count, nid) for nid, n in g.nodes.items() if n.kind == "tool"]
        return max(tools, key=lambda t: (t[0], t[1]))[1] if tools else None
