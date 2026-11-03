# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""LangGraph trace parser.

`LangGraph <https://langchain-ai.github.io/langgraph/>`_ runs a state machine:
named **nodes** take the state, change it, and hand control to the next node.
Traces come out of it in three shapes, and all three are read here, from a
``.jsonl`` stream, a JSON array, or an object wrapping the records in a list.

**1. Event stream** (``graph.astream_events(..., version="v2")``), the richest
form. ``metadata.langgraph_node`` says which node a record belongs to and
``metadata.langgraph_triggers`` which node handed control to it::

    {"event": "on_chain_start", "name": "LangGraph", "data": {"input": {...}}}
    {"event": "on_chain_start", "name": "agent", "run_id": "r1",
     "metadata": {"langgraph_node": "agent", "langgraph_step": 1,
                  "langgraph_triggers": ["start:agent"]}}
    {"event": "on_tool_start", "name": "search", "run_id": "r2",
     "metadata": {"langgraph_node": "tools"}, "data": {"input": {"q": "x"}}}
    {"event": "on_tool_error", "name": "search", "run_id": "r2",
     "metadata": {"langgraph_node": "tools"}, "data": {"error": "HTTP 503"}}

**2. Debug stream** (``stream_mode="debug"``)::

    {"type": "task", "timestamp": "...", "step": 1,
     "payload": {"id": "...", "name": "agent", "triggers": ["start:agent"]}}
    {"type": "task_result", "step": 1, "payload": {"name": "agent", "error": null}}

**3. Plain transition records**, the shape a hand-rolled logger usually
writes — a node, where it went next, and what it called::

    {"timestamp": "...", "node": "agent", "next": "tools",
     "tool_calls": [{"name": "search", "id": "c1"}]}

The graph
---------

===============================  ===============================================
trace content                    graph
===============================  ===============================================
the compiled graph               ``graph`` (orchestrator)
the input it was invoked with     ``human`` -> ``graph``
each node that ran                ``agent:<node>``
a state transition                ``agent:<from>`` -> ``agent:<to>``, weight =
                                  number of times control took that path
``__start__`` as the source       ``graph`` -> ``agent:<node>``
a tool invocation                 ``agent:<node>`` -> ``tool:<name>``
an error on either                error count on that edge
===============================  ===============================================

A node is modelled as an ``agent`` with its name as the agent type, so
``agent:tools`` is stable across runs and baselines can be learned over a
graph's history. A node and the tools it calls are different nodes: the
``tools`` node of a ReAct graph is ``agent:tools``, the tool it ran is
``tool:search``.

``__start__`` is the orchestrator and ``__end__`` is dropped: it is a sentinel,
not a participant. A node transitioning to itself (a node that loops) adds no
edge, since a self-loop carries no structural information — the repeat is
visible in the node's call count.

Transitions come from ``langgraph_triggers``/``triggers`` when the trace has
them, from an explicit ``next``/``to``, and otherwise from the order the nodes
ran in. The last of those is a guess: parallel branches interleave, so a trace
without triggers can show a transition that the graph definition does not have.
Tool calls are counted once whether the trace holds a start, an end, or both.
"""
from __future__ import annotations

import logging
from datetime import datetime

from agent_certify.domains import extract_call_domains
from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser, iso, read_records, to_datetime
from agent_certify.paths import MAX_FILES

logger = logging.getLogger(__name__)

GRAPH = "graph"                    # the orchestrator node
HUMAN = "human"
START, END = "__start__", "__end__"

_NODE_KEYS = ("node", "langgraph_node", "node_name")
_TOOL_KEYS = ("tool", "tool_name")
_SOURCE_KEYS = ("from", "source", "previous", "prev_node", "parent_node")
_TARGET_KEYS = ("next", "to", "next_node", "goto")
_TRIGGER_KEYS = ("langgraph_triggers", "triggers")
_ID_KEYS = ("run_id", "tool_call_id", "call_id", "id")
_INPUT_KEYS = ("input", "inputs")
_OUTPUT_KEYS = ("output", "outputs", "result", "error")

_TOOL_EVENTS = ("on_tool_start", "on_tool_end", "on_tool_error", "on_tool_stream")
_END_EVENTS = ("on_tool_end", "on_chain_end", "on_llm_end", "on_chat_model_end")
_START_EVENTS = ("on_tool_start", "on_chain_start", "on_llm_start", "on_chat_model_start")


def _text(value) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _first(rec: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        text = _text(rec.get(k))
        if text:
            return text
    return ""


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _metadata(rec: dict) -> dict:
    """A record's LangGraph metadata, wherever the trace shape puts it."""
    meta = _dict(rec.get("metadata"))
    return meta or _dict(_dict(rec.get("payload")).get("metadata"))


def _has_langgraph_meta(rec: dict) -> bool:
    meta = _metadata(rec)
    return any(k.startswith("langgraph_") for k in meta) or any(k.startswith("langgraph_") for k in rec)


def looks_like_langgraph_record(rec) -> bool:
    """True for a record this parser can read; used by :mod:`agent_certify.parser.auto`.

    A Claude Code transcript record carries a ``message`` object and is never
    claimed here.
    """
    if not isinstance(rec, dict) or "message" in rec:
        return False
    if _text(rec.get("event")).startswith("on_"):
        return True
    if _has_langgraph_meta(rec):
        return True
    if _text(rec.get("type")) in ("task", "task_result") and isinstance(rec.get("payload"), dict):
        return True
    if _first(rec, _NODE_KEYS):
        return bool(_first(rec, _TARGET_KEYS) or _first(rec, _SOURCE_KEYS) or _first(rec, _TOOL_KEYS)
                    or rec.get("tool_calls") is not None or rec.get("step") is not None
                    or "error" in rec or "state" in rec)
    return False


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return [value] if value not in (None, "") else []


def trigger_source(trigger: str) -> str:
    """The node a LangGraph trigger string names.

    ``"agent"`` -> ``agent``; ``"start:agent"`` -> ``__start__`` (the graph
    entry); ``"branch:agent:route:tools"`` -> ``agent`` (the node the branch
    left). An unrecognised shape gives ``""``.
    """
    parts = [p for p in _text(trigger).split(":") if p]
    if not parts:
        return ""
    if parts[0] == "start":
        return START
    if parts[0] == "branch":
        return parts[1] if len(parts) > 2 else ""      # branch:<from>:<condition>:<to>
    return parts[0]


class LangGraphParser(BaseParser):
    """Parse a LangGraph trace into an :class:`AgentGraph`.

    Usage::

        parser = LangGraphParser()
        graph = parser.parse("trace.jsonl")
        graphs = parser.parse_directory("traces/")

    ``include_human=False`` drops the ``human`` node. After a parse,
    ``skipped_records`` (also ``graph.skipped_records``) counts the records that
    could not be read: malformed JSON, or an entry this parser does not
    recognise.

    A failing node whose failure cannot be charged to any incoming transition
    is counted in the ``unattributed_errors`` metadata of the ``graph`` node
    and logged at warning level, alongside ``transitions``. The key is absent
    when there were none.
    """

    def __init__(self, include_human: bool = True):
        self.include_human = include_human
        self.skipped_records = 0
        self.records_seen = 0

    # ------------------------------------------------------------------ api
    def parse(self, path: str) -> AgentGraph:
        p = self._expand(path)
        if not p.is_file():
            raise FileNotFoundError(p)
        self.skipped_records = 0
        self.records_seen = 0
        g = AgentGraph(session_id=p.stem, project=p.parent.name)
        g.add_node(GRAPH, "orchestrator", "graph")
        state = _State()

        for rec in read_records(p):
            self.records_seen += 1
            if not looks_like_langgraph_record(rec):
                self.skipped_records += 1
                continue
            state.messages += 1
            self._stamp(rec, state)
            self._record(g, rec, state)

        if state.graph_name:
            g.nodes[GRAPH].name = state.graph_name
            g.nodes[GRAPH].metadata["graph"] = state.graph_name
        g.total_messages = state.messages
        g.total_tool_calls = state.tool_calls
        g.nodes[GRAPH].metadata["transitions"] = state.transitions
        if state.unattributed_errors:
            # A node failure no incoming transition could carry. Reported the
            # same way transitions are, rather than counted into a field
            # nothing reads: a silent loss is the one thing this parser must
            # not produce.
            g.nodes[GRAPH].metadata["unattributed_errors"] = state.unattributed_errors
            logger.warning("%s: %d node error(s) could not be attributed to an incoming transition",
                           p.name, state.unattributed_errors)
        if state.first and state.last:
            g.duration_seconds = (state.last - state.first).total_seconds()
            g.started_at, g.ended_at = iso(state.first), iso(state.last)
        g.skipped_records = self.skipped_records
        g.total_records = self.records_seen
        g.source = str(p)
        if self.skipped_records:
            logger.debug("%s: skipped %d of %d record(s)", p, self.skipped_records, self.records_seen)
        return g

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        """Parse every ``*.json`` and ``*.jsonl`` trace in ``directory`` that holds LangGraph records."""
        d = self._expand(directory)
        if not d.is_dir():
            raise NotADirectoryError(d)
        graphs = []
        for f in sorted(list(d.glob("*.json")) + list(d.glob("*.jsonl")))[:MAX_FILES]:
            try:
                g = self.parse(str(f))
            except OSError as exc:
                logger.warning("%s: cannot read (%s)", f, exc)
                continue
            if g.has_data:
                graphs.append(g)
        return graphs

    # ------------------------------------------------------------ internals
    @staticmethod
    def _stamp(rec: dict, state: _State) -> None:
        ts = to_datetime(rec.get("timestamp") or rec.get("time") or rec.get("ts"))
        if ts is None:
            return
        if state.first is not None and (ts.tzinfo is None) != (state.first.tzinfo is None):
            return                                  # mixed naive/aware stamps: keep the first kind seen
        state.first = min(state.first or ts, ts)
        state.last = max(state.last or ts, ts)

    def _record(self, g: AgentGraph, rec: dict, state: _State) -> None:
        event = _text(rec.get("event"))
        payload = _dict(rec.get("payload"))
        meta = _metadata(rec)
        node = _first(meta, _NODE_KEYS) or _first(payload, _NODE_KEYS) or _first(rec, _NODE_KEYS)
        if not node and _text(rec.get("type")) in ("task", "task_result"):
            node = _text(payload.get("name"))
        if not node and event in ("on_chain_start", "on_chain_end") and not meta:
            self._root(g, rec, state, event)        # the graph itself, not one of its nodes
            return

        here = self._activate(g, rec, payload, state, node) if node else None
        self._targets(g, rec, payload, state, here or GRAPH)
        self._tools(g, rec, state, here or GRAPH, event)
        if self._failed(rec, payload, event) and here and not state.tool_pending:
            self._node_error(g, state, here)

    def _root(self, g: AgentGraph, rec: dict, state: _State, event: str) -> None:
        """A record about the compiled graph itself: its name, and the input it was given."""
        name = _text(rec.get("name"))
        if name and not state.graph_name:
            state.graph_name = name
        data = _dict(rec.get("data"))
        given = any(k in data for k in _INPUT_KEYS) or any(k in rec for k in _INPUT_KEYS)
        if self.include_human and not state.human_linked and event == "on_chain_start" and given:
            g.add_node(HUMAN, "human", "human")
            g.add_call(HUMAN, GRAPH)
            state.human_linked = True

    @staticmethod
    def _node_id(g: AgentGraph, node: str) -> str:
        """The graph node for a LangGraph node name; ``__start__`` is the orchestrator."""
        if node == START:
            return GRAPH
        nid = f"agent:{node}"
        if nid not in g.nodes:
            g.add_node(nid, "agent", node, agentType=node, framework="langgraph")
        return nid

    def _activate(self, g: AgentGraph, rec: dict, payload: dict, state: _State, node: str) -> str | None:
        """Register the node this record belongs to and the transition that reached it."""
        if node == END:
            state.current = None
            return None
        nid = self._node_id(g, node)
        if nid == state.current:
            return nid                              # still the same node running; no new transition
        names = [trigger_source(t) for t in _as_list(_first_value(rec, payload, _TRIGGER_KEYS))]
        names = [n for n in names if n and n != END] or [_first(rec, _SOURCE_KEYS) or _first(payload, _SOURCE_KEYS)]
        sources = [self._node_id(g, n) for n in names if n]
        if not sources and state.last_node:
            sources = [state.last_node]             # order the nodes ran in, as a last resort (already an id)
        for src in sources:
            self._transition(g, state, src, nid)
        if not sources and not g.neighbors(nid):
            self._transition(g, state, GRAPH, nid)  # nothing says how it was reached
        state.current = state.last_node = nid
        return nid

    def _targets(self, g: AgentGraph, rec: dict, payload: dict, state: _State, here: str) -> None:
        """Transitions the record declares outright (``next``, ``to``)."""
        for raw in _as_list(_first_value(rec, payload, _TARGET_KEYS)):
            target = _text(raw)
            if not target or target == END:
                continue
            nid = self._node_id(g, target)
            self._transition(g, state, here, nid)
            state.declared.add((here, nid))

    @staticmethod
    def _transition(g: AgentGraph, state: _State, src: str, dst: str) -> None:
        if src == dst:
            # A node looping on itself is not a link — an edge to itself would
            # be a self-loop the graph model rejects, and it would change the
            # topology for a repetition that adds no path. The repeat is real
            # work all the same, so it shows in the node's call count.
            g.nodes[dst].call_count += 1
            return
        if (src, dst) in state.declared:
            state.declared.discard((src, dst))       # already counted where the trace declared it
            return
        g.add_call(src, dst)
        state.transitions += 1

    def _tools(self, g: AgentGraph, rec: dict, state: _State, caller: str, event: str) -> None:
        """Tool invocations: a tool event, a ``tool`` field, or a ``tool_calls`` list."""
        state.tool_pending = False
        name = _text(rec.get("name")) if event in _TOOL_EVENTS else _first(rec, _TOOL_KEYS)
        if name:
            state.tool_pending = True
            self._tool_call(g, state, caller, name, _first(rec, _ID_KEYS),
                            self._failed(rec, _dict(rec.get("payload")), event),
                            finished=event in _END_EVENTS or _text(rec.get("status")) in ("end", "finished"))
            self._destinations(g, rec, f"tool:{name}")
        for call in _as_list(rec.get("tool_calls")):
            entry = _dict(call)
            tool = _text(entry.get("name")) or _first(entry, _TOOL_KEYS)
            if tool:
                state.tool_pending = True
                self._tool_call(g, state, caller, tool, _first(entry, _ID_KEYS),
                                bool(entry.get("error")), finished=False)
                self._destinations(g, entry, f"tool:{tool}")

    @staticmethod
    def _destinations(g: AgentGraph, rec: dict, target: str) -> None:
        """Network destinations of one tool record: its input, and its output when the input had one."""
        data = _dict(rec.get("data"))
        payload = {k: v for k, v in rec.items() if k != "data"}
        arguments = [payload] + [data[k] for k in _INPUT_KEYS if k in data]
        result = [data[k] for k in _OUTPUT_KEYS if k in data] or None
        found = extract_call_domains(arguments, result)
        if found:
            g.record_domains(target, found)

    @staticmethod
    def _tool_call(g: AgentGraph, state: _State, caller: str, name: str, call_id: str,
                   failed: bool, finished: bool) -> None:
        target = f"tool:{name}"
        g.add_node(target, "tool", name)
        key = (caller, target, call_id)
        if failed:
            if state.open.pop(key, None) is not None:
                g.record_error(caller, target)      # this call was counted when it started
            else:
                g.add_call(caller, target, error=True)
                state.tool_calls += 1
        elif finished and state.open.pop(key, None) is not None:
            pass                                    # start already counted
        else:
            g.add_call(caller, target)
            state.tool_calls += 1
            if not finished:
                state.open[key] = True

    @staticmethod
    def _failed(rec: dict, payload: dict, event: str) -> bool:
        if event.endswith("_error"):
            return True
        for holder in (rec, payload, _dict(rec.get("data"))):
            if holder.get("error") not in (None, "", False) or holder.get("is_error") is True:
                return True
        return _text(rec.get("status")).lower() in ("error", "failed", "failure")

    @staticmethod
    def _node_error(g: AgentGraph, state: _State, nid: str) -> None:
        """Mark the transition that reached a failing node as failed."""
        for edge in reversed(g.edges):
            if edge.target == nid and edge.errors < edge.weight:
                g.record_error(edge.source, nid)
                return
        state.unattributed_errors += 1


def _first_value(rec: dict, payload: dict, keys: tuple[str, ...]):
    """The first of ``keys`` present in the record, its metadata or its payload."""
    for holder in (rec, _metadata(rec), payload):
        for k in keys:
            if holder.get(k) not in (None, "", []):
                return holder[k]
    return None


class _State:
    def __init__(self):
        self.messages = 0
        self.tool_calls = 0
        self.transitions = 0
        self.unattributed_errors = 0
        self.open: dict[tuple[str, str, str], bool] = {}   # started tool calls awaiting their result
        self.declared: set[tuple[str, str]] = set()         # transitions a "next" field already counted
        self.current: str | None = None                     # node the records are currently about
        self.last_node: str | None = None
        self.tool_pending = False                           # this record was about a tool, not its node
        self.graph_name = ""
        self.human_linked = False
        self.first: datetime | None = None
        self.last: datetime | None = None
