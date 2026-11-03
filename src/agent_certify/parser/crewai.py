# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""CrewAI execution log parser.

`CrewAI <https://crewai.com>`_ runs a *crew*: a set of agents, each with a
``role``, working through a list of tasks and calling tools. A crew writes its
execution log as JSON (``Crew(output_log_file="run.json")``), and its event bus
(``ToolUsageStartedEvent``, ``TaskCompletedEvent``, ...) is commonly dumped to
JSONL. Both are read here, as is a single JSON object wrapping the entries in a
list (``{"events": [...]}``).

Records are matched on their *content*, not on a schema version, because the
log layout differs between CrewAI versions and between the log file and the
event bus. A record is read when it names an agent and at least one of a task,
a tool, a crew or a status::

    {"timestamp": "2026-11-03 10:00:00", "agent": "Researcher",
     "task": "Find the 2026 numbers", "status": "started"}
    {"timestamp": "2026-11-03 10:00:04", "agent_role": "Researcher",
     "tool_name": "search_web", "tool_args": {"q": "..."}, "status": "completed"}
    {"event": "tool_usage_error", "agent_role": "Researcher",
     "tool_name": "search_web", "error": "HTTP 503"}
    {"event": "crew_kickoff_started", "crew": "ResearchCrew", "inputs": {"topic": "x"}}

Accepted spellings: the agent is ``agent``, ``agent_role``, ``agent_name``,
``role`` or ``agent_key``; the tool ``tool`` or ``tool_name``; the task
``task``, ``task_name`` or ``task_description``; the crew ``crew`` or
``crew_name``. An entry failed when it carries an ``error``, when ``status`` is
``failed``/``error``, or when its event name mentions a failure.

The graph
---------

====================================  ==========================================
log content                           graph
====================================  ==========================================
the crew itself                       ``crew`` (orchestrator)
``inputs`` on a kickoff               ``human`` -> ``crew``
each agent role                       ``agent:<role>``
a task assigned to an agent           ``crew`` -> ``agent:<role>``, weight =
                                      number of distinct tasks
a tool call by an agent               ``agent:<role>`` -> ``tool:<name>``
delegation (``Delegate work to        ``agent:<from>`` -> ``agent:<coworker>``,
coworker``, ``Ask question to         besides the tool edge itself
coworker``)
====================================  ==========================================

Node ids are the roles themselves (``agent:Researcher``), so an agent keeps its
identity across runs and a baseline can be learned over a crew's history — the
same reason :meth:`AgentGraph.role` maps Claude Code's per-spawn agent ids onto
their type.

A call is counted once even when the log holds both a start and a finish record
for it: records are paired by ``tool_call_id``/``id``/``run_id`` when one is
present, and by (agent, tool, task) otherwise. A log that only records
completions therefore counts the same as one that records both.
"""
from __future__ import annotations

import logging
from datetime import datetime

from agent_certify.domains import extract_call_domains
from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser, iso, read_records, to_datetime
from agent_certify.paths import MAX_FILES

logger = logging.getLogger(__name__)

CREW = "crew"                      # the orchestrator node
HUMAN = "human"

_AGENT_KEYS = ("agent", "agent_role", "agent_name", "role", "agent_key")
_TOOL_KEYS = ("tool", "tool_name")
_TASK_KEYS = ("task", "task_name", "task_description")
_CREW_KEYS = ("crew", "crew_name")
_ID_KEYS = ("tool_call_id", "call_id", "id", "run_id", "task_id")
_EVENT_KEYS = ("event", "event_type", "type", "status")
_ARG_KEYS = ("tool_args", "args", "arguments", "input", "tool_input")
_RESULT_KEYS = ("output", "result", "observation", "response", "content", "tool_output")
_COWORKER_KEYS = ("coworker", "co_worker", "agent")

#: Tool names through which a CrewAI agent hands work to another agent.
DELEGATION_TOOLS = {"delegate work to coworker", "delegate work to co-worker",
                    "ask question to coworker", "ask question to co-worker"}

_STARTED = ("started", "start", "running", "in_progress", "begin")
_FINISHED = ("completed", "complete", "finished", "finish", "done", "success", "succeeded")
_FAILED = ("failed", "failure", "error", "exception", "timeout")


def _text(value) -> str:
    """A log field as a trimmed string; non-strings and blanks become ``""``."""
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _first(rec: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        text = _text(rec.get(k))
        if text:
            return text
    return ""


def _event_words(rec: dict) -> str:
    """Every event/status-ish field of a record, lowercased, for keyword matching.

    Empty when the record carries none of them: a blank join would be a
    whitespace string, which is truthy, and a record holding nothing but an
    agent name would then look like a CrewAI record.
    """
    return " ".join(filter(None, (_text(rec.get(k)) for k in _EVENT_KEYS))).lower()


def looks_like_crewai_record(rec) -> bool:
    """True for a record this parser can read; used by :mod:`agent_certify.parser.auto`.

    A Claude Code transcript record carries a ``message`` object and is never
    claimed here, however it is otherwise shaped.
    """
    if not isinstance(rec, dict) or "message" in rec:
        return False
    words = _event_words(rec)
    if _first(rec, _AGENT_KEYS):
        return bool(_first(rec, _TOOL_KEYS) or _first(rec, _TASK_KEYS) or _first(rec, _CREW_KEYS) or words)
    # A crew-level record names no agent: only a kickoff-style event counts.
    return bool(_first(rec, _CREW_KEYS)) and ("crew" in words or "kickoff" in words)


def _status(rec: dict) -> str:
    """``"started"``, ``"finished"``, ``"failed"``, or ``""`` when the record says nothing."""
    if rec.get("error") not in (None, "", False) or rec.get("is_error") is True:
        return "failed"
    words = _event_words(rec)
    if any(w in words for w in _FAILED):
        return "failed"
    if any(w in words for w in _FINISHED):
        return "finished"
    if any(w in words for w in _STARTED):
        return "started"
    return ""


class CrewAIParser(BaseParser):
    """Parse a CrewAI execution log into an :class:`AgentGraph`.

    Usage::

        parser = CrewAIParser()
        graph = parser.parse("run.json")
        graphs = parser.parse_directory("logs/")

    ``include_human=False`` drops the ``human`` node. After a parse,
    ``skipped_records`` (also ``graph.skipped_records``) counts the records that
    could not be read: malformed JSON, or an entry this parser does not
    recognise.
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
        g.add_node(CREW, "orchestrator", "crew")
        state = _State()

        for rec in read_records(p):
            self.records_seen += 1
            if not looks_like_crewai_record(rec):
                self.skipped_records += 1
                continue
            state.messages += 1
            self._stamp(rec, state)
            self._record(g, rec, state)

        if state.crew_name:
            g.nodes[CREW].name = state.crew_name
            g.nodes[CREW].metadata["crew"] = state.crew_name
        g.total_messages = state.messages
        g.total_tool_calls = state.tool_calls
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
        """Parse every ``*.json`` and ``*.jsonl`` log in ``directory`` that holds CrewAI records."""
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
        crew = _first(rec, _CREW_KEYS)
        if crew and not state.crew_name:
            state.crew_name = crew
        if self.include_human and not state.human_linked and self._is_kickoff(rec):
            g.add_node(HUMAN, "human", "human")
            g.add_call(HUMAN, CREW)
            state.human_linked = True

        role = _first(rec, _AGENT_KEYS)
        agent = self._agent_node(g, role) if role else None
        tool = _first(rec, _TOOL_KEYS)
        task = _first(rec, _TASK_KEYS)
        if tool:
            self._tool_call(g, rec, state, agent or CREW, tool)
        elif task and agent:
            self._task(g, rec, state, agent, task)

    @staticmethod
    def _is_kickoff(rec: dict) -> bool:
        words = _event_words(rec)
        return "kickoff" in words or (isinstance(rec.get("inputs"), dict) and bool(rec["inputs"]))

    @staticmethod
    def _agent_node(g: AgentGraph, role: str) -> str:
        nid = f"agent:{role}"
        if nid not in g.nodes:
            g.add_node(nid, "agent", role, agentType=role, framework="crewai")
        return nid

    def _tool_call(self, g: AgentGraph, rec: dict, state: _State, caller: str, tool: str) -> None:
        target = f"tool:{tool}"
        g.add_node(target, "tool", tool)
        status = _status(rec)
        key = (caller, target, _first(rec, _ID_KEYS) or _first(rec, _TASK_KEYS))
        if status == "failed":
            if state.open.pop(key, None) is not None:
                g.record_error(caller, target)      # the start of this call was already counted
            else:
                g.add_call(caller, target, error=True)
                state.tool_calls += 1
        elif status == "finished" and state.open.pop(key, None) is not None:
            pass                                    # start already counted; nothing new happened
        else:
            g.add_call(caller, target)
            state.tool_calls += 1
            if status == "started":
                state.open[key] = True
        destinations = extract_call_domains(_call_payload(rec), _call_result(rec))
        if destinations:
            g.record_domains(target, destinations)
        self._delegation(g, rec, caller, tool)

    def _delegation(self, g: AgentGraph, rec: dict, caller: str, tool: str) -> None:
        """Link an agent to the coworker it handed work to."""
        if tool.strip().lower() not in DELEGATION_TOOLS or not caller.startswith("agent:"):
            return
        args = next((rec[k] for k in _ARG_KEYS if isinstance(rec.get(k), dict)), None)
        coworker = _first(args, _COWORKER_KEYS) if args else ""
        if not coworker:
            return
        target = self._agent_node(g, coworker)
        if target != caller:                        # self-delegation is not a link
            g.add_call(caller, target)

    @staticmethod
    def _task(g: AgentGraph, rec: dict, state: _State, agent: str, task: str) -> None:
        """A task assigned to an agent: one ``crew -> agent`` invocation per distinct task."""
        status = _status(rec)
        key = (agent, task)
        if status == "failed":
            if key in state.tasks:
                g.record_error(CREW, agent)
            else:
                g.add_call(CREW, agent, error=True)
                state.tasks.add(key)
        elif key not in state.tasks:
            g.add_call(CREW, agent)
            state.tasks.add(key)
        tasks = g.nodes[agent].metadata.setdefault("tasks", [])
        if task not in tasks:
            tasks.append(task)


def _call_payload(rec: dict) -> dict:
    """A tool record without what the tool returned: the call, as the agent made it."""
    return {k: v for k, v in rec.items() if k not in _RESULT_KEYS}


def _call_result(rec: dict) -> dict | None:
    """What the tool returned, if the record carries it."""
    out = {k: rec[k] for k in _RESULT_KEYS if k in rec}
    return out or None


class _State:
    def __init__(self):
        self.messages = 0
        self.tool_calls = 0
        self.open: dict[tuple[str, str, str], bool] = {}    # started tool calls awaiting their result
        self.tasks: set[tuple[str, str]] = set()            # (agent, task) pairs already counted
        self.crew_name = ""
        self.human_linked = False
        self.first: datetime | None = None
        self.last: datetime | None = None
