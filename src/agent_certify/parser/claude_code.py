"""Claude Code session parser.

Claude Code writes one JSONL transcript per session under
``~/.claude/projects/<project>/<session-id>.jsonl``. Each line is a record such
as ``{"type": "assistant", "message": {"role": "assistant", "content": [...]}}``.
Assistant content holds ``tool_use`` blocks (``id``, ``name``, ``input``); user
content holds the matching ``tool_result`` blocks (``tool_use_id``,
``is_error``). One assistant message may be streamed over several records, so
tool calls are de-duplicated by their ``id``.

Sub-agents spawned through the ``Agent`` (formerly ``Task``) tool keep their own
transcript in ``<session-id>/subagents/agent-<agent-id>.jsonl``, with a
``.meta.json`` beside it naming the ``toolUseId`` that spawned it. The parser
follows those links, so a session's graph contains every sub-agent and every
tool it used. Tools are shared nodes: when the orchestrator and a sub-agent
both call ``Bash``, both edges end at ``tool:Bash``.

Node ids: ``human``, ``claude`` (the orchestrator), ``agent:<agent-id>``,
``tool:<tool-name>``.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser

logger = logging.getLogger(__name__)

HUMAN = "human"
ORCHESTRATOR = "claude"

# Tools that spawn a sub-agent. Matching on "agent"/"Task" substrings would also
# catch TaskStop, TaskList, ListAgents..., which manage agents but spawn none.
SPAWN_TOOLS = {"Agent", "Task"}


def tool_id(name: str) -> str:
    return f"tool:{name}"


def agent_id(aid: str) -> str:
    return f"agent:{aid}"


class ClaudeCodeParser(BaseParser):
    """Parse Claude Code JSONL transcripts into agent graphs.

    Usage::

        parser = ClaudeCodeParser()
        graph = parser.parse("~/.claude/projects/-home-me-proj/<session>.jsonl")
        graphs = parser.parse_directory("~/.claude/projects/-home-me-proj/")

    ``include_subagents=False`` ignores sub-agent transcripts; spawned agents
    then appear as leaf nodes. ``include_human=False`` drops the human node.
    After a parse, ``skipped_lines`` holds the number of malformed lines skipped.
    """

    def __init__(self, include_subagents: bool = True, include_human: bool = True):
        self.include_subagents = include_subagents
        self.include_human = include_human
        self.skipped_lines = 0

    # ------------------------------------------------------------------ api
    def parse(self, path: str) -> AgentGraph:
        """Parse a Claude Code JSONL session into an AgentGraph."""
        p = self._expand(path)
        if not p.is_file():
            raise FileNotFoundError(p)
        self.skipped_lines = 0
        g = AgentGraph(session_id=p.stem, project=p.parent.name)
        g.add_node(ORCHESTRATOR, "orchestrator", "claude")
        state = _State()
        sub_dir = p.parent / p.stem / "subagents"
        metas = _load_metas(sub_dir)
        state.spawn_links = {m["toolUseId"]: aid for aid, m in metas.items() if "toolUseId" in m}

        self._read_transcript(p, ORCHESTRATOR, g, state, is_main=True)

        if self.include_subagents and sub_dir.is_dir():
            for f in sorted(sub_dir.glob("agent-*.jsonl")):
                aid = f.stem[len("agent-"):]
                meta = metas.get(aid, {})
                node = agent_id(aid)
                if node not in g.nodes:
                    # Spawned from somewhere the transcripts do not show
                    # (e.g. a workflow script); attach it to the orchestrator.
                    g.add_node(node, "agent", _agent_label(meta.get("agentType"), meta.get("description"), aid),
                               spawned_by="unknown")
                    g.add_call(ORCHESTRATOR, node)
                g.nodes[node].metadata.update({k: meta[k] for k in ("agentType", "description", "spawnDepth")
                                               if k in meta})
                g.nodes[node].metadata["transcript"] = str(f)
                self._read_transcript(f, node, g, state, is_main=False)

        g.total_messages = state.messages
        g.total_tool_calls = len(state.calls)
        if state.first and state.last:
            g.duration_seconds = (state.last - state.first).total_seconds()
            g.started_at = _iso(state.first)
            g.ended_at = _iso(state.last)
        if self.skipped_lines:
            logger.warning("%s: skipped %d malformed line(s)", p, self.skipped_lines)
        return g

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        """Parse all JSONL files in a ``~/.claude/projects/`` subdirectory.

        Given ``~/.claude/projects/`` itself, parses every project under it.
        Sub-agent transcripts are read as part of their parent session, not as
        sessions of their own.
        """
        d = self._expand(directory)
        if not d.is_dir():
            raise NotADirectoryError(d)
        files = sorted(d.glob("*.jsonl"))
        if not files:
            files = sorted(f for sub in sorted(d.iterdir()) if sub.is_dir() for f in sub.glob("*.jsonl"))
        graphs = []
        for f in files:
            try:
                graphs.append(self.parse(str(f)))
            except OSError as exc:
                logger.warning("%s: cannot read (%s)", f, exc)
        return graphs

    # ------------------------------------------------------------ internals
    def _read_transcript(self, path: Path, caller: str, g: AgentGraph, state: _State, is_main: bool) -> None:
        for rec in self._records(path):
            rtype = rec.get("type")
            msg = rec.get("message")
            if rtype not in ("user", "assistant") or not isinstance(msg, dict):
                continue
            state.messages += 1
            ts = _timestamp(rec.get("timestamp"))
            if ts:
                state.first = min(state.first or ts, ts)
                state.last = max(state.last or ts, ts)

            # Old transcripts inline sub-agent ("sidechain") records in the main file.
            who = caller
            if is_main and rec.get("isSidechain"):
                who = agent_id(rec.get("agentId") or "sidechain")
                if who not in g.nodes:
                    g.add_node(who, "agent", who.split(":", 1)[1])
                    g.add_call(ORCHESTRATOR, who)

            content = msg.get("content")
            if rtype == "assistant":
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            self._tool_use(block, who, g, state)
            else:
                self._user(rec, content, who, g, state, is_main)

    def _tool_use(self, block: dict, caller: str, g: AgentGraph, state: _State) -> None:
        call_id = block.get("id")
        name = block.get("name") or "unknown"
        if call_id in state.calls:
            return  # same block re-streamed in a later record
        inp = block.get("input") if isinstance(block.get("input"), dict) else {}
        if name in SPAWN_TOOLS or "subagent_type" in inp:
            linked = state.spawn_links.get(call_id)
            target = agent_id(linked or call_id or f"anon{len(state.calls)}")
            g.add_node(target, "agent", _agent_label(inp.get("subagent_type"), inp.get("description"), linked),
                       spawned_via=name, spawn_call_id=call_id,
                       **({"agentType": inp["subagent_type"]} if inp.get("subagent_type") else {}))
        else:
            target = tool_id(name)
            g.add_node(target, "tool", name)
        g.add_call(caller, target)
        state.calls[call_id or f"anon{len(state.calls)}"] = (caller, target)

    def _user(self, rec: dict, content, caller: str, g: AgentGraph, state: _State, is_main: bool) -> None:
        if isinstance(content, list):
            results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]
            for b in results:
                rid = b.get("tool_use_id")
                if rid in state.results:
                    continue
                state.results.add(rid)
                if b.get("is_error") and rid in state.calls:
                    g.record_error(*state.calls[rid])
            if results:
                return
        # A prompt typed by the person. A sub-agent's first "user" message is
        # its parent's prompt, already covered by the spawn edge.
        if (self.include_human and is_main and caller == ORCHESTRATOR and not rec.get("isMeta")
                and not rec.get("isCompactSummary") and content):
            g.add_node(HUMAN, "human", "human")
            g.add_call(HUMAN, ORCHESTRATOR)

    def _records(self, path: Path) -> Iterator[dict]:
        """Stream records, skipping malformed lines."""
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    self.skipped_lines += 1
                    logger.debug("%s:%d: malformed JSON, skipped", path, lineno)
                    continue
                if isinstance(rec, dict):
                    yield rec
                else:
                    self.skipped_lines += 1


class _State:
    def __init__(self):
        self.messages = 0
        self.calls: dict[str, tuple[str, str]] = {}   # tool_use id -> (caller, target)
        self.results: set[str] = set()
        self.spawn_links: dict[str, str] = {}         # spawning tool_use id -> agent id
        self.first: datetime | None = None
        self.last: datetime | None = None


def _load_metas(sub_dir: Path) -> dict[str, dict]:
    metas = {}
    if not sub_dir.is_dir():
        return metas
    for m in sub_dir.glob("agent-*.meta.json"):
        try:
            metas[m.name[len("agent-"):-len(".meta.json")]] = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("%s: unreadable sub-agent metadata", m)
    return metas


def _agent_label(agent_type: str | None, description: str | None, aid: str | None) -> str:
    parts = [p for p in (agent_type, description) if p]
    if parts:
        return ": ".join(parts)
    return f"agent-{aid}" if aid else "sub-agent"


def _iso(ts: datetime) -> str:
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
