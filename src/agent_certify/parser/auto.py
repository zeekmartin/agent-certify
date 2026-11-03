# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Input format auto-detection.

Detection looks at the content, not only the extension: Agent Trace's own
storage file is ``.agent-trace/traces.jsonl``, which is as ``.jsonl`` as a
Claude Code transcript, and a CrewAI log is as ``.json`` as anything else in a
project folder.

=====================================  ===================================
input                                  parser
=====================================  ===================================
``*.agent-trace`` / ``.agent-trace/``  :class:`CursorTraceParser`
``*.jsonl`` with trace records         :class:`CursorTraceParser`
``*.jsonl`` with MCP log records       :class:`MCPLogsParser`
``*.json`` / ``*.jsonl`` with CrewAI   :class:`CrewAIParser`
agent/task/tool entries
``*.json`` / ``*.jsonl`` with          :class:`LangGraphParser`
LangGraph node or event records
other ``*.jsonl`` (incl. empty)        :class:`ClaudeCodeParser`
anything else                          ``ValueError``
=====================================  ===================================

The first :data:`MAX_PROBE` records of a file are examined and the first one
that a parser claims decides the format; a file whose records none of them
claim is read as a Claude Code transcript, as it was before the other formats
existed. A ``.jsonl`` file is probed line by line (bounded reads: a huge first
line is skipped), and a ``.json`` file — or a ``.jsonl`` file whose lines are
not records of their own — is read as one document.
"""
from __future__ import annotations

from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser, decode_json, read_records, session_files
from agent_certify.parser.claude_code import ClaudeCodeParser
from agent_certify.parser.crewai import CrewAIParser, looks_like_crewai_record
from agent_certify.parser.cursor_trace import TRACE_DIR, TRACE_SUFFIX, CursorTraceParser, looks_like_trace_record
from agent_certify.parser.langgraph import LangGraphParser, looks_like_langgraph_record
from agent_certify.parser.mcp_logs import MCPLogsParser
from agent_certify.paths import iter_lines

CLAUDE, CURSOR, MCP_LOG, CREWAI, LANGGRAPH = "claude-code", "cursor-agent-trace", "mcp-log", "crewai", "langgraph"

#: Records examined before giving up on recognising a format.
MAX_PROBE = 20

#: Formats whose files a directory scan picks up by content rather than by name.
_DIRECTORY_FORMATS = (CREWAI, LANGGRAPH)


def is_trace_dir(p: Path) -> bool:
    """A ``.agent-trace`` folder, or a repository holding one and no sessions of its own."""
    return p.is_dir() and (p.name == TRACE_DIR or ((p / TRACE_DIR).is_dir() and not any(p.glob("*.jsonl"))))


def looks_like_mcp_record(rec) -> bool:
    return (isinstance(rec, dict) and "sessionId" in rec and "cwd" in rec and "type" not in rec
            and ("debug" in rec or "error" in rec))


def classify(rec) -> str | None:
    """The format one record belongs to, or None when no parser claims it."""
    if looks_like_trace_record(rec):
        return CURSOR
    if looks_like_mcp_record(rec):
        return MCP_LOG
    if looks_like_crewai_record(rec):
        return CREWAI
    if looks_like_langgraph_record(rec):
        return LANGGRAPH
    return None


def detect_format(path: str | Path) -> str:
    """Name of the format at ``path``; raises ``ValueError`` when unsupported."""
    p = Path(path)
    if p.is_dir():
        if is_trace_dir(p):
            return CURSOR
        raise ValueError(f"{p} is a directory; use parse_directory()")
    if p.suffix == TRACE_SUFFIX:
        return CURSOR
    if p.suffix not in (".jsonl", ".json"):
        raise ValueError(f"Unknown format: {p} (expected .jsonl, .json or .agent-trace)")
    fmt = _probe_lines(p) if p.suffix == ".jsonl" else None
    if fmt is None:
        fmt = _probe_document(p)
    return fmt or CLAUDE                            # empty or unrecognised: v0.1 behaviour


def _probe(records) -> str | None:
    """The format of the first record any parser claims; CLAUDE when records were read but none matched."""
    seen = False
    for i, rec in enumerate(records):
        if i >= MAX_PROBE:
            break
        if rec is None:
            continue
        fmt = classify(rec)
        if fmt is not None:
            return fmt
        seen = seen or isinstance(rec, dict)
    return CLAUDE if seen else None


def _probe_lines(p: Path) -> str | None:
    def lines():
        for _, line in iter_lines(p):
            if line is not None and line.strip():
                yield decode_json(line)
    return _probe(lines())


def _probe_document(p: Path) -> str | None:
    try:
        return _probe(read_records(p))
    except OSError:
        return None


class AutoParser(BaseParser):
    """Auto-detect input format and use the right parser.

    Usage::

        AutoParser().parse("session.jsonl")              # Claude Code
        AutoParser().parse(".agent-trace/traces.jsonl")   # Cursor
        AutoParser().parse("crew-run.json")               # CrewAI
        AutoParser().parse("langgraph-trace.jsonl")       # LangGraph
        AutoParser().parse_directory("~/.claude/projects/C--dev-x/")   # every session found
    """

    def __init__(self):
        self.claude = ClaudeCodeParser()
        self.cursor = CursorTraceParser()
        self.mcp = MCPLogsParser()
        self.crewai = CrewAIParser()
        self.langgraph = LangGraphParser()
        self.last_format: str | None = None

    def parse(self, path: str) -> AgentGraph:
        p = self._expand(path)
        if not p.exists():
            raise FileNotFoundError(p)
        if p.is_dir() and not is_trace_dir(p):
            graphs = self.parse_directory(str(p))
            if not graphs:
                raise ValueError(f"no supported sessions under {p}")
            return graphs[0] if len(graphs) == 1 else AgentGraph.merge(graphs, session_id=p.name)
        fmt = detect_format(p)
        self.last_format = fmt
        return self._parser(fmt).parse(str(p))

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        """Every supported session, trace and log under ``directory``.

        Claude Code sessions are found as :meth:`ClaudeCodeParser.parse_directory`
        finds them (``*.jsonl`` here, or one level down). Sub-agent transcripts
        are read with their parent session, and MCP server logs are left out
        (they enrich a session; see ``--include-mcp``). CrewAI and LangGraph
        files are recognised by content, ``*.json`` included, so a folder of
        crew runs can be learned from directly; a ``.json`` file that holds
        neither (``package.json``, say) is ignored.
        """
        d = self._expand(directory)
        if not d.is_dir():
            raise NotADirectoryError(d)
        graphs = []
        for f in session_files(d):
            fmt = detect_format(f)
            if fmt == CLAUDE:
                graphs.append(self.claude.parse(str(f)))
            elif fmt == CURSOR and f.parent.name != TRACE_DIR:
                graphs.append(self.cursor.parse(str(f)))   # a loose traces file; .agent-trace dirs come below
            elif fmt in _DIRECTORY_FORMATS:
                graphs.append(self._parser(fmt).parse(str(f)))
        for f in sorted(d.glob("*.json")):
            fmt = self._try_detect(f)
            if fmt in _DIRECTORY_FORMATS:
                graphs.append(self._parser(fmt).parse(str(f)))
        graphs += [self.cursor.parse(str(t)) for t in self.cursor.find_traces(str(d))]
        return graphs

    # ------------------------------------------------------------ internals
    def _parser(self, fmt: str) -> BaseParser:
        return {CURSOR: self.cursor, MCP_LOG: self.mcp, CREWAI: self.crewai,
                LANGGRAPH: self.langgraph}.get(fmt, self.claude)

    @staticmethod
    def _try_detect(f: Path) -> str | None:
        try:
            return detect_format(f)
        except (OSError, ValueError):
            return None
