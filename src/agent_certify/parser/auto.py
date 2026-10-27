# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Input format auto-detection.

Detection looks at the content, not only the extension: Agent Trace's own
storage file is ``.agent-trace/traces.jsonl``, which is as ``.jsonl`` as a
Claude Code transcript.

==================================  ===================================
input                               parser
==================================  ===================================
``*.agent-trace`` / ``.agent-trace/``  :class:`CursorTraceParser`
``*.jsonl`` with trace records       :class:`CursorTraceParser`
``*.jsonl`` with MCP log records     :class:`MCPLogsParser`
other ``*.jsonl`` (incl. empty)      :class:`ClaudeCodeParser`
anything else                        ``ValueError``
==================================  ===================================
"""
from __future__ import annotations

from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser, decode_json, session_files
from agent_certify.parser.claude_code import ClaudeCodeParser
from agent_certify.parser.cursor_trace import TRACE_DIR, TRACE_SUFFIX, CursorTraceParser, looks_like_trace_record
from agent_certify.parser.mcp_logs import MCPLogsParser
from agent_certify.paths import iter_lines

CLAUDE, CURSOR, MCP_LOG = "claude-code", "cursor-agent-trace", "mcp-log"


def is_trace_dir(p: Path) -> bool:
    """A ``.agent-trace`` folder, or a repository holding one and no sessions of its own."""
    return p.is_dir() and (p.name == TRACE_DIR or ((p / TRACE_DIR).is_dir() and not any(p.glob("*.jsonl"))))


def detect_format(path: str | Path) -> str:
    """Name of the format at ``path``; raises ``ValueError`` when unsupported."""
    p = Path(path)
    if p.is_dir():
        if is_trace_dir(p):
            return CURSOR
        raise ValueError(f"{p} is a directory; use parse_directory()")
    if p.suffix == TRACE_SUFFIX:
        return CURSOR
    if p.suffix != ".jsonl":
        raise ValueError(f"Unknown format: {p} (expected .jsonl or .agent-trace)")
    for i, (_, line) in enumerate(iter_lines(p)):     # bounded reads: a huge first line is skipped
        if i >= 20:
            break
        if line is None or not line.strip():
            continue
        rec = decode_json(line.strip())
        if looks_like_trace_record(rec):
            return CURSOR
        if isinstance(rec, dict) and "sessionId" in rec and "cwd" in rec and "type" not in rec \
                and ("debug" in rec or "error" in rec):
            return MCP_LOG
        if isinstance(rec, dict):
            return CLAUDE
    return CLAUDE                               # empty or unreadable lines: v0.1 behaviour


class AutoParser(BaseParser):
    """Auto-detect input format and use the right parser.

    Usage::

        AutoParser().parse("session.jsonl")              # Claude Code
        AutoParser().parse(".agent-trace/traces.jsonl")   # Cursor
        AutoParser().parse_directory("~/.claude/projects/C--dev-x/")   # every session found
    """

    def __init__(self):
        self.claude = ClaudeCodeParser()
        self.cursor = CursorTraceParser()
        self.mcp = MCPLogsParser()
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
        if fmt == CURSOR:
            return self.cursor.parse(str(p))
        if fmt == MCP_LOG:
            return self.mcp.parse(str(p))
        return self.claude.parse(str(p))

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        """Every Claude Code session and Cursor trace under ``directory``.

        Claude Code sessions are found as :meth:`ClaudeCodeParser.parse_directory`
        finds them (``*.jsonl`` here, or one level down). Sub-agent transcripts
        are read with their parent session, and MCP server logs are left out
        (they enrich a session; see ``--include-mcp``).
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
        graphs += [self.cursor.parse(str(t)) for t in self.cursor.find_traces(str(d))]
        return graphs
