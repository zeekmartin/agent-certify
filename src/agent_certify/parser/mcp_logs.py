# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""MCP server logs parser.

Claude Code writes one JSONL log per MCP server and process start:

    Windows:  %LOCALAPPDATA%\\claude-cli-nodejs\\Cache\\<project>\\mcp-logs-<server>\\<timestamp>.jsonl
    Linux:    ~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/<timestamp>.jsonl
    macOS:    ~/Library/Caches/claude-cli-nodejs/<project>/mcp-logs-<server>/<timestamp>.jsonl

Each record is ``{"timestamp", "sessionId", "cwd", "debug" | "error"}`` with a
free-text message. Tool calls show up as ``Calling MCP tool: <tool>``, and
failures as ``Tool '<tool>' failed after ...``. ``sessionId`` is the Claude
Code session id, so a log can be joined to that session's transcript.

The logs include calls Claude Code makes on its own (the IDE server's
``getDiagnostics`` after an edit, for instance) that never appear as
``tool_use`` blocks in the transcript. The logs do not say which agent made a
call, so every call is attributed to the orchestrator.

Tool nodes use Claude Code's naming, ``tool:mcp__<server>__<tool>``, and
:meth:`MCPLogsParser.enrich` reuses a transcript's existing node for the same
tool. Calls already present in the transcript are not counted twice.
"""
from __future__ import annotations

import copy
import logging
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser, decode_json
from agent_certify.parser.claude_code import ORCHESTRATOR, tool_id
from agent_certify.paths import MAX_FILES, iter_lines, walk

logger = logging.getLogger(__name__)

_CALL = re.compile(r"^Calling MCP tool: (?P<tool>\S+)")
_FAIL = re.compile(r"^Tool '(?P<tool>[^']+)' failed")
_LOG_DIR_PREFIX = "mcp-logs-"


def default_roots() -> list[Path]:
    """Directories that may hold per-project MCP log folders on this platform."""
    roots = []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            roots += [Path(local) / "claude-cli-nodejs" / "Cache", Path(local) / "claude-cli-nodejs"]
    else:
        xdg = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        roots += [Path(xdg) / "claude-cli-nodejs"]
        if sys.platform == "darwin":
            roots += [Path.home() / "Library" / "Caches" / "claude-cli-nodejs"]
    return roots


def project_key(project_path: str) -> str:
    """Claude Code's folder name for a project: ``H:\\agent-certify`` -> ``H--agent-certify``."""
    p = str(project_path).rstrip("\\/")
    if re.fullmatch(r"[A-Za-z0-9-]+", p):
        return p                              # already a folder name
    return re.sub(r"[^A-Za-z0-9-]", "-", p)


def _norm(server: str) -> str:
    return re.sub(r"[^a-z0-9]", "", server.lower())


class MCPLogsParser(BaseParser):
    """Parse MCP server logs to extract tool call edges.

    Usage::

        mcp = MCPLogsParser()
        mcp.find_logs("H:/agent-certify")          # log files for one project
        graph = ClaudeCodeParser().parse(session)
        graph = mcp.enrich(graph)                  # adds that session's MCP calls

    ``roots`` overrides where logs are searched for (tests, unusual installs).
    """

    def __init__(self, roots: list[str | os.PathLike] | None = None):
        self.roots = [Path(r) for r in roots] if roots is not None else default_roots()
        self.skipped_lines = 0
        self.added_calls = 0

    # ---------------------------------------------------------------- find
    def find_logs(self, project_path: str | None = None) -> list[Path]:
        """Find all MCP log files on the system, optionally for one project.

        ``project_path`` may be the project's folder name (``H--agent-certify``)
        or its path (``H:\\agent-certify``). Returns [] when there are none.
        """
        key = project_key(project_path) if project_path else None
        found: set[Path] = set()
        for root in self.roots:
            if not root.is_dir():
                continue
            projects = [root / key] if key else [p for p in root.iterdir() if p.is_dir()]
            for proj in projects:
                if proj.is_dir():
                    found.update(proj.glob(f"{_LOG_DIR_PREFIX}*/*.jsonl"))
        return sorted(found)

    # --------------------------------------------------------------- parse
    def parse(self, path: str) -> AgentGraph:
        """Parse a single MCP log file into ``claude -> tool:mcp__<server>__<tool>`` edges."""
        p = self._expand(path)
        if not p.is_file():
            raise FileNotFoundError(p)
        self.skipped_lines = 0
        server = self._server(p)
        g = AgentGraph(session_id=None, project=p.parent.parent.name)
        g.add_node(ORCHESTRATOR, "orchestrator", "claude")
        sessions, stamps = set(), []
        for ev in self._events(p, server):
            sessions.add(ev["session"])
            if ev["ts"]:
                stamps.append(ev["ts"])
            nid = tool_id(f"mcp__{server}__{ev['tool']}")
            g.add_node(nid, "tool", f"mcp__{server}__{ev['tool']}", mcp_server=server, source="mcp-log")
            if ev["kind"] == "call":
                g.add_call(ORCHESTRATOR, nid)
                g.total_tool_calls += 1
            elif g.get_edge(ORCHESTRATOR, nid):
                g.record_error(ORCHESTRATOR, nid)
        sessions.discard(None)
        g.skipped_records = self.skipped_lines
        g.session_id = sessions.pop() if len(sessions) == 1 else p.stem
        if stamps:
            g.started_at, g.ended_at = min(stamps), max(stamps)
        return g

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        """One graph per log file under ``directory``."""
        return [self.parse(str(f)) for f in self._log_files_under(self._expand(directory))]

    # -------------------------------------------------------------- enrich
    def enrich(self, graph: AgentGraph, mcp_log_dir: str | None = None) -> AgentGraph:
        """Return a copy of ``graph`` with the MCP calls its session made.

        Logs come from ``mcp_log_dir`` when given (a project's log folder, or
        any folder above ``mcp-logs-*`` folders), otherwise from
        :meth:`find_logs` for ``graph.project``. Only records whose
        ``sessionId`` equals ``graph.session_id`` count. A tool the transcript
        already shows keeps its node; only calls beyond the transcript's count
        are added. ``added_calls`` holds how many were added.
        """
        if mcp_log_dir is not None:
            files = self._log_files_under(self._expand(mcp_log_dir))
        else:
            files = self.find_logs(graph.project) if graph.project else []
        calls: dict[tuple[str, str], int] = defaultdict(int)
        errors: dict[tuple[str, str], int] = defaultdict(int)
        for f in files:
            server = self._server(f)
            for ev in self._events(f, server):
                if graph.session_id and ev["session"] != graph.session_id:
                    continue
                (calls if ev["kind"] == "call" else errors)[(server, ev["tool"])] += 1

        g = copy.deepcopy(graph)
        self.added_calls = 0
        if not calls:
            return g
        if ORCHESTRATOR not in g.nodes:
            g.add_node(ORCHESTRATOR, "orchestrator", "claude")
        for (server, tool), n in sorted(calls.items()):
            nid = self._existing_node(g, server, tool) or tool_id(f"mcp__{server}__{tool}")
            g.add_node(nid, "tool", nid.split(":", 1)[1], mcp_server=server, mcp_log_calls=n)
            g.nodes[nid].metadata.setdefault("source", "mcp-log")
            edge = g.get_edge(ORCHESTRATOR, nid)
            extra = n - (edge.weight if edge else 0)
            if extra > 0:
                g.add_call(ORCHESTRATOR, nid, count=extra)
                g.total_tool_calls += extra
                self.added_calls += extra
            known_errors = g.get_edge(ORCHESTRATOR, nid).errors if g.get_edge(ORCHESTRATOR, nid) else 0
            for _ in range(max(0, errors.get((server, tool), 0) - known_errors)):
                g.record_error(ORCHESTRATOR, nid)
        return g

    # ------------------------------------------------------------ internals
    @staticmethod
    def _log_files_under(root: Path) -> list[Path]:
        """``mcp-logs-*/*.jsonl`` below ``root``, with the shared depth and file-count limits."""
        found = []
        for here, _dirs, filenames in walk(root):
            if here.name.startswith(_LOG_DIR_PREFIX):
                found += [here / f for f in filenames if f.endswith(".jsonl")]
            if len(found) >= MAX_FILES:
                break
        return sorted(found[:MAX_FILES])

    @staticmethod
    def _server(path: Path) -> str:
        name = path.parent.name
        return name.removeprefix(_LOG_DIR_PREFIX) if name.startswith(_LOG_DIR_PREFIX) else "unknown"

    @staticmethod
    def _existing_node(g: AgentGraph, server: str, tool: str) -> str | None:
        """A transcript node for the same MCP tool (server names are spelled differently in each)."""
        want = _norm(server)
        for nid, node in g.nodes.items():
            parts = node.name.split("__")
            if node.kind == "tool" and len(parts) == 3 and parts[0] == "mcp" \
                    and parts[2] == tool and _norm(parts[1]) == want:
                return nid
        return None

    def _events(self, path: Path, server: str) -> Iterator[dict]:
        """Tool-call and tool-failure events, skipping unreadable or oversized lines."""
        for _, line in iter_lines(path):
            if line is None:
                self.skipped_lines += 1
                continue
            line = line.strip()
            if not line:
                continue
            rec = decode_json(line)
            if not isinstance(rec, dict):
                self.skipped_lines += 1
                continue
            msg = rec.get("debug") or rec.get("error") or ""
            if not isinstance(msg, str):
                continue
            m = _CALL.match(msg)
            kind = "call"
            if not m:
                m, kind = _FAIL.match(msg), "error"
            if m:
                yield {"kind": kind, "tool": m.group("tool"), "session": rec.get("sessionId"),
                       "ts": rec.get("timestamp")}
