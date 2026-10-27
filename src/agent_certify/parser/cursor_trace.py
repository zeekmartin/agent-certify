# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Cursor Agent Trace parser.

`Agent Trace <https://agent-trace.dev>`_ (github.com/cursor/agent-trace) is an
open format for recording **which code was written by AI and which by
humans**. Each trace record (schema v1) is::

    {"version": "1.0", "id": "<uuid>", "timestamp": "<RFC 3339>",
     "vcs": {"type": "git", "revision": "<sha>"},
     "tool": {"name": "cursor", "version": "..."},
     "files": [{"path": "src/app.py",
                "conversations": [{"url": "...",
                                   "contributor": {"type": "ai", "model_id": "..."},
                                   "ranges": [{"start_line": 1, "end_line": 40,
                                               "contributor": {...}}]}]}]}

with ``contributor.type`` one of ``human``, ``ai``, ``mixed``, ``unknown``.
Records are stored as JSONL, by default in ``.agent-trace/traces.jsonl``.

The format records authorship of code, **not tool calls**: there are no
tools, MCP servers or sub-agents in it. The graph built from it is therefore a
provenance graph:

* the producing tool (``tool.name``, e.g. ``cursor``) is the orchestrator;
* each AI contributor becomes ``agent:<model_id>`` (type = model), linked
  from the orchestrator; ``human`` stays ``human``; ``mixed`` / ``unknown``
  become ``agent:mixed`` / ``agent:unknown``;
* each file becomes ``file:<path>``, linked from every contributor that wrote
  lines in it, edge weight = lines written.

Contributors and files only link to each other through the orchestrator's
models, so the graph is bipartite and has no triangles: **FI is always 1.0**
for these graphs. Blast radius (which files a model touched), policy rules
(``agent:* → file:infra/*``) and anomaly detection (a new model, new files)
are the useful views.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.parser.base import BaseParser, decode_json
from agent_certify.paths import MAX_DOCUMENT_BYTES, MAX_FILES, iter_lines, walk

logger = logging.getLogger(__name__)

TRACE_DIR = ".agent-trace"
TRACE_FILE = "traces.jsonl"
TRACE_SUFFIX = ".agent-trace"
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}


def looks_like_trace_record(rec) -> bool:
    return isinstance(rec, dict) and "files" in rec and "version" in rec


class CursorTraceParser(BaseParser):
    """Parse Cursor Agent Trace records into an AgentGraph.

    ``parse`` accepts a ``traces.jsonl`` file, a ``.agent-trace`` directory,
    or a ``*.agent-trace`` file holding one record, a list of records, or
    JSONL. All records in it are combined into one graph. Records or fields
    that are missing or malformed are skipped; ``skipped`` counts them.
    """

    def __init__(self):
        self.skipped = 0

    def parse(self, path: str) -> AgentGraph:
        p = self._expand(path)
        files = self._trace_files(p)
        if not files:
            raise FileNotFoundError(p)
        self.skipped = 0
        g = AgentGraph(session_id=None, project=self._project_name(p))
        ids, stamps, editor = [], [], None
        for f in files:
            for rec in self._records(f):
                tool = rec.get("tool") if isinstance(rec.get("tool"), dict) else {}
                editor = editor or self._add_editor(g, tool)
                self._add_record(g, rec, editor)
                ids.append(str(rec.get("id") or ""))
                if isinstance(rec.get("timestamp"), str):
                    stamps.append(rec["timestamp"])
        if editor is None:
            self._add_editor(g, {})
        g.session_id = ids[0] if len(ids) == 1 and ids[0] else (files[0].stem if len(files) == 1 else p.name)
        if stamps:
            g.started_at, g.ended_at = min(stamps), max(stamps)
        g.total_messages = len(ids)
        g.skipped_records = self.skipped
        if self.skipped:
            logger.warning("%s: skipped %d malformed trace record(s) or field(s)", p, self.skipped)
        return g

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        return [self.parse(str(t)) for t in self.find_traces(directory)]

    def find_traces(self, directory: str = ".") -> list[Path]:
        """``.agent-trace`` directories and ``*.agent-trace`` files under ``directory``.

        Skips ``.git``, ``node_modules``, virtualenvs and build output, walks at
        most :data:`~agent_certify.paths.MAX_DEPTH` levels down and returns at
        most :data:`~agent_certify.paths.MAX_FILES` traces.
        """
        root = self._expand(directory)
        found = []
        for here, dirnames, filenames in walk(root, skip=_SKIP_DIRS):
            if here.name == TRACE_DIR:
                found.append(here)
                dirnames[:] = []
            else:
                found += [here / f for f in filenames if f.endswith(TRACE_SUFFIX)]
            if len(found) >= MAX_FILES:
                logger.warning("%s: stopped after %d traces", root, MAX_FILES)
                break
        return sorted(found[:MAX_FILES])

    # ------------------------------------------------------------ internals
    @staticmethod
    def _trace_files(p: Path) -> list[Path]:
        if p.is_file():
            return [p]
        if p.is_dir():
            inner = p / TRACE_DIR if (p / TRACE_DIR).is_dir() else p
            return sorted(inner.glob("*.jsonl")) + sorted(inner.glob(f"*{TRACE_SUFFIX}"))
        return []

    @staticmethod
    def _project_name(p: Path) -> str:
        p = p.resolve()
        while p.name in (TRACE_DIR, TRACE_FILE) or p.suffix in (TRACE_SUFFIX, ".jsonl"):
            p = p.parent
        return p.name

    def _records(self, path: Path) -> Iterator[dict]:
        """Trace records from one file.

        A file of at most :data:`~agent_certify.paths.MAX_DOCUMENT_BYTES` is first
        tried as one JSON document (an object, or an array of records); otherwise,
        and for larger files, it is streamed as JSONL with the line-size limit.
        """
        whole = None
        if path.stat().st_size <= MAX_DOCUMENT_BYTES:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            if not text:
                return
            whole = decode_json(text)
        if whole is not None:
            candidates = whole if isinstance(whole, list) else [whole]
            for rec in candidates:
                yield from self._accept(rec)
            return
        for _, line in iter_lines(path):
            if line is None:
                self.skipped += 1
            elif line.strip():
                yield from self._accept(decode_json(line))

    def _accept(self, rec) -> Iterator[dict]:
        if looks_like_trace_record(rec) and isinstance(rec["files"], list):
            yield rec
        else:
            self.skipped += 1

    @staticmethod
    def _add_editor(g: AgentGraph, tool: dict) -> str:
        name = str(tool.get("name") or "agent-trace")
        nid = name.lower()
        g.add_node(nid, "orchestrator", name, **({"version": tool["version"]} if tool.get("version") else {}))
        return nid

    def _contributor_node(self, g: AgentGraph, contributor, editor: str) -> str:
        contributor = contributor if isinstance(contributor, dict) else {}
        ctype = contributor.get("type") if contributor.get("type") in ("human", "ai", "mixed", "unknown") \
            else "unknown"
        if ctype == "human":
            g.add_node("human", "human", "human")
            return "human"
        model = str(contributor.get("model_id") or "") if ctype == "ai" else ctype
        model = model or "ai"
        nid = f"agent:{model}"
        if nid not in g.nodes:
            g.add_node(nid, "agent", model, agentType=model, contributor_type=ctype)
            g.add_call(editor, nid)
        return nid

    def _add_record(self, g: AgentGraph, rec: dict, editor: str) -> None:
        for entry in rec["files"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                self.skipped += 1
                continue
            fid = f"file:{entry['path']}"
            g.add_node(fid, "file", entry["path"])
            convs = entry.get("conversations") if isinstance(entry.get("conversations"), list) else []
            for conv in convs:
                if not isinstance(conv, dict):
                    self.skipped += 1
                    continue
                default = conv.get("contributor")
                ranges = conv.get("ranges") if isinstance(conv.get("ranges"), list) else []
                if not ranges:
                    # A conversation with no ranges still says who touched the file.
                    self._write(g, self._contributor_node(g, default, editor), fid, 0)
                for r in ranges:
                    if not isinstance(r, dict):
                        self.skipped += 1
                        continue
                    who = self._contributor_node(g, r.get("contributor") or default, editor)
                    self._write(g, who, fid, self._lines(r))
                    g.total_tool_calls += 1

    @staticmethod
    def _lines(r: dict) -> int:
        try:
            return max(0, int(r["end_line"]) - int(r["start_line"]) + 1)
        except (KeyError, TypeError, ValueError):
            return 0

    @staticmethod
    def _write(g: AgentGraph, who: str, fid: str, lines: int) -> None:
        # Edge weight = lines written (at least 1 per contribution, so a link always counts).
        g.add_call(who, fid, count=max(1, lines))
