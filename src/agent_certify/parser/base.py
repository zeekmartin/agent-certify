# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Parser interface and the reading helpers every parser shares.

Logs are untrusted input. The helpers here make every parser fail soft: a
line that is malformed, nested deeply enough to exhaust the decoder
(``RecursionError``), or large enough to exhaust memory is counted as skipped
instead of aborting the scan, and directory scans stop at
:data:`agent_certify.paths.MAX_FILES` files.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.paths import MAX_DOCUMENT_BYTES, MAX_FILES, iter_lines

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Reads one framework's session logs into an :class:`AgentGraph`."""

    @abstractmethod
    def parse(self, path: str) -> AgentGraph:
        """Parse one session into an AgentGraph."""

    def parse_directory(self, directory: str) -> list[AgentGraph]:
        """Parse every session found under ``directory``."""
        raise NotImplementedError(f"{type(self).__name__} does not support directories")

    @staticmethod
    def _expand(path: str) -> Path:
        """``~`` only: parsers never expand environment variables (the CLI does, for typed paths)."""
        return Path(path).expanduser()


def decode_json(text: str):
    """``json.loads`` that returns None instead of raising, NaN/Infinity included."""
    try:
        return json.loads(text, parse_constant=_no_constant)
    except (ValueError, RecursionError, MemoryError):    # JSONDecodeError is a ValueError
        return None


def _no_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


# Keys under which a log file may wrap its records in a single JSON object.
_WRAPPER_KEYS = ("events", "logs", "records", "entries", "steps", "trace", "traces", "history", "data")


def read_records(path: Path, max_document: int = MAX_DOCUMENT_BYTES) -> Iterator[object | None]:
    """Records from a JSON document or a JSONL file, whichever ``path`` turns out to be.

    A file of at most ``max_document`` bytes is first read as one JSON
    document: an array of records, a single record, or an object holding its
    records in a list under a key such as ``events`` or ``logs``. Anything
    else — a bigger file, or one that is not valid JSON as a whole — is
    streamed as JSONL.

    ``None`` is yielded for a record that could not be read (malformed, nested
    too deeply, or a line over :data:`~agent_certify.paths.MAX_LINE_BYTES`), so
    a caller can count what it skipped instead of aborting. Blank lines are not
    records and are not yielded.
    """
    whole = None
    if path.stat().st_size <= max_document:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return
        whole = decode_json(text)
    if whole is not None:
        yield from _unwrap(whole)
        return
    for _, line in iter_lines(path):
        if line is None:
            yield None
        elif line.strip():
            yield decode_json(line)          # None when the line is unreadable


def _unwrap(document) -> Iterator[object]:
    """One JSON document as a stream of records."""
    if isinstance(document, list):
        yield from document
        return
    if isinstance(document, dict):
        for key in _WRAPPER_KEYS:
            inner = document.get(key)
            if isinstance(inner, list):
                yield from inner
                return
    yield document


def to_datetime(value) -> datetime | None:
    """A log record's timestamp as a datetime, or None when it is not one.

    Accepts ISO 8601 with or without a trailing ``Z`` and with a space instead
    of ``T`` (what CrewAI writes), and epoch seconds or milliseconds.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if abs(value) > 1e11 else value      # milliseconds past ~5138 AD
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def iso(ts: datetime) -> str:
    """A datetime as the UTC ISO 8601 string graphs and baselines store."""
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def session_files(directory: Path, max_files: int = MAX_FILES) -> list[Path]:
    """Session transcripts in a project folder (``*.jsonl``), or one level down for ``~/.claude/projects``.

    At most ``max_files`` are returned (newest kept when there are more); a
    warning says how many were left out.
    """
    files = sorted(directory.glob("*.jsonl"))
    if not files:
        files = sorted(f for sub in sorted(directory.iterdir()) if sub.is_dir() and not sub.name.startswith(".")
                       for f in sub.glob("*.jsonl"))
    if len(files) > max_files:
        logger.warning("%s: %d session files, reading the %d most recent", directory, len(files), max_files)
        files = sorted(sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)[:max_files])
    return files
