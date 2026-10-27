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
from pathlib import Path

from agent_certify.graph import AgentGraph
from agent_certify.paths import MAX_FILES

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
