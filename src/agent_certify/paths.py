# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BUSL-1.1
"""Path handling in one place: trusted CLI input, untrusted MCP input, state files.

Two kinds of input reach agent-certify:

* **Trusted** — arguments the user typed on the command line. :func:`expand_cli`
  expands ``~`` and environment variables (``$HOME``, ``%USERPROFILE%``), as a
  shell would.
* **Untrusted** — arguments an AI agent sends to the MCP server. :func:`confine`
  expands ``~`` only (never environment variables, whose values could leak back
  to the caller), resolves symlinks and ``..``, and accepts the result only if it
  lies inside one of the allowed roots. Its errors never contain the path.

This module also holds the resource limits shared by the parsers, and creates
the ``.agent-certify/`` state directory with a ``.gitignore`` so that its
contents (session ids, project names) are not committed by accident.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path

# ------------------------------------------------------------------ limits
MAX_DEPTH = 5                       # directory levels walked below a scanned directory
MAX_FILES = 1000                    # session / trace files read from one directory
MAX_LINE_BYTES = 10 * 1024 * 1024   # longer JSONL lines are skipped
MAX_DOCUMENT_BYTES = 50 * 1024 * 1024   # a whole-file JSON document (.agent-trace) larger than this is refused

STATE_DIR = Path(".agent-certify")
_STATE_GITIGNORE = ("# Created by agent-certify. These files hold session ids and project names;\n"
                    "# keep them out of version control.\n*\n")


class PathNotAllowed(ValueError):
    """An untrusted path resolved outside every allowed root (the message never contains the path)."""

    def __init__(self):
        super().__init__("Path not allowed")


def expand_cli(raw: str | os.PathLike) -> Path:
    """Expand ``~`` and environment variables in a path typed by the user."""
    return Path(os.path.expandvars(os.path.expanduser(str(raw))))


def confine(raw: str | os.PathLike, allowed_roots: Iterable[str | os.PathLike], base: str | os.PathLike | None = None,
            ) -> Path:
    """Resolve an untrusted path and require it to lie inside one of ``allowed_roots``.

    ``~`` is expanded; environment variables are not. A relative path is taken
    relative to ``base`` (default: the working directory). Symlinks and ``..``
    are resolved before the check, so neither can escape a root. Raises
    :class:`PathNotAllowed` (whose message holds no path) otherwise.
    """
    text = str(raw)
    if not text or "\x00" in text:
        raise PathNotAllowed()
    p = Path(os.path.expanduser(text))
    if not p.is_absolute():
        p = Path(base if base is not None else os.getcwd()) / p
    try:
        resolved = p.resolve()
    except (OSError, RuntimeError):     # e.g. a symlink loop
        raise PathNotAllowed() from None
    for root in allowed_roots:
        try:
            r = Path(root).resolve()
        except (OSError, RuntimeError):
            continue
        if resolved == r or r in resolved.parents:
            return resolved
    raise PathNotAllowed()


def ensure_state_dir(path: str | os.PathLike) -> Path:
    """Create the parent directory of ``path``; give an ``.agent-certify`` directory its ``.gitignore``."""
    parent = Path(path).parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.name == STATE_DIR.name:
        ignore = parent / ".gitignore"
        if not ignore.exists():
            try:
                ignore.write_text(_STATE_GITIGNORE, encoding="utf-8")
            except OSError:
                pass                    # best effort: never fail a save over this
    return parent


def iter_lines(path: str | os.PathLike, max_line: int = MAX_LINE_BYTES) -> Iterator[tuple[int, str | None]]:
    """(line number, text) for each line; text is None for a line longer than ``max_line`` bytes.

    Reads in bounded chunks, so a single huge line never has to fit in memory.
    """
    with open(path, "rb") as f:
        lineno = 0
        while True:
            chunk = f.readline(max_line + 1)
            if not chunk:
                return
            lineno += 1
            if len(chunk) > max_line and not chunk.endswith(b"\n"):
                while True:                     # drain the rest of the oversized line
                    rest = f.readline(1 << 20)
                    if not rest or rest.endswith(b"\n"):
                        break
                yield lineno, None
                continue
            yield lineno, chunk.decode("utf-8", errors="replace")


def walk(root: str | os.PathLike, max_depth: int = MAX_DEPTH, skip: Iterable[str] = ()) -> Iterator[tuple[Path, list[str], list[str]]]:
    """``os.walk`` limited to ``max_depth`` levels below ``root``, skipping directory names in ``skip``.

    Yields (directory, subdirectory names, file names); like ``os.walk``, the
    caller may prune the subdirectory list in place.
    """
    root = Path(root)
    skip = set(skip)
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        if len(here.parts) - base_depth >= max_depth:
            dirnames[:] = []
        yield here, dirnames, sorted(filenames)
