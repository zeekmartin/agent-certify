# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
"""Parser interface: turn a framework's logs into an :class:`AgentGraph`."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from agent_certify.graph import AgentGraph


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
        return Path(path).expanduser()
