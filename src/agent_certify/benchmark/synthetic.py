# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Synthetic clean sessions, so the benchmark runs without anyone's logs.

The sessions look like a Claude Code project that has settled into a habit:
one orchestrator, a fixed set of tools, one to three ``Explore`` or ``Plan``
sub-agents sharing a tool with it, and the odd failed call. They **vary**, which
matters more than their realism: a baseline learned from identical sessions has
a standard deviation of zero on every metric, and then any difference at all is
an anomaly and a false positive rate measured against it means nothing.

Variation is by session index, not random, so a benchmark run is reproducible
and a regression in the numbers is a real change rather than a reseed. Pass
``seed`` to :func:`clean_sessions` to jitter the call counts instead.

The jitter is a hash, not a pseudo-random generator: it has to give the same
sessions on every machine and every Python version, and a benchmark fixture
must never be mistaken for a source of randomness — so the module imports no
generator at all.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from agent_certify.graph import AgentGraph

#: The tools every synthetic session uses, so none of them is ever "new".
TOOLS = ("Bash", "Read", "Edit", "Grep", "Write")

#: Sub-agent types the baseline gets to learn.
AGENT_TYPES = ("Explore", "Plan")

#: The network destination every session reaches, so a baseline has one to
#: learn and an injected foreign host is genuinely new.
HOME_DOMAIN = "api.internal.example"

_EPOCH = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def jitter(seed: int | None, index: int, slot: int) -> int:
    """A reproducible offset in -2..+2, or 0 when ``seed`` is None.

    Derived from a digest of ``(seed, index, slot)`` rather than drawn from a
    generator, so the same arguments give the same offset everywhere, forever.
    """
    if seed is None:
        return 0
    digest = hashlib.blake2b(f"{seed}:{index}:{slot}".encode(), digest_size=4).digest()
    return digest[0] % 5 - 2


def clean_session(index: int, seed: int | None = None) -> AgentGraph:
    """One synthetic session, shaped by ``index``.

    Index drives how much happens: 1–3 sub-agents, 4 to 11 calls per tool and
    0–2 failed calls. What it does *not* drive is which agent type pairs with
    which shared tool: that comes from the sub-agent's position, so a session
    with fewer sub-agents uses a prefix of the same invocation paths rather
    than different ones. Otherwise a held-out session would show a path the
    training half never had, and every clean session would be a false positive
    for reasons that are the generator's fault, not the detector's.

    ``seed`` jitters the call counts by up to ±2 (see :func:`jitter`), for a run
    that is still reproducible but less regular.
    """
    started = _EPOCH + timedelta(hours=index)
    g = AgentGraph(session_id=f"clean-{index:03d}", project="benchmark",
                   started_at=started.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   ended_at=(started + timedelta(minutes=20 + index % 7)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    g.duration_seconds = (20 + index % 7) * 60.0
    g.add_node("claude", "orchestrator", "claude")
    g.add_node("human", "human", "human")
    g.add_call("human", "claude")

    calls = 0
    for i, tool in enumerate(TOOLS):
        weight = max(1, 4 + (index + i) % 8 + jitter(seed, index, i))
        nid = f"tool:{tool}"
        g.add_node(nid, "tool", tool)
        g.add_call("claude", nid, count=weight)
        calls += weight

    for a in range(1 + index % 3):
        agent_type = AGENT_TYPES[a % len(AGENT_TYPES)]
        aid = f"agent:{agent_type}-{a}"
        g.add_node(aid, "agent", f"{agent_type}: step {a}", agentType=agent_type)
        g.add_call("claude", aid)
        shared = f"tool:{TOOLS[a % len(TOOLS)]}"      # a shared tool closes a triangle with the orchestrator
        g.add_call(aid, shared, count=2)
        calls += 3

    g.record_domains(f"tool:{TOOLS[0]}", {HOME_DOMAIN})   # the one destination this system calls
    g.total_tool_calls = calls
    g.total_messages = calls + 2
    for e in range(index % 3):                        # 0, 1 or 2 failed calls: the baseline needs a spread
        g.record_error("claude", f"tool:{TOOLS[e]}")
    return g


def clean_sessions(count: int = 12, seed: int | None = None) -> list[AgentGraph]:
    """``count`` synthetic clean sessions, varied by index (see :func:`clean_session`)."""
    if count < 1:
        raise ValueError(f"count must be at least 1, got {count}")
    return [clean_session(i, seed=seed) for i in range(count)]
