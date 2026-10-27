# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import numpy as np
import pytest
from conftest import session_graph

from agent_certify import AgentFIScanner, BaselineLearner, load_baseline
from agent_certify.cli import main

# Star of 4 tools plus c tool->tool cross-links (a path t0-t1-...): each closes a
# triangle with claude. c=0: 4 links, none supported. c=1: 5 links, 3 supported.
# c=2: 6 links, 5 supported. c=3: 7 links, all supported.
FI_BY_CROSS = {0: 1.0, 1: 2 / 5, 2: 1 / 6, 3: 0.0}
CROSS = [0, 1, 2, 3, 0, 1, 2, 3, 0, 0]


def _sessions():
    graphs = []
    for i, c in enumerate(CROSS):
        tools = {"Bash": 10, "Read": 5, "Write": 3, "Grep": 2}
        if i % 2:
            tools["WebSearch"] = 1          # 5 of 10 sessions (adds a leaf, so FI_BY_CROSS holds for even i only)
        graphs.append(session_graph(f"s{i}", tools, errors=i % 3, agents=1 if i == 9 else 0,
                                    cross_links=c, start=f"2026-10-{i + 1:02d}T10:00:00Z"))
    return graphs


def test_learn_stats_match_numpy():
    graphs = _sessions()
    fis = [AgentFIScanner(g).scan().fi for g in graphs]
    b = BaselineLearner().learn_graphs(graphs)

    assert b.learned_from == 10
    assert b.fi_mean == pytest.approx(np.mean(fis))
    assert b.fi_std == pytest.approx(np.std(fis))
    assert b.fi_min == min(fis) and b.fi_max == max(fis)
    assert b.node_count_mean == pytest.approx(np.mean([len(g.nodes) for g in graphs]))
    assert b.known_tools == {"Bash", "Read", "Write", "Grep", "WebSearch"}
    assert b.tool_frequency["Bash"] == 1.0 and b.tool_frequency["WebSearch"] == 0.5
    assert b.max_sub_agents_seen == 1 and b.sub_agent_count_mean == pytest.approx(0.1)
    rates = [(i % 3) / g.total_tool_calls for i, g in enumerate(graphs)]
    assert b.error_rate_mean == pytest.approx(np.mean(rates))
    assert b.error_rate_std == pytest.approx(np.std(rates))
    assert ("claude", "agent:Explore") in b.known_links          # agents recorded by type
    assert ("agent:Explore", "tool:Bash") in b.known_links
    assert b.period_start == "2026-10-01T10:00:00Z" and b.period_end == "2026-10-10T10:00:00Z"


def test_known_fi_values():
    # Sessions with even index use the 4-tool star, so their FI is known exactly.
    graphs = [g for i, g in enumerate(_sessions()) if i % 2 == 0]
    expected = [FI_BY_CROSS[c] for i, c in enumerate(CROSS) if i % 2 == 0]
    assert [AgentFIScanner(g).scan().fi for g in graphs] == pytest.approx(expected)
    b = BaselineLearner().learn_graphs(graphs)
    assert b.fi_mean == pytest.approx(np.mean(expected))
    assert b.fi_std == pytest.approx(np.std(expected))


def test_save_load_roundtrip(tmp_path):
    learner = BaselineLearner()
    b = learner.learn_graphs(_sessions())
    path = learner.save(b, tmp_path / "nested" / "baseline.json")
    assert json.loads(path.read_text())["known_tools"] == sorted(b.known_tools)
    assert learner.load(path) == b
    assert load_baseline(path) == b


def test_default_save_location():
    learner = BaselineLearner()
    path = learner.save(learner.learn_graphs(_sessions()[:2]))
    assert path == Path(".agent-certify") / "baseline.json" and path.is_file()


def test_single_session_has_zero_std():
    b = BaselineLearner().learn_graphs(_sessions()[:1])
    assert b.learned_from == 1
    assert b.fi_std == 0 and b.node_count_std == 0 and b.error_rate_std == 0 and b.bridge_count_std == 0


def test_empty_directory(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no sessions"):
        BaselineLearner().learn([str(empty)])


def test_learn_from_real_files(session_dir):
    b = BaselineLearner().learn([str(session_dir / "sess-1.jsonl"), str(session_dir)])
    assert b.learned_from == 2                     # the file, and the same file found in the directory
    assert b.known_tools == {"Bash", "Read", "Grep"}
    assert ("claude", "agent:Explore") in b.known_links
    assert b.max_sub_agents_seen == 1


def test_cli_learn(session_dir, capsys):
    assert main(["learn", str(session_dir)]) == 0
    out = capsys.readouterr().out
    assert "Learned baseline from 1 session (Oct 1 — Oct 1, 2026)" in out
    assert "Bash (100%)" in out
    assert (Path(".agent-certify") / "baseline.json").is_file()

    assert main(["learn", str(session_dir), "-o", "custom.json"]) == 0
    assert Path("custom.json").is_file()


def test_cli_learn_empty(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    with pytest.raises(SystemExit, match="no sessions"):
        main(["learn", str(empty)])
