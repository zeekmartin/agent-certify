# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""CrewAI parser: the log shapes a crew writes, and the graph they map to."""
import json

import pytest

from agent_certify import AgentFIScanner, AutoParser, BaselineLearner, CrewAIParser
from agent_certify.parser.auto import CREWAI, detect_format
from agent_certify.parser.crewai import looks_like_crewai_record

# A two-agent crew: Researcher searches (one call failing), Writer writes and
# delegates a check back to the Researcher.
RUN = [
    {"timestamp": "2026-11-03 10:00:00", "event": "crew_kickoff_started",
     "crew": "ResearchCrew", "inputs": {"topic": "fragility"}},
    {"timestamp": "2026-11-03 10:00:01", "agent": "Researcher", "task": "Find the numbers", "status": "started"},
    {"timestamp": "2026-11-03 10:00:02", "agent_role": "Researcher", "tool_name": "search_web",
     "tool_args": {"q": "fragility index"}, "status": "started", "tool_call_id": "c1"},
    {"timestamp": "2026-11-03 10:00:03", "agent_role": "Researcher", "tool_name": "search_web",
     "status": "completed", "tool_call_id": "c1"},
    {"timestamp": "2026-11-03 10:00:04", "event": "tool_usage_error", "agent_role": "Researcher",
     "tool_name": "search_web", "error": "HTTP 503", "tool_call_id": "c2"},
    {"timestamp": "2026-11-03 10:00:05", "agent": "Researcher", "task": "Find the numbers", "status": "completed"},
    {"timestamp": "2026-11-03 10:00:06", "agent": "Writer", "task": "Write it up", "status": "started"},
    {"timestamp": "2026-11-03 10:00:07", "agent": "Writer", "tool": "Delegate work to coworker",
     "tool_args": {"coworker": "Researcher", "task": "check the figures"}, "status": "completed"},
    {"timestamp": "2026-11-03 10:00:10", "agent": "Writer", "tool_name": "file_write", "status": "completed"},
]


def write(path, records, as_lines: bool = False):
    """Write ``records`` as a JSON array (CrewAI's log file) or as JSONL (its event bus)."""
    text = "\n".join(json.dumps(r) for r in records) if as_lines else json.dumps(records, indent=2)
    path.write_text(text + "\n", encoding="utf-8")
    return path


@pytest.fixture
def run_log(tmp_path):
    return write(tmp_path / "crew-run.json", RUN)


@pytest.fixture
def graph(run_log):
    return CrewAIParser().parse(str(run_log))


# ----------------------------------------------------------------- happy path
def test_nodes_and_roles(graph):
    assert sorted(graph.nodes) == ["agent:Researcher", "agent:Writer", "crew", "human",
                                   "tool:Delegate work to coworker", "tool:file_write", "tool:search_web"]
    assert graph.nodes["crew"].kind == "orchestrator" and graph.nodes["crew"].name == "ResearchCrew"
    assert graph.nodes["agent:Researcher"].kind == "agent"
    # An agent's role is its own id, so it is the same node across runs of the crew.
    assert graph.role("agent:Researcher") == "agent:Researcher"
    assert graph.session_id == "crew-run"


def test_edges_and_counts(graph):
    edges = {(e.source, e.target): (e.weight, e.errors) for e in graph.edges}
    assert edges[("human", "crew")] == (1, 0)
    assert edges[("crew", "agent:Researcher")] == (1, 0)      # one distinct task, started and completed
    assert edges[("agent:Researcher", "tool:search_web")] == (2, 1)
    assert edges[("agent:Writer", "tool:file_write")] == (1, 0)
    assert graph.total_tool_calls == 4                        # search x2, delegate, file_write
    assert graph.total_messages == len(RUN) and graph.skipped_records == 0
    assert graph.total_records == len(RUN)


def test_started_and_completed_count_one_call(tmp_path):
    """A start and its completion are one invocation, not two."""
    pairs = [{"agent": "A", "tool": "t", "status": "started", "tool_call_id": "x"},
             {"agent": "A", "tool": "t", "status": "completed", "tool_call_id": "x"}]
    g = CrewAIParser().parse(str(write(tmp_path / "pairs.json", pairs)))
    assert g.total_tool_calls == 1
    assert graph_edge(g, "agent:A", "tool:t") == (1, 0)
    # The same log without the start record counts the same.
    g2 = CrewAIParser().parse(str(write(tmp_path / "one.json", pairs[1:])))
    assert g2.total_tool_calls == 1


def graph_edge(g, source, target):
    e = g.get_edge(source, target)
    return (e.weight, e.errors) if e else None


def test_error_after_start_is_one_failed_call(tmp_path):
    records = [{"agent": "A", "tool": "t", "status": "started", "tool_call_id": "x"},
               {"agent": "A", "tool": "t", "error": "boom", "tool_call_id": "x"}]
    g = CrewAIParser().parse(str(write(tmp_path / "fail.json", records)))
    assert g.total_tool_calls == 1 and graph_edge(g, "agent:A", "tool:t") == (1, 1)
    assert g.nodes["tool:t"].error_count == 1


def test_timestamps_and_duration(graph):
    assert graph.started_at == "2026-11-03T10:00:00Z"
    assert graph.ended_at == "2026-11-03T10:00:10Z"
    assert graph.duration_seconds == 10.0


# --------------------------------------------------------------- multi-agent
def test_delegation_links_agents(graph):
    """Handing work to a coworker is an agent -> agent link, not just a tool call."""
    assert graph_edge(graph, "agent:Writer", "agent:Researcher") == (1, 0)
    assert graph_edge(graph, "agent:Writer", "tool:Delegate work to coworker") == (1, 0)


def test_self_delegation_is_not_a_link(tmp_path):
    records = [{"agent": "A", "tool": "Ask question to coworker", "tool_args": {"coworker": "A"}}]
    g = CrewAIParser().parse(str(write(tmp_path / "self.json", records)))
    assert g.get_edge("agent:A", "agent:A") is None
    assert graph_edge(g, "agent:A", "tool:Ask question to coworker") == (1, 0)


def test_delegation_without_a_named_coworker(tmp_path):
    """A delegation tool whose arguments name nobody stays a plain tool call."""
    records = [{"agent": "A", "tool": "Delegate work to coworker", "tool_args": {"task": "x"}}]
    g = CrewAIParser().parse(str(write(tmp_path / "vague.json", records)))
    assert [n for n in g.nodes if n.startswith("agent:")] == ["agent:A"]


def test_delegation_closes_a_triangle(graph):
    """crew -> Writer, crew -> Researcher and Writer -> Researcher is a triangle: FI drops below 1."""
    result = AgentFIScanner(graph).scan()
    assert 0 <= result.fi < 1.0
    assert result.node_count == len(graph.nodes)


def test_tasks_recorded_once_per_distinct_task(tmp_path):
    records = [{"agent": "A", "task": "one", "status": "started"},
               {"agent": "A", "task": "one", "status": "completed"},
               {"agent": "A", "task_description": "two", "status": "completed"},
               {"agent": "A", "task": "three", "status": "failed", "error": "nope"}]
    g = CrewAIParser().parse(str(write(tmp_path / "tasks.json", records)))
    assert graph_edge(g, "crew", "agent:A") == (3, 1)         # three tasks, one of them failed
    assert g.nodes["agent:A"].metadata["tasks"] == ["one", "two", "three"]
    assert g.total_tool_calls == 0                            # a task is not a tool call


# ------------------------------------------------------------ fail-soft input
def test_malformed_lines_are_skipped_not_fatal(tmp_path):
    f = tmp_path / "noisy.jsonl"
    lines = [json.dumps(RUN[1]), "{not json", "", json.dumps(RUN[2]), "[1, 2, 3]", "null"]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parser = CrewAIParser()
    g = parser.parse(str(f))
    assert parser.skipped_records == 3 and g.skipped_records == 3   # bad JSON, a list, a null
    assert g.total_records == 5 and g.total_messages == 2
    assert "agent:Researcher" in g.nodes and g.has_data


def test_records_that_are_not_crewai_are_skipped(tmp_path):
    records = [{"hello": "world"}, {"type": "assistant", "message": {"content": []}}, RUN[1]]
    parser = CrewAIParser()
    g = parser.parse(str(write(tmp_path / "mixed.json", records)))
    assert parser.skipped_records == 2 and g.total_messages == 1


@pytest.mark.parametrize("name,text", [("empty.json", ""), ("blank.jsonl", "\n\n"), ("none.json", "[]")])
def test_empty_session(tmp_path, name, text):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    g = CrewAIParser().parse(str(f))
    assert sorted(g.nodes) == ["crew"]
    assert not g.has_data and g.total_tool_calls == 0 and g.total_messages == 0
    assert AgentFIScanner(g).scan().fi == 0.0                   # a lone node has no fragile links


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        CrewAIParser().parse(str(tmp_path / "nope.json"))
    with pytest.raises(NotADirectoryError):
        CrewAIParser().parse_directory(str(tmp_path / "nope"))


def test_wrapped_document_and_jsonl_agree(tmp_path):
    """The same records as an array, as JSONL, and wrapped in an object give the same graph."""
    array = CrewAIParser().parse(str(write(tmp_path / "a.json", RUN)))
    lines = CrewAIParser().parse(str(write(tmp_path / "b.jsonl", RUN, as_lines=True)))
    wrapped = tmp_path / "c.json"
    wrapped.write_text(json.dumps({"crew": "ResearchCrew", "events": RUN}), encoding="utf-8")
    nested = CrewAIParser().parse(str(wrapped))
    for other in (lines, nested):
        assert sorted(other.nodes) == sorted(array.nodes)
        assert other.total_tool_calls == array.total_tool_calls
        assert {(e.source, e.target, e.weight) for e in other.edges} == \
               {(e.source, e.target, e.weight) for e in array.edges}


def test_include_human_false(run_log):
    g = CrewAIParser(include_human=False).parse(str(run_log))
    assert "human" not in g.nodes


def test_record_naming_neither_agent_nor_crew_is_skipped(tmp_path):
    records = [{"crew": "Solo", "event": "crew_kickoff_started"}, {"tool": "search", "status": "completed"}]
    parser = CrewAIParser()
    g = parser.parse(str(write(tmp_path / "solo.json", records)))
    # The kickoff is read (hence the human); the tool record names nobody, so it is not a CrewAI record.
    assert parser.skipped_records == 1 and sorted(g.nodes) == ["crew", "human"]
    assert g.total_tool_calls == 0


def test_parse_directory(tmp_path):
    write(tmp_path / "run-1.json", RUN)
    write(tmp_path / "run-2.jsonl", RUN, as_lines=True)
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "version": "1"}), encoding="utf-8")
    graphs = CrewAIParser().parse_directory(str(tmp_path))
    assert [g.session_id for g in graphs] == ["run-1", "run-2"]   # package.json holds no records


# -------------------------------------------------------------- auto-detect
def test_detected_and_routed(tmp_path):
    for name, as_lines in (("run.json", False), ("events.jsonl", True)):
        path = write(tmp_path / name, RUN, as_lines=as_lines)
        assert detect_format(path) == CREWAI
        auto = AutoParser()
        g = auto.parse(str(path))
        assert auto.last_format == CREWAI and "agent:Researcher" in g.nodes


def test_record_predicate_rejects_other_formats():
    assert looks_like_crewai_record(RUN[1])
    assert not looks_like_crewai_record({"type": "assistant", "message": {"role": "assistant", "content": []}})
    assert not looks_like_crewai_record({"agent": "A"})          # an agent alone says nothing
    assert not looks_like_crewai_record({"event": "on_tool_start", "name": "search"})
    assert not looks_like_crewai_record("a string")
    assert not looks_like_crewai_record(None)


def test_baseline_learns_from_crew_runs(tmp_path):
    write(tmp_path / "run-1.json", RUN)
    write(tmp_path / "run-2.json", RUN)
    baseline = BaselineLearner().learn([str(tmp_path)])
    assert baseline.learned_from == 2
    assert {"search_web", "file_write"} <= baseline.known_tools
    assert ("agent:Writer", "agent:Researcher") in baseline.known_links
