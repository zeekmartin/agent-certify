# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""LangGraph parser: the three trace shapes, and the graph they map to."""
import json

import pytest

from agent_certify import AgentFIScanner, AutoParser, BaselineLearner, LangGraphParser
from agent_certify.parser.auto import LANGGRAPH, detect_format
from agent_certify.parser.langgraph import looks_like_langgraph_record, trigger_source

# Shape 1 — astream_events(version="v2"): a ReAct loop, agent -> tools -> agent,
# with one tool call succeeding and one failing.
EVENTS = [
    {"event": "on_chain_start", "name": "ReActGraph", "run_id": "root", "data": {"input": {"messages": ["hi"]}}},
    {"event": "on_chain_start", "name": "agent", "run_id": "r1", "timestamp": "2026-11-03T10:00:00Z",
     "metadata": {"langgraph_node": "agent", "langgraph_step": 1, "langgraph_triggers": ["start:agent"]}},
    {"event": "on_chain_end", "name": "agent", "run_id": "r1",
     "metadata": {"langgraph_node": "agent", "langgraph_step": 1}},
    {"event": "on_tool_start", "name": "search", "run_id": "t1",
     "metadata": {"langgraph_node": "tools", "langgraph_triggers": ["branch:agent:should_continue:tools"]}},
    {"event": "on_tool_end", "name": "search", "run_id": "t1", "metadata": {"langgraph_node": "tools"}},
    {"event": "on_tool_start", "name": "calculator", "run_id": "t2", "metadata": {"langgraph_node": "tools"}},
    {"event": "on_tool_error", "name": "calculator", "run_id": "t2",
     "metadata": {"langgraph_node": "tools"}, "data": {"error": "division by zero"}},
    {"event": "on_chain_start", "name": "agent", "run_id": "r2", "timestamp": "2026-11-03T10:00:09Z",
     "metadata": {"langgraph_node": "agent", "langgraph_step": 3, "langgraph_triggers": ["tools"]}},
    {"event": "on_chain_end", "name": "ReActGraph", "run_id": "root", "data": {"output": {}}},
]

# Shape 2 — stream_mode="debug": planner then worker, the worker failing.
DEBUG = [
    {"type": "task", "timestamp": "2026-11-03T10:00:00Z", "step": 1,
     "payload": {"id": "p1", "name": "planner", "triggers": ["start:planner"]}},
    {"type": "task_result", "step": 1, "payload": {"name": "planner", "error": None, "result": [["plan", ["a"]]]}},
    {"type": "task", "timestamp": "2026-11-03T10:00:02Z", "step": 2,
     "payload": {"id": "p2", "name": "worker", "triggers": ["planner"]}},
    {"type": "task_result", "step": 2, "payload": {"name": "worker", "error": "RuntimeError: boom"}},
]

# Shape 3 — a hand-rolled logger: node, where it went next, what it called.
PLAIN = [
    {"timestamp": "2026-11-03T10:00:00Z", "node": "agent", "next": "tools",
     "tool_calls": [{"name": "search", "id": "c1"}, {"name": "search", "id": "c2"}]},
    {"timestamp": "2026-11-03T10:00:03Z", "node": "tools", "next": "agent", "error": None},
    {"timestamp": "2026-11-03T10:00:05Z", "node": "agent", "next": "__end__"},
]


def write(path, records, as_lines: bool = True):
    text = "\n".join(json.dumps(r) for r in records) if as_lines else json.dumps(records, indent=2)
    path.write_text(text + "\n", encoding="utf-8")
    return path


def edge(g, source, target):
    e = g.get_edge(source, target)
    return (e.weight, e.errors) if e else None


@pytest.fixture
def events(tmp_path):
    return LangGraphParser().parse(str(write(tmp_path / "events.jsonl", EVENTS)))


@pytest.fixture
def debug(tmp_path):
    return LangGraphParser().parse(str(write(tmp_path / "debug.jsonl", DEBUG)))


@pytest.fixture
def plain(tmp_path):
    return LangGraphParser().parse(str(write(tmp_path / "plain.jsonl", PLAIN)))


# ---------------------------------------------------------- shape 1: events
def test_event_stream_nodes(events):
    assert sorted(events.nodes) == ["agent:agent", "agent:tools", "graph", "human",
                                    "tool:calculator", "tool:search"]
    assert events.nodes["graph"].kind == "orchestrator" and events.nodes["graph"].name == "ReActGraph"
    # A LangGraph node is an agent whose type is its name, so it is the same node across runs.
    assert events.nodes["agent:tools"].kind == "agent" and events.role("agent:tools") == "agent:tools"


def test_event_stream_transitions_and_tools(events):
    assert edge(events, "human", "graph") == (1, 0)          # the input the graph was invoked with
    assert edge(events, "graph", "agent:agent") == (1, 0)    # __start__ is the orchestrator
    assert edge(events, "agent:agent", "agent:tools") == (1, 0)
    assert edge(events, "agent:tools", "agent:agent") == (1, 0)   # the loop back
    assert edge(events, "agent:tools", "tool:search") == (1, 0)
    assert edge(events, "agent:tools", "tool:calculator") == (1, 1)
    assert events.total_tool_calls == 2                      # start+end is one call; start+error is one call
    assert events.nodes["graph"].metadata["transitions"] == 3
    assert events.started_at == "2026-11-03T10:00:00Z" and events.duration_seconds == 9.0
    assert events.skipped_records == 0 and events.total_records == len(EVENTS)


def test_tool_error_is_counted_once(events):
    assert events.nodes["tool:calculator"].error_count == 1
    assert events.nodes["tool:calculator"].call_count == 1


# ----------------------------------------------------------- shape 2: debug
def test_debug_stream(debug):
    assert sorted(debug.nodes) == ["agent:planner", "agent:worker", "graph"]
    assert edge(debug, "graph", "agent:planner") == (1, 0)
    assert edge(debug, "agent:planner", "agent:worker") == (1, 1)   # the worker failed
    assert debug.total_tool_calls == 0 and debug.total_messages == len(DEBUG)
    assert "human" not in debug.nodes                                # no input record in this shape


# ----------------------------------------------------------- shape 3: plain
def test_plain_transitions(plain):
    assert sorted(plain.nodes) == ["agent:agent", "agent:tools", "graph", "tool:search"]
    assert edge(plain, "graph", "agent:agent") == (1, 0)
    assert edge(plain, "agent:agent", "agent:tools") == (1, 0)       # declared by "next", counted once
    assert edge(plain, "agent:tools", "agent:agent") == (1, 0)
    assert edge(plain, "agent:agent", "tool:search") == (2, 0)       # two entries in tool_calls
    assert plain.total_tool_calls == 2


def test_end_sentinel_is_not_a_node(plain):
    assert "agent:__end__" not in plain.nodes
    assert not any("__end__" in n for n in plain.nodes)


def test_self_transition_adds_no_edge(tmp_path):
    records = [{"node": "agent", "next": "agent", "step": 1},
               {"node": "agent", "next": "tools", "step": 2}]
    g = LangGraphParser().parse(str(write(tmp_path / "loop.jsonl", records)))
    assert g.get_edge("agent:agent", "agent:agent") is None
    assert edge(g, "agent:agent", "agent:tools") == (1, 0)


def test_repeated_records_for_one_node_do_not_inflate_transitions(tmp_path):
    records = [{"event": "on_chain_start", "name": "agent", "metadata": {"langgraph_node": "agent"}},
               {"event": "on_chat_model_start", "name": "gpt", "metadata": {"langgraph_node": "agent"}},
               {"event": "on_chat_model_end", "name": "gpt", "metadata": {"langgraph_node": "agent"}},
               {"event": "on_chain_end", "name": "agent", "metadata": {"langgraph_node": "agent"}}]
    g = LangGraphParser().parse(str(write(tmp_path / "same.jsonl", records)))
    assert edge(g, "graph", "agent:agent") == (1, 0)
    assert g.nodes["graph"].metadata["transitions"] == 1


# ------------------------------------------------------------- multi-agent
def test_multi_node_graph_has_structure(tmp_path):
    """A supervisor fanning out to two workers that share a tool: the shared tool closes triangles."""
    records = [
        {"node": "supervisor", "next": ["research", "write"], "step": 1},
        {"node": "research", "from": "supervisor", "tool_calls": [{"name": "search"}], "step": 2},
        {"node": "write", "from": "supervisor", "tool_calls": [{"name": "search"}], "step": 3},
        {"node": "supervisor", "from": "write", "step": 4},
    ]
    g = LangGraphParser().parse(str(write(tmp_path / "fanout.jsonl", records)))
    assert {"agent:supervisor", "agent:research", "agent:write", "tool:search"} <= set(g.nodes)
    assert edge(g, "agent:supervisor", "agent:research") == (1, 0)
    assert g.total_tool_calls == 2
    result = AgentFIScanner(g).scan()
    assert 0 <= result.fi <= 1 and result.node_count == len(g.nodes)


def test_triggers_name_the_predecessor():
    assert trigger_source("agent") == "agent"
    assert trigger_source("start:agent") == "__start__"
    assert trigger_source("branch:agent:should_continue:tools") == "agent"
    assert trigger_source("branch:to") == ""                  # too short to name a source
    assert trigger_source("") == "" and trigger_source(None) == ""


# ------------------------------------------------------------ fail-soft input
def test_malformed_lines_are_skipped_not_fatal(tmp_path):
    f = tmp_path / "noisy.jsonl"
    f.write_text("\n".join([json.dumps(EVENTS[1]), "{broken", "", "[]", json.dumps(EVENTS[3])]) + "\n",
                 encoding="utf-8")
    parser = LangGraphParser()
    g = parser.parse(str(f))
    assert parser.skipped_records == 2 and g.skipped_records == 2
    assert g.total_messages == 2 and "agent:agent" in g.nodes and g.has_data


def test_records_that_are_not_langgraph_are_skipped(tmp_path):
    records = [{"hello": "world"}, {"type": "user", "message": {"content": "hi"}}, EVENTS[1]]
    parser = LangGraphParser()
    g = parser.parse(str(write(tmp_path / "mixed.jsonl", records)))
    assert parser.skipped_records == 2 and g.total_messages == 1


@pytest.mark.parametrize("name,text", [("empty.jsonl", ""), ("blank.jsonl", "\n\n"), ("none.json", "[]")])
def test_empty_trace(tmp_path, name, text):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    g = LangGraphParser().parse(str(f))
    assert sorted(g.nodes) == ["graph"]
    assert not g.has_data and g.total_tool_calls == 0
    assert AgentFIScanner(g).scan().fi == 0.0


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        LangGraphParser().parse(str(tmp_path / "nope.jsonl"))
    with pytest.raises(NotADirectoryError):
        LangGraphParser().parse_directory(str(tmp_path / "nope"))


def test_document_and_jsonl_agree(tmp_path):
    lines = LangGraphParser().parse(str(write(tmp_path / "a.jsonl", EVENTS)))
    array = LangGraphParser().parse(str(write(tmp_path / "b.json", EVENTS, as_lines=False)))
    wrapped = tmp_path / "c.json"
    wrapped.write_text(json.dumps({"graph": "ReActGraph", "events": EVENTS}), encoding="utf-8")
    nested = LangGraphParser().parse(str(wrapped))
    for other in (array, nested):
        assert {(e.source, e.target, e.weight, e.errors) for e in other.edges} == \
               {(e.source, e.target, e.weight, e.errors) for e in lines.edges}
        assert other.total_tool_calls == lines.total_tool_calls


def test_include_human_false(tmp_path):
    g = LangGraphParser(include_human=False).parse(str(write(tmp_path / "e.jsonl", EVENTS)))
    assert "human" not in g.nodes


def test_parse_directory(tmp_path):
    write(tmp_path / "trace-1.jsonl", EVENTS)
    write(tmp_path / "trace-2.json", DEBUG, as_lines=False)
    (tmp_path / "tsconfig.json").write_text(json.dumps({"compilerOptions": {}}), encoding="utf-8")
    graphs = LangGraphParser().parse_directory(str(tmp_path))
    assert [g.session_id for g in graphs] == ["trace-1", "trace-2"]


# -------------------------------------------------------------- auto-detect
@pytest.mark.parametrize("records", [EVENTS, DEBUG, PLAIN])
def test_detected_and_routed(tmp_path, records):
    path = write(tmp_path / "trace.jsonl", records)
    assert detect_format(path) == LANGGRAPH
    auto = AutoParser()
    g = auto.parse(str(path))
    assert auto.last_format == LANGGRAPH and g.has_data


def test_record_predicate_rejects_other_formats():
    assert all(looks_like_langgraph_record(r) for r in EVENTS + DEBUG + PLAIN)
    assert not looks_like_langgraph_record({"type": "assistant", "message": {"role": "assistant", "content": []}})
    assert not looks_like_langgraph_record({"agent": "Researcher", "tool": "search", "status": "done"})
    assert not looks_like_langgraph_record({"node": "agent"})      # a node name alone says nothing
    assert not looks_like_langgraph_record({"files": [], "version": "1.0"})     # a Cursor trace record
    assert not looks_like_langgraph_record("a string") and not looks_like_langgraph_record(None)


def test_baseline_learns_from_traces(tmp_path):
    write(tmp_path / "trace-1.jsonl", EVENTS)
    write(tmp_path / "trace-2.jsonl", EVENTS)
    baseline = BaselineLearner().learn([str(tmp_path)])
    assert baseline.learned_from == 2
    assert {"search", "calculator"} <= baseline.known_tools
    assert ("agent:agent", "agent:tools") in baseline.known_links
