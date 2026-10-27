# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from conftest import session_graph
from test_anomaly import make_baseline

from agent_certify import AgentFIScanner, AnomalyDetector, OTelExporter, Policy, PolicyRule
from agent_certify.cli import main


def _scan(g, perspective="engineering"):
    return AgentFIScanner(g, perspective=perspective).scan()


def _otlp_span(exporter, span):
    doc = exporter.to_otlp_json(span)
    return doc, doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]


def _attrs(lst):
    return {a["key"]: a["value"] for a in lst}


def test_span_attributes_and_events():
    g = session_graph("s1", {"Bash": 10, "deploy": 10}, errors=3)          # new tool + 15% errors
    r = _scan(g)
    report = AnomalyDetector(make_baseline()).detect(g, r)
    span = OTelExporter().export_scan(g, r, report)
    assert span.name == "agent_certify.scan"
    assert span.attributes["agent_certify.fi"] == 1.0
    assert span.attributes["agent_certify.node_count"] == 3
    assert span.attributes["agent_certify.edge_count"] == 2
    assert span.attributes["agent_certify.bridge_count"] == 2
    assert span.attributes["agent_certify.perspective"] == "engineering"
    assert span.attributes["agent_certify.session_id"] == "s1"
    assert span.attributes["agent_certify.anomaly_count"] == len(report.anomalies)
    names = [e["name"] for e in span.events]
    assert "anomaly.new_tool" in names and "anomaly.error_rate" in names
    assert span.status == "ERROR"                                            # a critical anomaly
    assert "New tool never seen: deploy" in span.status_message


def test_warnings_only_stay_ok():
    g = session_graph("s2", {"Bash": 10, "Read": 6, "Write": 4}, errors=1, cross_links=1)   # new link: warning
    r = _scan(g)
    report = AnomalyDetector(make_baseline(fi_std=1.0)).detect(g, r)
    assert report.anomalies and not report.has_critical
    assert OTelExporter().export_scan(g, r, report).status == "OK"


def test_policy_violation_sets_error():
    g = session_graph("s3", {"Bash": 1})
    violations = Policy([PolicyRule("forbidden_tool", "Bash", "warning", "")]).check(g)
    span = OTelExporter().export_scan(g, _scan(g), violations=violations)
    assert span.status == "ERROR"
    assert span.events[0]["name"] == "policy_violation.forbidden_tool"
    assert span.events[0]["attributes"]["rule_target"] == "Bash"
    assert span.attributes["agent_certify.policy_violation_count"] == 1


def test_otlp_json_structure():
    g = session_graph("s4", {"Bash": 2, "deploy": 1})
    r = _scan(g)
    start = datetime.now(timezone.utc) - timedelta(milliseconds=250)
    exporter = OTelExporter()
    span = exporter.export_scan(g, r, AnomalyDetector(make_baseline()).detect(g, r), start_time=start)
    doc, s = _otlp_span(exporter, span)

    resource = _attrs(doc["resourceSpans"][0]["resource"]["attributes"])
    assert resource["service.name"] == {"stringValue": "agent-certify"}
    assert doc["resourceSpans"][0]["scopeSpans"][0]["scope"]["name"] == "agent_certify"
    assert re.fullmatch(r"[0-9a-f]{32}", s["traceId"]) and re.fullmatch(r"[0-9a-f]{16}", s["spanId"])
    assert s["kind"] == 1                                                    # SPAN_KIND_INTERNAL
    assert int(s["endTimeUnixNano"]) - int(s["startTimeUnixNano"]) >= 250_000_000
    attrs = _attrs(s["attributes"])
    assert attrs["agent_certify.fi"] == {"doubleValue": 1.0}
    assert attrs["agent_certify.node_count"] == {"intValue": "3"}            # int64 as a string
    assert attrs["agent_certify.session_id"] == {"stringValue": "s4"}
    assert s["status"]["code"] == 2 and s["status"]["message"]
    event = s["events"][0]
    assert set(event) == {"timeUnixNano", "name", "attributes"}
    assert _attrs(event["attributes"])["severity"] == {"stringValue": "critical"}
    json.dumps(doc)                                                          # serialisable as-is


def test_value_types():
    from agent_certify.otel import _value
    assert _value(True) == {"boolValue": True}                                # not intValue
    assert _value(3) == {"intValue": "3"}
    assert _value(0.25) == {"doubleValue": 0.25}
    assert _value("x") == {"stringValue": "x"}


def test_trace_id_groups_a_session():
    exporter = OTelExporter()
    g1, g2 = session_graph("same", {"Bash": 1}), session_graph("other", {"Bash": 1})
    a, b = exporter.export_scan(g1, _scan(g1)), exporter.export_scan(g1, _scan(g1))
    assert a.trace_id == b.trace_id and a.span_id != b.span_id
    assert exporter.export_scan(g2, _scan(g2)).trace_id != a.trace_id


def test_write_appends_jsonl(tmp_path, capsys):
    exporter = OTelExporter()
    g = session_graph("s5", {"Bash": 1})
    path = tmp_path / "t" / "traces.jsonl"
    for _ in range(2):
        exporter.write(exporter.export_scan(g, _scan(g)), path)
    lines = path.read_text().splitlines()
    assert len(lines) == 2 and all("resourceSpans" in json.loads(line) for line in lines)
    assert exporter.write(exporter.export_scan(g, _scan(g))) == Path(".agent-certify/traces.jsonl")
    exporter.write(exporter.export_scan(g, _scan(g)), stdout=True)
    assert json.loads(capsys.readouterr().out)["resourceSpans"]


def test_cli_scan_otel(session_dir, capsys):
    session = str(session_dir / "sess-1.jsonl")
    assert main(["scan", session, "--otel"]) == 0
    captured = capsys.readouterr()
    assert "Fragility Index" in captured.out
    assert "OTel: 1 span(s) appended to .agent-certify/traces.jsonl" in captured.err
    line = json.loads(Path(".agent-certify/traces.jsonl").read_text().splitlines()[-1])
    span = line["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert _attrs(span["attributes"])["agent_certify.session_id"] == {"stringValue": "sess-1"}

    # --otel-stdout: stdout carries only OTLP lines; the report moves to stderr.
    assert main(["scan", session, "--otel-stdout"]) == 0
    captured = capsys.readouterr()
    assert [json.loads(x)["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"]
            for x in captured.out.splitlines()] == ["agent_certify.scan"]
    assert "Fragility Index" in captured.err

    # A directory: one span per session.
    assert main(["scan", str(session_dir.parent), "--otel", "--otel-file", "dir.jsonl"]) == 0
    assert len(Path("dir.jsonl").read_text().splitlines()) == 1


def test_cli_watch_otel(session_dir, capsys):
    session = str(session_dir / "sess-1.jsonl")
    assert main(["watch", session, "--interval", "0.05", "--scans", "1", "--otel", "--otel-file", "w.jsonl"]) == 0
    assert len(Path("w.jsonl").read_text().splitlines()) == 1
    capsys.readouterr()
    assert main(["watch", session, "--interval", "0.05", "--scans", "1", "--otel-stdout"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["resourceSpans"]
    assert "Final state" in captured.err
