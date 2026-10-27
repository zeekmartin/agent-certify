# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
"""OpenTelemetry export without the OpenTelemetry SDK.

Each scan becomes one span, ``agent_certify.scan``, carrying the structural
metrics as attributes; anomalies and policy violations become span events.
A critical anomaly or any policy violation sets the span status to ERROR.

Spans are written as OTLP/JSON (the protobuf JSON mapping used by OTLP/HTTP
with ``Content-Type: application/json``): one ``{"resourceSpans": [...]}``
object per line. That is the layout the OpenTelemetry Collector's ``file``
exporter writes and its ``otlpjsonfile`` receiver reads, so a collector can
pick the file up and forward it to Jaeger, Grafana Tempo, Datadog, etc.
Trace and span ids are lowercase hex, as OTLP/JSON requires.

All scans of one session share a trace id (derived from the session id), so a
``watch`` run shows up as one trace with a span per scan cycle.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from agent_certify.anomaly import AnomalyReport
from agent_certify.graph import AgentGraph
from agent_certify.policy import PolicyViolation
from agent_certify.scanner import ScanResult

DEFAULT_TRACES_PATH = Path(".agent-certify") / "traces.jsonl"
SPAN_KIND_INTERNAL = 1
STATUS_CODES = {"UNSET": 0, "OK": 1, "ERROR": 2}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _nanos(iso: str) -> str:
    ts = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    whole = int(ts.timestamp()) * 1_000_000_000
    return str(whole + ts.microsecond * 1000)


def _value(v) -> dict:
    """An OTLP AnyValue. bool before int: bool is an int subclass."""
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}             # int64 is a string in OTLP/JSON
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


def _attrs(d: dict) -> list[dict]:
    return [{"key": k, "value": _value(v)} for k, v in d.items()]


@dataclass
class OTelSpan:
    """A lightweight OpenTelemetry-compatible span."""
    trace_id: str                                   # 32 hex chars
    span_id: str                                    # 16 hex chars
    name: str
    start_time: str                                 # ISO 8601, UTC
    end_time: str
    attributes: dict[str, str | int | float | bool]
    events: list[dict] = field(default_factory=list)    # {"name", "time", "attributes"}
    status: str = "OK"                              # "OK", "ERROR"
    status_message: str = ""


class OTelExporter:
    """Export agent-certify results as OpenTelemetry spans.

    Usage::

        exporter = OTelExporter()
        span = exporter.export_scan(graph, result, anomalies, violations)
        exporter.write(span)                      # appends to .agent-certify/traces.jsonl
        exporter.write(span, stdout=True)         # one OTLP/JSON line on stdout
    """

    def __init__(self, service_name: str = "agent-certify"):
        from agent_certify import __version__
        self.service_name = service_name
        self.version = __version__

    def export_scan(self, graph: AgentGraph, result: ScanResult,
                    anomalies: AnomalyReport | None = None,
                    violations: list[PolicyViolation] | None = None,
                    start_time: datetime | None = None) -> OTelSpan:
        """Create a span representing one scan (``start_time``: when the scan began)."""
        end = _now()
        start = start_time or end
        span = OTelSpan(
            trace_id=self._trace_id(graph.session_id),
            span_id=secrets.token_hex(8),
            name="agent_certify.scan",
            start_time=_iso(start),
            end_time=_iso(end),
            attributes={
                "agent_certify.fi": float(result.fi),
                "agent_certify.node_count": result.node_count,
                "agent_certify.edge_count": result.edge_count,
                "agent_certify.bridge_count": len(result.bridges),
                "agent_certify.components": result.components,
                "agent_certify.articulation_point_count": len(result.articulation_points),
                "agent_certify.high_level_node_count": len(result.critical_nodes),
                "agent_certify.sub_agent_count": sum(1 for n in graph.nodes.values() if n.kind == "agent"),
                "agent_certify.tool_call_count": graph.total_tool_calls,
                "agent_certify.perspective": result.perspective,
                "agent_certify.session_id": graph.session_id or "",
                "agent_certify.project": graph.project or "",
            },
        )
        reasons = []
        if anomalies is not None:
            span.attributes["agent_certify.anomaly_count"] = len(anomalies.anomalies)
            for a in anomalies.anomalies:
                attrs = {"severity": a.severity, "category": a.category, "message": a.message,
                         "baseline_value": a.baseline_value}
                if a.z_score is not None:
                    attrs["z_score"] = float(a.z_score)
                span.events.append({"name": f"anomaly.{a.category}", "time": span.end_time, "attributes": attrs})
                if a.severity == "critical":
                    span.status = "ERROR"
                    reasons.append(a.message)
        if violations is not None:
            span.attributes["agent_certify.policy_violation_count"] = len(violations)
            for v in violations:
                span.events.append({"name": f"policy_violation.{v.rule.kind}", "time": span.end_time,
                                    "attributes": {"severity": v.severity, "message": v.message,
                                                   "rule_target": v.rule.target, "observed": v.observed}})
                span.status = "ERROR"
                reasons.append(v.message)
        span.status_message = "; ".join(reasons)[:500]
        return span

    def to_otlp_json(self, span: OTelSpan) -> dict:
        """Convert to OTLP/JSON (one ExportTraceServiceRequest)."""
        status = {"code": STATUS_CODES[span.status]}
        if span.status_message:
            status["message"] = span.status_message
        return {"resourceSpans": [{
            "resource": {"attributes": _attrs({"service.name": self.service_name,
                                               "service.version": self.version})},
            "scopeSpans": [{
                "scope": {"name": "agent_certify", "version": self.version},
                "spans": [{
                    "traceId": span.trace_id,
                    "spanId": span.span_id,
                    "name": span.name,
                    "kind": SPAN_KIND_INTERNAL,
                    "startTimeUnixNano": _nanos(span.start_time),
                    "endTimeUnixNano": _nanos(span.end_time),
                    "attributes": _attrs(span.attributes),
                    "events": [{"timeUnixNano": _nanos(e["time"]), "name": e["name"],
                                "attributes": _attrs(e["attributes"])} for e in span.events],
                    "status": status,
                }],
            }],
        }]}

    def write(self, span: OTelSpan, path: str | os.PathLike | None = None, stdout: bool = False) -> Path | None:
        """Append the span as one OTLP/JSON line to ``path`` (default .agent-certify/traces.jsonl), or stdout."""
        line = json.dumps(self.to_otlp_json(span), separators=(",", ":"))
        if stdout:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            return None
        p = Path(path) if path is not None else DEFAULT_TRACES_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        return p

    @staticmethod
    def _trace_id(session_id: str | None) -> str:
        if not session_id:
            return secrets.token_hex(16)
        return hashlib.sha256(f"agent-certify:{session_id}".encode()).hexdigest()[:32]
