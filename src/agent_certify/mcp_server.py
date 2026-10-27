# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
"""agent-certify as an MCP server: an agent can scan its own topology.

Model Context Protocol over stdio: newline-delimited JSON-RPC 2.0 on
stdin/stdout, no third-party MCP package. Implements ``initialize``,
``notifications/initialized`` (and any other notification: no reply),
``ping``, ``tools/list`` and ``tools/call``.

Errors never stop the server. Protocol problems (bad JSON, unknown method,
unknown tool) are JSON-RPC errors; a tool that fails (missing session, no
baseline, unknown node...) returns a normal result with ``isError: true`` and a
message the calling agent can read and act on, as the MCP specification asks.

stdout carries protocol messages only: anything else the library would print
goes to stderr while the server runs.

Register with Claude Code::

    claude mcp add agent-certify -- agent-certify mcp

Current session detection (when a tool's ``session_path`` is omitted):

1. ``CLAUDE_CODE_SESSION_ID`` (set by Claude Code for its child processes),
   or ``CLAUDE_SESSION_ID``: ``~/.claude/projects/*/<id>.jsonl``
2. the newest session of the project in the working directory
   (``~/.claude/projects/<cwd with separators as dashes>/``)
3. the newest session anywhere under ``~/.claude/projects/``
"""
from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

from agent_certify.anomaly import AnomalyDetector
from agent_certify.baseline import DEFAULT_BASELINE_PATH, load_baseline
from agent_certify.blast import BlastRadiusAnalyzer
from agent_certify.graph import AgentGraph
from agent_certify.parser.auto import AutoParser
from agent_certify.parser.mcp_logs import project_key
from agent_certify.policy import DEFAULT_POLICY_PATH, Policy
from agent_certify.scanner import HIGH, AgentFIScanner, Perspective, ScanResult
from agent_certify.watcher import latest_session

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SESSION_ENV_VARS = ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID")
PERSPECTIVES = ["engineering", "risk", "compliance", "monitoring"]

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603

_SESSION = {"type": "string",
            "description": "Session transcript (.jsonl), Cursor .agent-trace, or a project folder (newest session). "
                           "Omit to use the current session."}

TOOLS = [
    {
        "name": "scan_topology",
        "description": "Scan the structural topology of the current agent session. Returns the Fragility Index, "
                       "node count, edge count, bridges, and node classifications.",
        "inputSchema": {"type": "object", "properties": {
            "session_path": _SESSION,
            "perspective": {"type": "string", "enum": PERSPECTIVES, "default": "engineering",
                            "description": "Vocabulary for node roles."},
        }, "additionalProperties": False},
    },
    {
        "name": "check_anomalies",
        "description": "Compare the current session against the learned baseline. Returns any structural "
                       "anomalies detected.",
        "inputSchema": {"type": "object", "properties": {
            "session_path": _SESSION,
            "baseline_path": {"type": "string",
                              "description": f"Baseline JSON (default {DEFAULT_BASELINE_PATH.as_posix()})."},
        }, "additionalProperties": False},
    },
    {
        "name": "blast_radius",
        "description": "Analyze what happens if a specific node is compromised or removed. Returns the blast "
                       "radius, affected nodes, and whether the system fragments.",
        "inputSchema": {"type": "object", "properties": {
            "session_path": _SESSION,
            "node": {"type": "string", "description": "Node id or name, e.g. 'claude', 'bash', 'tool:Bash'."},
        }, "required": ["node"], "additionalProperties": False},
    },
    {
        "name": "check_policy",
        "description": "Check the current session against the policy rules. Returns any violations.",
        "inputSchema": {"type": "object", "properties": {
            "session_path": _SESSION,
            "policy_path": {"type": "string",
                            "description": f"Policy JSON (default {DEFAULT_POLICY_PATH.as_posix()})."},
        }, "additionalProperties": False},
    },
    {
        "name": "topology_summary",
        "description": "Get a brief natural-language summary of the current agent system's structural health. "
                       "Designed to be read by an AI agent about itself.",
        "inputSchema": {"type": "object", "properties": {"session_path": _SESSION}, "additionalProperties": False},
    },
]


class ToolError(Exception):
    """A tool could not run; reported to the caller as an ``isError`` result."""


# --------------------------------------------------------------- sessions
def find_current_session(projects_root: Path | None = None, cwd: str | None = None,
                         env: dict | None = None) -> tuple[Path, str]:
    """(session file, how it was found). Raises ToolError when there is none."""
    root = projects_root or Path.home() / ".claude" / "projects"
    env = os.environ if env is None else env
    if not root.is_dir():
        raise ToolError(f"No Claude Code projects folder at {root}; pass session_path explicitly.")
    for var in SESSION_ENV_VARS:
        sid = env.get(var)
        if sid:
            hits = sorted(root.glob(f"*/{sid}.jsonl"))
            if hits:
                return hits[0], f"{var}={sid}"
    here = cwd if cwd is not None else os.getcwd()
    project = root / project_key(here)
    newest = latest_session(project) if project.is_dir() else None
    if newest:
        return newest, f"newest session of project {project.name}"
    candidates = [f for d in root.iterdir() if d.is_dir() for f in d.glob("*.jsonl")]
    if not candidates:
        raise ToolError(f"No sessions under {root}; pass session_path explicitly.")
    return max(candidates, key=lambda f: f.stat().st_mtime), "newest session on this machine"


# ------------------------------------------------------------ summaries
def _pieces(n: int, all_single: bool) -> str:
    return f"{n} isolated pieces" if all_single else f"{n} pieces"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _readable(graph: AgentGraph, node_ids: list[str]) -> str:
    """Tools by name, sub-agents by type ("2 general-purpose sub-agents"), others by id."""
    names, agent_types = [], {}
    for nid in node_ids:
        node = graph.nodes[nid]
        if node.kind == "agent":
            t = graph.role(nid).split(":", 1)[1]
            agent_types[t] = agent_types.get(t, 0) + 1
        else:
            names.append(node.name if node.kind in ("tool", "file") else nid)
    names += [f"the {t} sub-agent" if c == 1 else f"{c} {t} sub-agents" for t, c in agent_types.items()]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def describe(graph: AgentGraph, result: ScanResult, anomalies=None, violations=None,
             baseline_note: str = "", policy_note: str = "", checks: bool = True,
             subject: str = "Your current session") -> str:
    """A plain-language account of the topology, addressed to the agent itself.

    ``checks=False`` leaves out the baseline and policy sentences (structure
    only). ``subject`` opens the text ("This session" for one the caller named).
    """
    kinds = {k: [n for n in graph.nodes.values() if n.kind == k] for k in ("orchestrator", "agent", "tool", "file")}
    parts = []
    if kinds["orchestrator"]:
        parts.append(f"{len(kinds['orchestrator'])} orchestrator")
    for k, word in (("agent", "sub-agent"), ("tool", "tool"), ("file", "file")):
        if kinds[k]:
            parts.append(f"{len(kinds[k])} {word}{'s' if len(kinds[k]) != 1 else ''}")
    if "human" in graph.nodes:
        parts.append("the human")
    links = result.edge_count
    out = [(f"{subject} has {result.node_count} nodes ({', '.join(parts)}) and {links} "
           f"link{'s' if links != 1 else ''}.")]

    fragile = len(result.fragile_edges)
    if links == 0:
        out.append("There are no links yet: nothing has been called.")
    elif fragile == links:
        out.append("Fragility Index is 1.0 — every connection is a single point of failure with no backup path.")
    elif fragile == 0:
        out.append("Fragility Index is 0.0 — every connection sits in a triangle, so each has a backup path.")
    else:
        cause = ", which here come from sub-agents sharing tools with the orchestrator" if kinds["agent"] else ""
        out.append(f"Fragility Index is {result.fi:.2f} — {fragile} of {links} links have no backup path; "
                   f"the other {links - fragile} sit in triangles{cause}.")

    if kinds["agent"] and kinds["tool"]:
        orch = {n.id for n in kinds["orchestrator"]}
        agent_ids = {a.id for a in kinds["agent"]}
        shared = sorted(t.name for t in kinds["tool"]
                        if graph.neighbors(t.id) & orch and graph.neighbors(t.id) & agent_ids)
        types = sorted({graph.role(a.id).split(":", 1)[1] for a in kinds["agent"]})
        verb = "shares" if len(kinds["agent"]) == 1 else "share"
        out.append(f"{_plural(len(kinds['agent']), 'sub-agent')} ({', '.join(types)}) "
                   + (f"{verb} {_plural(len(shared), 'tool')} with the orchestrator "
                      f"({', '.join(shared[:5])}{'…' if len(shared) > 5 else ''})."
                      if shared else "only use tools the orchestrator does not call itself."))

    keystones = sorted((n for n, lvl in result.node_levels.items() if lvl == HIGH),
                       key=lambda n: (graph.nodes[n].kind != "orchestrator", -graph.nodes[n].call_count, n))
    if keystones:
        blast = BlastRadiusAnalyzer(graph)
        first = keystones[0]
        node = graph.nodes[first]
        who = f"The orchestrator ({node.name})" if node.kind == "orchestrator" else _readable(graph, [first])
        b = blast.analyze(first)
        single = all(len(c) == 1 for c in b.components_after)
        if b.system_fragmented:
            effect = f"if it fails, the system fragments into {_pieces(len(b.components_after), single)}"
        else:
            effect = f"removing it raises FI from {result.fi:.2f} to {b.remaining_fi:.2f}"
        if len(keystones) == 1:
            out.append(f"{who} is the sole keystone: {effect}.")
        else:
            out.append(f"{who} is the main keystone: {effect}. Other keystones: {_readable(graph, keystones[1:])}.")
    elif links:
        out.append("No single node is a keystone: removing any one leaves the structure largely intact.")

    tools = kinds["tool"]
    if tools:
        top = max(tools, key=lambda n: n.call_count)
        errs = sum(n.error_count for n in graph.nodes.values())
        line = f"Most-used tool: {top.name} ({top.call_count} calls"
        line += f", {top.error_count} failed)." if top.error_count else ")."
        if errs and graph.total_tool_calls:
            line += f" Overall {errs / graph.total_tool_calls:.1%} of {graph.total_tool_calls} tool calls failed."
        out.append(line)

    if not checks:
        pass
    elif anomalies is None:
        out.append(baseline_note or "No baseline is loaded, so anomalies can't be judged "
                                    "(run `agent-certify learn` to create one).")
    elif not anomalies.anomalies:
        out.append(f"No anomalies detected against the baseline of {anomalies.learned_from} sessions.")
    else:
        top = "; ".join(a.message for a in anomalies.anomalies[:3])
        more = f" (and {len(anomalies.anomalies) - 3} more)" if len(anomalies.anomalies) > 3 else ""
        out.append(f"Against the baseline of {anomalies.learned_from} sessions: {anomalies.summary} — {top}{more}.")

    if not checks:
        pass
    elif violations is None:
        out.append(policy_note or "No policy is loaded.")
    elif not violations:
        out.append("No policy violations.")
    else:
        out.append(f"{len(violations)} policy violation{'s' if len(violations) != 1 else ''}: "
                   + "; ".join(f"{v.severity.upper()} {v.message}" for v in violations[:3])
                   + (" …" if len(violations) > 3 else "") + ".")

    if links and fragile == links and not kinds["agent"] and not kinds["file"]:
        out.append("This is the usual shape of a single-agent session — one orchestrator calling each tool "
                   "directly; redundancy only appears when sub-agents share tools.")
    return " ".join(out)


# ---------------------------------------------------------------- server
class AgentCertifyMCPServer:
    """MCP server exposing agent-certify tools via stdio JSON-RPC.

    ``handle(message)`` processes one decoded JSON-RPC message and returns the
    response (``None`` for notifications); ``run()`` is the stdio loop.
    ``projects_root``, ``cwd`` and ``env`` override session auto-detection.
    """

    TOOLS = TOOLS

    def __init__(self, projects_root: str | os.PathLike | None = None, cwd: str | None = None,
                 env: dict | None = None):
        from agent_certify import __version__
        self.version = __version__
        self.projects_root = Path(projects_root) if projects_root else None
        self.cwd = cwd
        self.env = env
        self.protocol_version = PROTOCOL_VERSIONS[0]
        self._handlers: dict[str, Callable[..., dict]] = {
            "scan_topology": self._scan_topology,
            "check_anomalies": self._check_anomalies,
            "blast_radius": self._blast_radius,
            "check_policy": self._check_policy,
            "topology_summary": self._topology_summary,
        }

    # ------------------------------------------------------------ transport
    def run(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
        """Read JSON-RPC messages from stdin until EOF; write responses to stdout."""
        inp = stdin or sys.stdin.buffer
        out = stdout or sys.stdout.buffer
        real_stdout, sys.stdout = sys.stdout, sys.stderr     # protect the protocol channel
        try:
            for raw in inp:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                response = self.handle_line(line)
                if response is not None:
                    out.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
                    out.flush()
        finally:
            sys.stdout = real_stdout

    def handle_line(self, line: str) -> Any:
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            return self._error(None, PARSE_ERROR, f"Parse error: {exc}")
        if isinstance(message, list):                        # JSON-RPC batch (2025-03-26)
            replies = [r for r in (self.handle(m) for m in message) if r is not None]
            return replies or None
        return self.handle(message)

    def handle(self, message: Any) -> dict | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
            return self._error(message.get("id") if isinstance(message, dict) else None,
                               INVALID_REQUEST, "Invalid Request")
        is_notification = "id" not in message
        try:
            response = self._dispatch(message)
        except Exception as exc:  # noqa: BLE001 — one bad request must never kill the server
            response = self._error(message.get("id"), INTERNAL_ERROR, f"Internal error: {exc}")
        return None if is_notification else response

    def _dispatch(self, request: dict) -> dict | None:
        method = request["method"]
        if method == "initialize":
            return self._handle_initialize(request)
        if method.startswith("notifications/"):
            return None
        if method == "ping":
            return self._result(request, {})
        if method == "tools/list":
            return self._result(request, {"tools": self.TOOLS})
        if method == "tools/call":
            return self._handle_tool_call(request)
        return self._error(request.get("id"), METHOD_NOT_FOUND, f"Method not found: {method}")

    def _handle_initialize(self, request: dict) -> dict:
        asked = (request.get("params") or {}).get("protocolVersion")
        self.protocol_version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return self._result(request, {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "agent-certify", "version": self.version},
            "instructions": "Structural verification of this agent session: call topology_summary for a "
                            "plain-language health check, scan_topology for the metrics, blast_radius before "
                            "trusting a single node, check_anomalies / check_policy against the project's "
                            ".agent-certify/ baseline and policy.",
        })

    def _handle_tool_call(self, request: dict) -> dict:
        params = request.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = self._handlers.get(name)
        if handler is None:
            return self._error(request.get("id"), INVALID_PARAMS, f"Unknown tool: {name}")
        if not isinstance(arguments, dict):
            return self._error(request.get("id"), INVALID_PARAMS, "arguments must be an object")
        schema = next(t["inputSchema"] for t in self.TOOLS if t["name"] == name)
        unknown = set(arguments) - set(schema["properties"])
        missing = set(schema.get("required", [])) - set(arguments)
        try:
            if unknown:
                raise ToolError(f"Unknown argument(s) for {name}: {', '.join(sorted(unknown))}")
            if missing:
                raise ToolError(f"Missing required argument(s) for {name}: {', '.join(sorted(missing))}")
            payload = handler(**arguments)
        except ToolError as exc:
            return self._result(request, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
        except Exception as exc:  # noqa: BLE001 — report any tool failure to the caller, keep serving
            return self._result(request, {"content": [{"type": "text", "text": f"{name} failed: {exc}"}],
                                          "isError": True})
        result = {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}
        if self.protocol_version >= "2025-06-18":
            result["structuredContent"] = payload
        return self._result(request, result)

    @staticmethod
    def _result(request: dict, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}

    @staticmethod
    def _error(msg_id, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    # ---------------------------------------------------------------- tools
    def _load(self, session_path: str | None) -> tuple[AgentGraph, str, str]:
        """(graph, session file, how it was found)."""
        if session_path:
            p = Path(os.path.expandvars(os.path.expanduser(session_path)))
            if not p.exists():
                raise ToolError(f"Session not found: {p}")
            how = "given"
            if p.is_dir() and any(p.glob("*.jsonl")):
                p, how = latest_session(p), f"newest session in {p}"
        else:
            p, how = find_current_session(self.projects_root, self.cwd, self.env)
        try:
            return AutoParser().parse(str(p)), str(p), how
        except (ValueError, OSError) as exc:
            raise ToolError(f"Cannot read {p}: {exc}") from exc

    def _baseline(self, baseline_path: str | None, required: bool):
        p = Path(baseline_path) if baseline_path else DEFAULT_BASELINE_PATH
        if not p.is_file():
            if required:
                raise ToolError(f"No baseline at {p.as_posix()}. Learn one first: "
                                "`agent-certify learn ~/.claude/projects/<project>/`.")
            return None, (f"No baseline at {p.as_posix()}, so anomalies can't be judged "
                          "(run `agent-certify learn` to create one).")
        try:
            return load_baseline(p), p.as_posix()
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ToolError(f"{p.as_posix()} is not a valid baseline: {exc}") from exc

    def _policy(self, policy_path: str | None, required: bool):
        p = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
        if not p.is_file():
            if required:
                raise ToolError(f"No policy at {p.as_posix()}. Draft one with `agent-certify suggest-policy`.")
            return None, f"No policy at {p.as_posix()}."
        try:
            return Policy.load(p), p.as_posix()
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ToolError(f"{p.as_posix()} is not a valid policy: {exc}") from exc

    def _scan_topology(self, session_path: str | None = None, perspective: str = "engineering") -> dict:
        if perspective.lower() not in PERSPECTIVES + ["classic"]:
            raise ToolError(f"Unknown perspective {perspective!r}; choose from {', '.join(PERSPECTIVES)}.")
        graph, path, how = self._load(session_path)
        r = AgentFIScanner(graph, perspective=perspective).scan()
        return {
            "session": path,
            "session_source": how,
            "fi": round(r.fi, 6),
            "node_count": r.node_count,
            "edge_count": r.edge_count,
            "bridge_count": len(r.bridges),
            "components": r.components,
            "articulation_points": r.articulation_points,
            "perspective": r.perspective,
            "labels": Perspective.labels(perspective),
            "nodes": [{"id": n.id, "kind": n.kind, "name": n.name, "calls": n.call_count,
                       "errors": n.error_count, "classification": r.node_classifications[n.id],
                       "level": r.node_levels[n.id]}
                      for n in sorted(graph.nodes.values(), key=lambda n: (-n.call_count, n.id))],
            "bridges": [{"source": e.source, "target": e.target} for e in r.bridges],
            "summary": describe(graph, r, checks=False, subject=_subject(how)),
        }

    def _check_anomalies(self, session_path: str | None = None, baseline_path: str | None = None) -> dict:
        baseline, source = self._baseline(baseline_path, required=True)
        graph, path, _ = self._load(session_path)
        report = AnomalyDetector(baseline, source).detect(graph, AgentFIScanner(graph).scan())
        return {
            "session": path,
            "baseline": source,
            "learned_from": baseline.learned_from,
            "anomaly_count": len(report.anomalies),
            "anomalies": [{k: getattr(a, k) for k in ("severity", "category", "message", "value", "baseline_value",
                                                       "z_score", "detail")} for a in report.anomalies],
            "summary": report.summary,
        }

    def _blast_radius(self, node: str, session_path: str | None = None) -> dict:
        graph, path, _ = self._load(session_path)
        try:
            b = BlastRadiusAnalyzer(graph).analyze(node)
        except KeyError as exc:
            raise ToolError(str(exc.args[0])) from exc
        return {
            "session": path,
            "compromised": b.compromised,
            "direct_impact": b.direct_impact,
            "total_reachable": b.total_reachable,
            "accessible_tools": b.accessible_tools,
            "baseline_fi": round(b.baseline_fi, 6),
            "remaining_fi": round(b.remaining_fi, 6),
            "system_fragmented": b.system_fragmented,
            "fragment_count": len(b.components_after),
            "recommendation": b.isolation_recommendation,
        }

    def _check_policy(self, session_path: str | None = None, policy_path: str | None = None) -> dict:
        policy, source = self._policy(policy_path, required=True)
        graph, path, _ = self._load(session_path)
        violations = policy.check(graph)
        return {
            "session": path,
            "policy": source,
            "rule_count": len(policy.rules),
            "violation_count": len(violations),
            "violations": [{"rule_kind": v.rule.kind, "target": v.rule.target, "severity": v.severity,
                            "message": v.message, "observed": v.observed} for v in violations],
            "summary": ("No policy violations." if not violations else
                        f"{len(violations)} violation(s) of {len(policy.rules)} rule(s): "
                        + "; ".join(v.message for v in violations[:3])),
        }

    def _topology_summary(self, session_path: str | None = None) -> dict:
        graph, path, how = self._load(session_path)
        r = AgentFIScanner(graph, perspective="engineering").scan()
        baseline, b_note = self._baseline(None, required=False)
        policy, p_note = self._policy(None, required=False)
        anomalies = AnomalyDetector(baseline).detect(graph, r) if baseline else None
        violations = policy.check(graph) if policy else None
        return {"session": path, "session_source": how,
                "summary": describe(graph, r, anomalies, violations, baseline_note=b_note, policy_note=p_note,
                                    subject=_subject(how))}


def _subject(how: str) -> str:
    return "This session" if how == "given" else "Your current session"


def main() -> None:
    AgentCertifyMCPServer().run()
