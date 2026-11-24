# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Command-line interface.

    agent-certify scan <session.jsonl | project-dir> [--format text|json|markdown|html] [-o FILE]
                       [--perspective engineering|risk|compliance|monitoring|classic]
                       [--baseline FILE | --no-baseline] [--policy FILE | --no-policy] [--include-mcp]
                       [--fail-on critical|warning|never]
    agent-certify watch <session.jsonl | project-dir> [--interval S] [--scans N] [--duration S]
                        [--baseline FILE | --no-baseline] [--policy FILE | --no-policy] [--perspective P]
    agent-certify learn <session.jsonl | dir>... [-o FILE]
    agent-certify suggest-policy [--baseline FILE] [-o FILE] [--force]
    agent-certify baseline accept (--tool NAME | --link "SRC -> DST" | --domain HOST) [--baseline FILE]
    agent-certify baseline reject (--tool NAME | --domain "*.cn") [--baseline FILE]
    agent-certify baseline show [--baseline FILE]
    agent-certify mcp                     # MCP server on stdio
    (scan and watch take --otel / --otel-stdout to emit OpenTelemetry spans)
    agent-certify blast <path> --node bash
    agent-certify keygen [signing.key]   # default: agent-certify.key
    agent-certify certify <path> --key signing.key [--validity-days 90] -o system.cert.json
    agent-certify verify system.cert.json <path> --public-key signing.key.pub
                         [--ignore-expiry] [--expect-system-id ID] [--allow-unsigned]

Exit codes: ``scan`` returns 2 when a finding reaches ``--fail-on`` (default:
any critical anomaly or critical policy violation); ``verify`` returns 1 on
drift or an untrusted certificate, 2 on usage errors. Every command exits 1
when its input holds no readable records.

A directory is scanned session by session and as one merged graph (every
session's agents and tools combined); ``html``, ``blast``, ``certify`` and
``verify`` use the merged graph. Anomalies and policy are evaluated per session.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import stat
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from agent_certify import __version__
from agent_certify.anomaly import (
    CALL_MIN_DELTA_CALLS,
    EGRESS_MIN_DELTA_BYTES,
    MIN_BASELINE_SESSIONS,
    AnomalyDetector,
    AnomalyReport,
)
from agent_certify.baseline import (
    DEFAULT_BASELINE_PATH,
    Baseline,
    BaselineLearner,
    carry_overrides,
    load_baseline,
    normalise_tool,
    parse_link,
)
from agent_certify.blast import BlastRadiusAnalyzer
from agent_certify.certificate import (
    DEFAULT_VALIDITY_DAYS,
    AgentCertificate,
    _private_key_hex,
    _public_key_hex,
    egress_violations,
    generate_keypair,
)
from agent_certify.domains import domain_matches, normalise_pattern
from agent_certify.graph import AgentGraph
from agent_certify.mcp_server import AgentCertifyMCPServer
from agent_certify.otel import DEFAULT_TRACES_PATH, OTelExporter
from agent_certify.parser import AutoParser, MCPLogsParser
from agent_certify.parser.auto import is_trace_dir
from agent_certify.paths import expand_cli, hash_project
from agent_certify.policy import DEFAULT_POLICY_PATH, Policy, PolicyGenerator, PolicyViolation
from agent_certify.regions import OFFLINE, RegionResolver, load_geoip
from agent_certify.scanner import AgentFIScanner, Perspective, ScanResult
from agent_certify.watcher import SessionWatcher, latest_session

DEFAULT_PATH = "~/.claude/projects"
FAIL_EXIT = 2
#: `certify` refusing to sign is a failed command, not a finding in a report:
#: exit 1, the way `verify` reports drift.
CERTIFY_REFUSED = 1

#: ``verify`` exit codes. 0 and 1 are the answer to "does this system still
#: match its certificate?"; 2 is the usual "you called it wrong"; 3 exists
#: because there is a third answer, and reporting it as either of the first two
#: would be a lie:
#:
#: * **0** — valid: signature, validity window, topology and egress coverage
#:   all checked and all in order.
#: * **1** — invalid: something was checked and did not match.
#: * **2** — the command line was wrong (missing argument, unreadable key).
#: * **3** — signature and topology valid, **egress coverage not verifiable**:
#:   the certificate carries no list of observed destinations and the session
#:   reached some. Nobody can say whether those were the certified ones.
#:   ``--accept-unverified-egress`` turns this case into 0, deliberately.
VERIFY_OK, VERIFY_INVALID, VERIFY_USAGE, VERIFY_EGRESS_UNVERIFIABLE = 0, 1, 2, 3


def _path(p: str) -> Path:
    """A path typed by the user: ``~`` and environment variables are expanded, as a shell would."""
    return expand_cli(p)


def _warn(message: str) -> None:
    print(f"WARNING: {message}", file=sys.stderr)


def load(path: str, include_mcp: bool = False) -> tuple[list[AgentGraph], AgentGraph]:
    """(per-session graphs, merged graph) for a session file or a directory.

    The format is detected from the content (Claude Code transcript, Cursor
    Agent Trace, MCP server log, CrewAI execution log, LangGraph trace).
    ``include_mcp`` adds each session's calls from the MCP server logs.
    """
    p = _path(path)
    parser = AutoParser()
    try:
        if p.is_file() or is_trace_dir(p):
            graphs = [parser.parse(str(p))]
        elif p.is_dir():
            graphs = parser.parse_directory(str(p))
            if not graphs:
                raise SystemExit(f"agent-certify: no sessions (.jsonl, .json, .agent-trace) found under {p}")
        else:
            raise SystemExit(f"agent-certify: {p} does not exist")
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}") from exc
    graphs = _usable(graphs, p)
    if include_mcp:
        mcp = MCPLogsParser()
        enriched, added = [], 0
        for g in graphs:
            enriched.append(mcp.enrich(g))
            added += mcp.added_calls
        graphs = enriched
        print(f"MCP logs: {added} call(s) added from {len(mcp.find_logs())} log file(s) on this machine"
              if mcp.roots else "MCP logs: no log directory on this platform", file=sys.stderr)
    if len(graphs) == 1:
        return graphs, graphs[0]
    return graphs, AgentGraph.merge(graphs, session_id=f"{p.name} ({len(graphs)} sessions)")


def _name(g: AgentGraph) -> str:
    return Path(g.source).name if g.source else (g.session_id or "session")


def _usable(graphs: list[AgentGraph], p: Path) -> list[AgentGraph]:
    """Warn once per file with unreadable records; drop (or refuse) files with nothing usable."""
    usable = [g for g in graphs if g.has_data]
    if not usable:
        target = _name(graphs[0]) if len(graphs) == 1 else p.name or str(p)
        raise SystemExit(f"No readable records in {target}")
    for g in usable:
        if g.skipped_records:
            print(f"WARNING: {_name(g)}: {g.skipped_records} of {g.total_records} records unreadable, skipped",
                  file=sys.stderr)
    if len(usable) < len(graphs):
        left_out = len(graphs) - len(usable)
        print(f"agent-certify: {left_out} file(s) with no readable records left out", file=sys.stderr)
    return usable


# ---------------------------------------------------------------- formatting
def _fmt_duration(s: float | None) -> str:
    if not s:
        return "-"
    return f"{s / 3600:.1f}h" if s >= 3600 else f"{s / 60:.0f}m"


_LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


def _skipped_note(g: AgentGraph) -> str | None:
    """A line about unreadable records, or None when every record was read."""
    if not g.skipped_records:
        return None
    total = max(g.total_records, g.skipped_records)
    return (f"Skipped records  {g.skipped_records} ({g.skipped_records / total:.1%} of {total}) — malformed or "
            "oversized lines; the graph may be incomplete")


def _text_report(g: AgentGraph, r: ScanResult, anomalies: AnomalyReport | None = None,
                 baseline: Baseline | None = None, violations: str | None = None) -> str:
    fi_line = f"Fragility Index  {r.fi:.4f}   ({len(r.fragile_edges)}/{r.edge_count} links with tri(e)=0"
    fi_line += f"; baseline: {baseline.fi_mean:.2f} ± {baseline.fi_std:.2f})" if baseline else ")"
    lines = [
        f"Session   {g.session_id}",
        f"Project   {g.project or '-'}",
        f"Messages  {g.total_messages}   Tool calls {g.total_tool_calls}   Duration {_fmt_duration(g.duration_seconds)}",
        fi_line,
    ]
    note = _skipped_note(g)
    if note:
        lines.append(note)
    lines.append("")
    if anomalies is not None:
        lines += [str(anomalies), ""]
    if violations is not None:
        lines += [violations, ""]
    lines += [
        (f"Nodes {r.node_count}   Links {r.edge_count}   Bridges {len(r.bridges)}   "
         f"Components {r.components}   Articulation points {len(r.articulation_points)}"),
        "",
        f"{'NODE':<52} {'KIND':<12} {'CALLS':>6} {'ERR':>4}  {'dFI':>8}  ROLE",
    ]
    for nid in sorted(g.nodes, key=lambda n: (_LEVEL_ORDER[r.node_levels[n]], -g.nodes[n].call_count, n)):
        n = g.nodes[nid]
        label = f"{nid[:14]} {n.name}" if n.kind == "agent" else nid
        lines.append(f"{label[:52]:<52} {n.kind:<12} {n.call_count:>6} {n.error_count:>4}  "
                     f"{r.fi_deltas[nid]:>+8.4f}  {r.node_classifications[nid]}")
    triangulated = sorted((e for e in g.edges if e.tri_count > 0), key=lambda e: -e.tri_count)
    if triangulated:
        lines += ["", "Links with a backup path (tri(e) > 0):"]
        lines += [f"  {e.source} -> {e.target}  tri={e.tri_count}" for e in triangulated]
    return "\n".join(lines)


def _markdown_report(g: AgentGraph, r: ScanResult, anomalies: AnomalyReport | None = None) -> str:
    lines = [
        f"## agent-certify scan: `{g.session_id}`", "",
        f"- **Project:** {g.project or '-'}",
        f"- **Fragility Index:** {r.fi:.4f} ({len(r.fragile_edges)}/{r.edge_count} links with tri(e)=0)",
        f"- **Nodes / links / bridges:** {r.node_count} / {r.edge_count} / {len(r.bridges)}",
        (f"- **Tool calls:** {g.total_tool_calls} · **Messages:** {g.total_messages} · "
         f"**Duration:** {_fmt_duration(g.duration_seconds)}"),
    ]
    note = _skipped_note(g)
    if note:
        lines.append(f"- **{note}**")
    lines += ["", "| Node | Kind | Calls | Errors | ΔFI | Role |", "|---|---|--:|--:|--:|---|"]
    for nid in sorted(g.nodes, key=lambda n: -g.nodes[n].call_count):
        n = g.nodes[nid]
        lines.append(f"| `{nid}` | {n.kind} | {n.call_count} | {n.error_count} | "
                     f"{r.fi_deltas[nid]:+.4f} | {r.node_classifications[nid]} |")
    if anomalies is not None:
        lines += ["", f"### Anomalies: {anomalies.summary}", ""]
        lines += [f"- **{a.severity.upper()}** {a.message}" + (f" — {a.detail}" if a.detail else "")
                  for a in anomalies.anomalies]
    return "\n".join(lines)


def _counts(rep: AnomalyReport | None, violations: list[PolicyViolation] | None) -> tuple[str, str]:
    anomalies = "-" if rep is None else (
        ", ".join(f"{rep.count(s)} {s}" for s in ("critical", "warning", "info") if rep.count(s)) or "0")
    if violations is None:
        return anomalies, "-"
    by = {s: sum(1 for v in violations if v.severity == s) for s in ("critical", "warning")}
    return anomalies, ", ".join(f"{n} {s}" for s, n in by.items() if n) or "0"


def _session_table(sessions: list[dict], with_anomalies: bool, with_policy: bool) -> str:
    head = f"{'SESSION':<38} {'AGENTS':>6} {'TOOLS':>5} {'CALLS':>6} {'LINKS':>5} {'BRIDGES':>7} {'FI':>7}"
    head += "  ANOMALIES" + " " * 10 if with_anomalies else ""
    head += "  VIOLATIONS" if with_policy else ""
    lines = [head.rstrip()]
    for s in sessions:
        g, r = s["graph"], s["result"]
        agents = sum(1 for n in g.nodes.values() if n.kind == "agent")
        tools = sum(1 for n in g.nodes.values() if n.kind == "tool")
        row = (f"{(g.session_id or '')[:38]:<38} {agents:>6} {tools:>5} {g.total_tool_calls:>6} "
               f"{r.edge_count:>5} {len(r.bridges):>7} {r.fi:>7.4f}")
        anomaly_text, violation_text = _counts(s["anomalies"], s["violations"])
        if with_anomalies:
            row += f"  {anomaly_text:<19}"
        if with_policy:
            row += f"  {violation_text}"
        lines.append(row.rstrip())
    return "\n".join(lines)


def _fmt_period(start: str, end: str) -> str:
    def parse(s):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ") if s else None
    a, b = parse(start), parse(end)
    if not a or not b:
        return "unknown period"

    def day(d):
        return f"{d:%b} {d.day}"
    if a.year == b.year:
        return f"{day(a)} — {day(b)}, {b.year}"
    return f"{day(a)}, {a.year} — {day(b)}, {b.year}"


def _fmt_domains(domains: set[str], limit: int = 6) -> str:
    """The destinations a baseline learned, a few of them at most."""
    shown = sorted(domains)[:limit]
    more = len(domains) - len(shown)
    return ", ".join(shown) + (f", +{more} more" if more > 0 else "")


def _learn_report(b: Baseline, saved: Path) -> str:
    tools = sorted(b.tool_frequency.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    tool_text = textwrap.fill(", ".join(f"{t} ({f:.0%})" for t, f in tools), width=88,
                              initial_indent="  ", subsequent_indent="  ", break_on_hyphens=False)
    return "\n".join([
        (f"Learned baseline from {b.learned_from} session{'s' if b.learned_from != 1 else ''} "
         f"({_fmt_period(b.period_start, b.period_end)})"),
        "",
        "Structural profile:",
        f"  FI:           {b.fi_mean:.2f} ± {b.fi_std:.2f}  (range: {b.fi_min:.2f} — {b.fi_max:.2f})",
        f"  Nodes:        {b.node_count_mean:.1f} ± {b.node_count_std:.1f}",
        f"  Links:        {b.edge_count_mean:.1f} ± {b.edge_count_std:.1f}",
        f"  Bridges:      {b.bridge_count_mean:.1f} ± {b.bridge_count_std:.1f}",
        "",
        f"Tools seen ({len(b.known_tools)}):",
        tool_text,
        "",
        (f"Sub-agents:    {b.sub_agent_count_mean:.1f} ± {b.sub_agent_count_std:.1f}  "
         f"(max seen: {b.max_sub_agents_seen})"),
        f"Error rate:    {b.error_rate_mean:.1%} ± {b.error_rate_std:.1%}",
        f"Known links:   {len(b.known_links)}",
        *([f"Destinations:  {len(b.known_domains)}  ({_fmt_domains(b.known_domains)})"]
          if b.known_domains else []),
        "",
        f"Saved to {saved.as_posix()}",
        *_thin_baseline_note(b),
    ])


def _thin_baseline_note(b: Baseline) -> list[str]:
    """A warning when a baseline rests on too few sessions to compare against.

    Learning from two sessions is allowed and sometimes all there is, but the
    result is not a description of normal: every statistic has a deviation near
    zero or as wide as its mean, so the volume checks fire on a handful of
    calls and ``new_tool`` fires on tools the sessions simply happened not to
    use. Saying so once, here, costs nothing and saves an operator the triage.
    """
    if b.learned_from >= MIN_BASELINE_SESSIONS:
        return []
    return ["", (f"WARNING: learned from {b.learned_from} session(s), under the "
                 f"{MIN_BASELINE_SESSIONS} this needs to describe normal. Expect noise: an unknown "
                 "tool is reported at warning rather than critical (--min-baseline-sessions), and "
                 "the call-volume and outbound-volume checks compare against a deviation that is "
                 "near zero or as wide as its own mean. Learn from more sessions when you have "
                 "them.")]


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text + ("\n" if not text.endswith("\n") else ""))


# ------------------------------------------------------------------ commands
def _find_file(explicit: str | None, disabled: bool, default: Path, loader, what: str):
    """Load ``explicit``, else ``default`` if it exists; (None, "") when disabled or absent."""
    if disabled:
        return None, ""
    if explicit:
        p = _path(explicit)
        if not p.is_file():
            raise SystemExit(f"agent-certify: {what} {p} not found")
    else:
        p = default
        if not p.is_file():
            return None, ""
    try:
        return loader(p), p.as_posix()
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"agent-certify: {p} is not a valid {what} ({exc})") from None


def _find_baseline(args) -> tuple[Baseline | None, str]:
    """The baseline to compare against: --baseline, else ./.agent-certify/baseline.json if present."""
    return _find_file(args.baseline, args.no_baseline, DEFAULT_BASELINE_PATH, load_baseline, "baseline")


def _find_policy(args) -> tuple[Policy | None, str]:
    """The policy to enforce: --policy, else ./.agent-certify/policy.json if present."""
    return _find_file(args.policy, args.no_policy, DEFAULT_POLICY_PATH, Policy.load, "policy")


def _violations_text(violations: list[PolicyViolation]) -> str:
    if not violations:
        return "✓  No policy violations"
    lines = [f"⛔ POLICY VIOLATIONS ({len(violations)}):", ""]
    for v in violations:
        lines.append(f"{'[' + v.severity.upper() + ']':<11}{v.message}")
        lines.append(f"{'':<11}Rule: {v.rule.describe()} — {v.rule.message}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _fails(sessions: list[dict], fail_on: str) -> bool:
    """True when a session has a finding at or above ``fail_on`` (info-level anomalies never count)."""
    if fail_on == "never":
        return False
    levels = {"critical"} if fail_on == "critical" else {"critical", "warning"}
    for s in sessions:
        if s["anomalies"] is not None and any(a.severity in levels for a in s["anomalies"].anomalies):
            return True
        if s["violations"] is not None and any(v.severity in levels for v in s["violations"]):
            return True
    return False


def cmd_scan(args) -> int:
    started = datetime.now(timezone.utc)
    # --otel-stdout keeps stdout for OTLP lines (to pipe into a collector); the report goes to stderr.
    with contextlib.redirect_stdout(sys.stderr) if args.otel_stdout else contextlib.nullcontext():
        sessions = _scan_report(args)
    if args.otel or args.otel_stdout:
        exporter = OTelExporter()
        written = None
        for s in sessions:                                  # one span per session
            span = exporter.export_scan(s["graph"], s["result"], s["anomalies"], s["violations"], start_time=started)
            written = exporter.write(span, args.otel_file, stdout=args.otel_stdout)
        if written:
            print(f"OTel: {len(sessions)} span(s) appended to {written.as_posix()}", file=sys.stderr)
    _geoip_attribution(args)
    if _fails(sessions, args.fail_on):
        print(f"agent-certify: findings at or above '{args.fail_on}' (exit {FAIL_EXIT})", file=sys.stderr)
        return FAIL_EXIT
    return 0


def _regions(args) -> RegionResolver:
    """The region resolver a command builds from its arguments.

    Offline by default, and offline still with ``--geoip-db`` alone: that reads
    a local file to put a country on an address literal. Only ``--resolve-dns``
    makes a network call, it requires the database (an address with nothing to
    look it up in says nothing), and it announces itself on stderr before the
    first lookup.
    """
    db_path = getattr(args, "geoip_db", None)
    resolve = bool(getattr(args, "resolve_dns", False))
    if not db_path and not resolve:
        return OFFLINE
    if resolve and not db_path:
        raise SystemExit("agent-certify: --resolve-dns needs --geoip-db PATH: a resolved address names "
                         "no country without a local database (DB-IP 'IP to Country Lite' CSV, CC BY 4.0)")
    try:
        database = load_geoip(db_path) if db_path else None
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}") from None
    if database is not None and database.skipped:
        _warn(f"{database.skipped} unusable row(s) in {Path(db_path).as_posix()} were skipped "
              f"({database.ranges} address range(s) loaded)")
    resolver = RegionResolver(geoip=database, resolve_dns=resolve)
    resolver.warn_once()
    return resolver


def _detector(baseline: Baseline | None, source: str, args) -> AnomalyDetector | None:
    """The detector a command builds from its arguments, floors included."""
    if not baseline:
        return None
    return AnomalyDetector(
        baseline, source,
        min_call_delta=getattr(args, "min_call_delta", CALL_MIN_DELTA_CALLS),
        min_egress_delta=getattr(args, "min_egress_delta", EGRESS_MIN_DELTA_BYTES),
        min_baseline_sessions=getattr(args, "min_baseline_sessions", MIN_BASELINE_SESSIONS))


def _scan_report(args) -> list[dict]:
    """Print the report; return every session's graph, scan, anomalies and violations."""
    graphs, merged = load(args.path, include_mcp=args.include_mcp)
    _hash_projects([*graphs, merged], args)
    baseline, source = _find_baseline(args)
    policy, policy_source = _find_policy(args)
    detector = _detector(baseline, source, args)
    # One resolver, one cache, one warning — and built whether or not a policy
    # uses it, so a wrong --geoip-db is an error the operator hears about.
    regions = _regions(args)
    sessions = []
    for g in graphs:
        r = AgentFIScanner(g, perspective=args.perspective).scan()
        sessions.append({"graph": g, "result": r,
                         "anomalies": detector.detect(g, r) if detector else None,
                         "violations": policy.check(g, regions) if policy else None})
    single = len(graphs) == 1
    result = sessions[0]["result"] if single else AgentFIScanner(merged, perspective=args.perspective).scan()
    anomalies = sessions[0]["anomalies"] if single else None
    violations = sessions[0]["violations"] if single else None

    if args.format == "json":
        payload = {"graph": merged.to_dict(), "scan": result.to_dict()}
        if anomalies is not None:
            payload["anomalies"] = anomalies.to_dict()
        if violations is not None:
            payload["policy_violations"] = [v.to_dict() for v in violations]
        if not single:
            payload["sessions"] = []
            for s in sessions:
                entry = {"session_id": s["graph"].session_id, "project": s["graph"].project,
                         "scan": s["result"].to_dict()}
                if s["anomalies"] is not None:
                    entry["anomalies"] = s["anomalies"].to_dict()
                if s["violations"] is not None:
                    entry["policy_violations"] = [v.to_dict() for v in s["violations"]]
                payload["sessions"].append(entry)
        _emit(json.dumps(payload, indent=2), args.output)
    elif args.format == "html":
        from agent_certify.viz import render_html
        out = args.output or f"agent-graph-{_safe(merged.session_id)}.html"
        per_session = None if single or not (detector or policy) else [
            (s["graph"].session_id or "", s["anomalies"], s["violations"]) for s in sessions]
        Path(out).write_text(render_html(merged, result, perspective=args.perspective, anomalies=anomalies,
                                         violations=violations, session_findings=per_session), encoding="utf-8")
        print(f"wrote {out}")
    elif args.format == "markdown":
        text = _markdown_report(merged, result, anomalies)
        if violations is not None:
            text += f"\n\n### Policy violations: {len(violations)}\n\n" + "\n".join(
                f"- **{v.severity.upper()}** {v.message} (rule: {v.rule.describe()})" for v in violations)
        if not single and (detector or policy):
            text += "\n\n### Per session\n\n| Session | Anomalies | Policy violations |\n|---|---|---|\n"
            text += "\n".join(f"| `{s['graph'].session_id}` | {a} | {v} |"
                              for s in sessions for a, v in [_counts(s["anomalies"], s["violations"])])
            if policy:
                text += "\n\n" + "\n".join(f"- `{s['graph'].session_id}`: **{v.severity.upper()}** {v.message}"
                                           for s in sessions for v in (s["violations"] or []))
        _emit(text, args.output)
    else:
        text = _text_report(merged, result, anomalies, baseline if single else None,
                            _violations_text(violations) if violations is not None else None)
        if not single:
            text = (_session_table(sessions, detector is not None, policy is not None)
                    + "\n\nMerged graph\n============\n" + text)
            if policy:
                listed = [f"  {s['graph'].session_id}: [{v.severity.upper()}] {v.message}"
                          for s in sessions for v in s["violations"]]
                text += "\n\nPolicy violations per session:\n" + ("\n".join(listed) if listed else "  none")
        if source:
            text += f"\n\nBaseline: {source} ({baseline.learned_from} sessions)"
        if policy_source:
            scope = "" if single else ", evaluated per session"
            text += f"\nPolicy:   {policy_source} ({len(policy.rules)} rules{scope})"
        _emit(text, args.output)
    return sessions


def cmd_watch(args) -> int:
    p = _path(args.path)
    if p.is_dir():
        session = latest_session(p)
        if session is None:
            raise SystemExit(f"agent-certify: no .jsonl sessions in {p}")
    else:
        session = p                     # may not exist yet: the watcher waits for it
    baseline, _ = _find_baseline(args)
    policy, _ = _find_policy(args)
    on_scan, out = None, print
    if args.otel or args.otel_stdout:
        exporter = OTelExporter()

        def on_scan(graph, result, report, violations, started):
            exporter.write(exporter.export_scan(graph, result, report, violations, start_time=started),
                           args.otel_file, stdout=args.otel_stdout)

        if args.otel_stdout:
            def out(line):
                print(line, file=sys.stderr)
    _geoip_attribution(args)        # before the loop: a watch may never end
    SessionWatcher(str(session), baseline=baseline, policy=policy, interval=args.interval,
                   hash_project=args.hash_project,
                   min_call_delta=args.min_call_delta, min_egress_delta=args.min_egress_delta,
                   min_baseline_sessions=args.min_baseline_sessions, regions=_regions(args),
                   perspective=args.perspective, max_scans=args.scans, max_seconds=args.duration,
                   out=out, on_scan=on_scan).watch()
    return 0


def cmd_mcp(args) -> int:
    AgentCertifyMCPServer().run()
    return 0


def cmd_suggest_policy(args) -> int:
    baseline, _source = _find_file(args.baseline, False, DEFAULT_BASELINE_PATH, load_baseline, "baseline")
    if baseline is None:
        raise SystemExit(f"agent-certify: no baseline at {DEFAULT_BASELINE_PATH.as_posix()}; "
                         "run `agent-certify learn <sessions>` first or pass --baseline")
    out = Path(args.output) if args.output else DEFAULT_POLICY_PATH
    if out.exists() and not args.force:
        raise SystemExit(f"agent-certify: {out.as_posix()} exists and may hold your edits; "
                         "use --force to overwrite or --output for another file")
    policy = PolicyGenerator().suggest(baseline)
    saved = policy.save(out)
    lines = [f"Generated policy from {policy.generated_from}:", ""]
    for r in policy.rules:
        note = (f"seen in {baseline.tool_frequency.get(r.target, 0):.0%} of sessions" if r.kind == "required_tool"
                else r.message)
        lines.append(f"  {'[' + r.severity.upper() + ']':<11}{r.describe()} ({note})")
    lines += ["", f"Saved draft to {saved.as_posix()}", "",
              "Edit the file to add FORBIDDEN rules, for example:",
              ('  {"kind": "forbidden_tool", "target": "deploy_production", "severity": "critical", '
               '"message": "No agent may deploy to production"}'),
              ('  {"kind": "forbidden_link", "target": "agent:* → *database*", "severity": "critical", '
               '"message": "Sub-agents may not reach the database"}')]
    print("\n".join(lines))
    return 0


def cmd_learn(args) -> int:
    learner = BaselineLearner()
    try:
        if args.include_mcp:
            # Learn from the same data `scan --include-mcp` will compare against.
            graphs = []
            for p in args.paths:
                if not _path(p).exists():
                    raise FileNotFoundError(str(_path(p)))
                graphs += load(p, include_mcp=True)[0]
            baseline = learner.learn_graphs(graphs)
        else:
            baseline = learner.learn([str(_path(p)) for p in args.paths])
    except FileNotFoundError as exc:
        raise SystemExit(f"agent-certify: {exc.args[0]} does not exist") from None
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}") from None
    target = Path(args.output) if args.output else DEFAULT_BASELINE_PATH
    previous = None
    if not getattr(args, "forget_overrides", False) and target.exists():
        try:
            previous = load_baseline(target)
        except ValueError:
            previous = None     # an unreadable old file is not a reason to refuse to learn
    carry_overrides(baseline, previous)
    saved = learner.save(baseline, args.output)
    print(_learn_report(baseline, saved))
    if previous is not None and previous.has_overrides:
        print()
        print(f"Carried forward from {target.as_posix()}: " + _override_counts(baseline))
        print("  (re-learning recomputes the statistics; it does not undo accept/reject)")
    return 0


# --------------------------------------------------------------- baseline edits
def _override_counts(b: Baseline) -> str:
    counts = [f"{len(b.accepted_tools)} accepted tool(s)", f"{len(b.rejected_tools)} rejected",
              f"{len(b.accepted_links)} accepted link(s)"]
    if b.accepted_domains or b.rejected_domains:
        counts.append(f"{len(b.accepted_domains)} accepted domain(s), {len(b.rejected_domains)} rejected")
    return ", ".join(counts)


def _domain(raw: str) -> str:
    """One ``--domain`` argument as a stored pattern, or a usage error."""
    try:
        return normalise_pattern(raw)
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}") from None


def _load_baseline_for_edit(args) -> tuple[Baseline, Path]:
    """The baseline to edit, and where to write it back."""
    # Through _path() like every other path argument of the CLI: without it
    # `--baseline ~/b.json` looked for a literal "~" directory here while it
    # expanded everywhere else.
    path = _path(args.baseline) if args.baseline else DEFAULT_BASELINE_PATH
    if not path.exists():
        raise SystemExit(f"agent-certify: no baseline at {path.as_posix()}; "
                         "run `agent-certify learn <sessions>` first or pass --baseline")
    try:
        return load_baseline(path), path
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}") from None


def _save_baseline(baseline: Baseline, path: Path) -> None:
    BaselineLearner().save(baseline, path)


def cmd_baseline_accept(args) -> int:
    """Whitelist a tool, or one scoped invocation link, without re-learning."""
    if not (args.tool or args.link or args.domain):
        raise SystemExit('agent-certify: nothing to accept; pass --tool NAME, '
                         '--link "SRC -> DST" or --domain HOST')
    baseline, path = _load_baseline_for_edit(args)
    lines = []
    for raw in args.tool or []:
        try:
            name = normalise_tool(raw)
        except ValueError as exc:
            raise SystemExit(f"agent-certify: {exc}") from None
        was_rejected = name in baseline.rejected_tools
        baseline.rejected_tools.discard(name)
        baseline.accepted_tools.add(name)
        lines.append(f"  accepted tool: {name}"
                     + ("  (was rejected; the newer decision wins)" if was_rejected else ""))
    for raw in args.link or []:
        try:
            link = parse_link(raw, baseline)
        except ValueError as exc:
            raise SystemExit(f"agent-certify: {exc}") from None
        baseline.accepted_links.add(link)
        lines.append(f"  accepted link: {link[0]} -> {link[1]}"
                     "  (scoped: other callers of that target still fire)")
    for raw in args.domain or []:
        pattern = _domain(raw)
        was_rejected = pattern in baseline.rejected_domains
        baseline.rejected_domains.discard(pattern)
        baseline.accepted_domains.add(pattern)
        lines.append(f"  accepted domain: {pattern}"
                     + ("  (was rejected; the newer decision wins)" if was_rejected else ""))
    _save_baseline(baseline, path)
    print(f"Updated {path.as_posix()}")
    print("\n".join(lines))
    print(f"\nNow: {_override_counts(baseline)}")
    return 0


def cmd_baseline_reject(args) -> int:
    """Permanently exclude a tool or a destination from becoming normal, across re-learns."""
    if not (args.tool or args.domain):
        raise SystemExit('agent-certify: nothing to reject; pass --tool NAME or --domain "*.cn"')
    baseline, path = _load_baseline_for_edit(args)
    lines = []
    for raw in args.tool or []:
        try:
            name = normalise_tool(raw)
        except ValueError as exc:
            raise SystemExit(f"agent-certify: {exc}") from None
        was_accepted = name in baseline.accepted_tools
        baseline.accepted_tools.discard(name)
        baseline.rejected_tools.add(name)
        note = "  (was accepted; the newer decision wins)" if was_accepted else ""
        if name in baseline.known_tools:
            note += "  (already learned as normal — it will now fire anyway)"
        lines.append(f"  rejected tool: {name}{note}")
    for raw in args.domain or []:
        pattern = _domain(raw)
        note = "  (was accepted; the newer decision wins)" if pattern in baseline.accepted_domains else ""
        baseline.accepted_domains.discard(pattern)
        baseline.rejected_domains.add(pattern)
        if any(domain_matches(d, pattern) for d in baseline.known_domains):
            note += "  (already learned as normal — it will now fire anyway)"
        lines.append(f"  rejected domain: {pattern}{note}")
    _save_baseline(baseline, path)
    print(f"Updated {path.as_posix()}")
    print("\n".join(lines))
    print(f"\nNow: {_override_counts(baseline)}")
    return 0


def cmd_baseline_show(args) -> int:
    """Print the operator decisions stored in a baseline."""
    baseline, path = _load_baseline_for_edit(args)
    if args.format == "json":
        _emit(json.dumps({"baseline": path.as_posix(),
                          "accepted_tools": sorted(baseline.accepted_tools),
                          "rejected_tools": sorted(baseline.rejected_tools),
                          "accepted_links": sorted(list(x) for x in baseline.accepted_links),
                          "accepted_domains": sorted(baseline.accepted_domains),
                          "rejected_domains": sorted(baseline.rejected_domains),
                          "known_domains": sorted(baseline.known_domains)},
                         indent=2), args.output)
        return 0
    lines = [f"Baseline: {path.as_posix()}  ({baseline.learned_from} session(s))", ""]
    if not baseline.has_overrides:
        lines.append("No operator decisions recorded. Everything comes from what was learned.")
    else:
        for title, items in (("Accepted tools", sorted(baseline.accepted_tools)),
                             ("Rejected tools", sorted(baseline.rejected_tools))):
            lines.append(f"{title} ({len(items)}):")
            lines += [f"  {x}" for x in items] or ["  —"]
            lines.append("")
        links = sorted(baseline.accepted_links)
        lines.append(f"Accepted links ({len(links)}):")
        lines += [f"  {a} -> {b}" for a, b in links] or ["  —"]
        lines.append("")
        for title, items in (("Accepted domains", sorted(baseline.accepted_domains)),
                             ("Rejected domains", sorted(baseline.rejected_domains))):
            lines.append(f"{title} ({len(items)}):")
            lines += [f"  {x}" for x in items] or ["  —"]
            lines.append("")
    if baseline.known_domains:
        lines.append("")
        lines.append(f"Destinations learned ({len(baseline.known_domains)}):")
        lines += [f"  {d}" for d in sorted(baseline.known_domains)]
    _emit("\n".join(lines).rstrip(), args.output)
    return 0


def cmd_blast(args) -> int:
    _, g = load(args.path)
    try:
        report = BlastRadiusAnalyzer(g, hops=args.hops).analyze(args.node)
    except KeyError as exc:
        raise SystemExit(f"agent-certify: {exc.args[0]}") from None
    _emit(json.dumps(report.to_dict(), indent=2) if args.format == "json" else str(report), args.output)
    return 0


def _create_exclusive(path: Path, text: str, mode: int) -> None:
    """Create ``path`` atomically with ``mode``; fail if it exists, never follow a symlink there.

    On Windows ``mode`` only controls the read-only flag: the file inherits the
    ACL of its directory, so keep keys in a directory only you can read.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, mode)
    try:
        os.write(fd, text.encode("ascii"))
    finally:
        os.close(fd)


def cmd_keygen(args) -> int:
    out = Path(args.output)
    pub_path = Path(str(out) + ".pub")
    if args.force:
        for p in (out, pub_path):
            if p.is_symlink() or p.exists():
                p.unlink()              # unlinking a symlink removes the link, not its target
    priv, pub = generate_keypair()
    for path, text, mode in ((out, priv, 0o600), (pub_path, pub, 0o644)):
        try:
            _create_exclusive(path, text + "\n", mode)
        except FileExistsError:
            raise SystemExit(f"agent-certify: {path} exists (use --force to replace it)") from None
        except OSError as exc:
            raise SystemExit(f"agent-certify: cannot create {path} safely ({exc.strerror})") from None
    print(f"private key: {out}  (mode 600 — store it outside the repository and never commit it)")
    print(f"public key:  {pub_path} ({pub})")
    return 0


def _read_private_key(path: str) -> str:
    """The Ed25519 seed in ``path``, or a usage error naming what was expected.

    Validated here rather than left to fail inside ``sign``, which raises a
    bare ``ValueError`` or ``TypeError`` and reaches the user as a traceback.
    The public-key path has always checked its input (see ``cmd_verify``);
    this is the same courtesy on the private side.
    """
    p = _path(path)
    if not p.is_file():
        raise SystemExit(f"agent-certify: private key {p} not found")
    if os.name == "posix":
        mode = p.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            _warn(f"{p} is accessible by other users (mode {stat.S_IMODE(mode):o}); run: chmod 600 {p}")
    try:
        key = p.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise SystemExit(f"agent-certify: cannot read private key {p}") from None
    if _private_key_hex(key) is None:
        raise SystemExit(f"agent-certify: {p} does not hold an Ed25519 private key "
                         "(32 bytes as 64 hex chars, as written by `agent-certify keygen`)")
    return key


def cmd_certify(args) -> int:
    _, g = load(args.path)
    baseline, _ = _find_baseline(args)
    policy, _ = _find_policy(args)
    regions = _regions(args)
    # A certificate says a system is in a known good state. Signing one for a
    # session that was already breaking its own egress rules would say the
    # opposite of the evidence, so it takes an explicit option.
    violations = egress_violations(g, baseline, policy, regions)
    if violations and not args.allow_egress_violations:
        print(f"agent-certify: refusing to certify: {len(violations)} destination(s) of this "
              "session break its own egress rules:", file=sys.stderr)
        for line in violations:
            print(f"  - {line}", file=sys.stderr)
        print("Fix the system, or revise the decision that forbids them "
              "(`baseline accept --domain`, or the policy rule). To sign anyway and record these "
              "violations in the certificate, pass --allow-egress-violations.", file=sys.stderr)
        return CERTIFY_REFUSED
    key = _read_private_key(args.key) if args.key else None
    if key is None:
        _warn("issuing an UNSIGNED certificate (no --key): it can only be checked with --allow-unsigned")
    if g.skipped_records:
        _warn(f"{g.skipped_records} record(s) could not be read; the certificate covers a possibly "
              "incomplete graph (recorded in the certificate as skipped_records)")
    if violations:
        _warn(f"--allow-egress-violations: signing although {len(violations)} destination(s) of "
              "this session break its own egress rules (" + "; ".join(violations[:3])
              + "). They are recorded in the certificate, and `verify` will report them")
    cert = AgentCertificate.create(g, system_id=args.system_id, signing_key=key,
                                   validity_days=args.validity_days, baseline=baseline, policy=policy,
                                   omit_observed_destinations=args.omit_observed_destinations,
                                   regions=regions)
    out = args.output or f"{_safe(cert.system_id)}.cert.json"
    cert.save(out)
    print(f"certificate {cert.certificate_id} -> {out}")
    print(f"  FI {cert.fi_score:.4f} | {cert.node_count} nodes, {cert.edge_count} links, "
          f"{cert.bridge_count} bridges | signed: {cert.is_signed} | valid until {cert.not_after}")
    egress = cert.egress
    observed = (f"{len(egress['destinations'])} destination(s)" if "destinations" in egress
                else "destinations not recorded (--omit-observed-destinations)")
    print(f"  egress: {observed}, "
          f"{len(egress.get('accepted_domains', []))} accepted and "
          f"{len(egress.get('rejected_domains', []))} rejected pattern(s), "
          f"{len(egress.get('forbidden_regions', []))} forbidden region(s)")
    if egress.get("destinations"):
        _warn("the certificate records the host names this session reached; review it before "
              "publishing, and use --omit-observed-destinations for a certificate that leaves "
              "the organisation (SECURITY.md §2, §6)")
    return 0


def _looks_like_session(arg: str) -> bool:
    return arg.lower().endswith((".jsonl", ".agent-trace")) or _path(arg).is_dir()


def _looks_like_certificate(arg: str) -> bool:
    return arg.lower().endswith(".json")


VERIFY_HINT = "Hint: usage is 'verify CERTIFICATE SESSION --public-key KEY'"


def cmd_verify(args) -> int:
    cert_arg, session_arg = args.certificate, args.path
    reversed_args = bool(cert_arg) and _looks_like_session(cert_arg) and (
        session_arg is None or _looks_like_certificate(session_arg))
    if not cert_arg or not session_arg or reversed_args:
        problem = ("the arguments look reversed" if reversed_args and session_arg
                   else "the certificate comes first" if reversed_args else "two arguments are needed")
        print(f"agent-certify: verify: {problem}.\n{VERIFY_HINT}", file=sys.stderr)
        return 2
    if not args.public_key and not args.allow_unsigned:
        print("agent-certify: verify needs --public-key ISSUER.pub (the issuer's public key, obtained out of "
              "band); --allow-unsigned skips the signature check", file=sys.stderr)
        return 2
    if args.allow_unsigned:
        _warn("--allow-unsigned: the certificate's signature is NOT checked; anyone could have written it")
    try:
        cert = AgentCertificate.load(_path(args.certificate))
    except (OSError, ValueError):
        raise SystemExit(f"agent-certify: {args.certificate} is not a readable agent-certify certificate") from None
    pub = None
    if args.public_key:
        try:
            pub = _path(args.public_key).read_text(encoding="utf-8").strip()
        except OSError:
            raise SystemExit(f"agent-certify: cannot read public key {args.public_key}") from None
        if _public_key_hex(pub) is None:
            raise SystemExit(f"agent-certify: {args.public_key} does not hold an Ed25519 public key (64 hex chars)")
    _, g = load(args.path)
    report = cert.verify(g, fi_tolerance=args.fi_tolerance, public_key=pub, allow_unsigned=args.allow_unsigned,
                         ignore_expiry=args.ignore_expiry, allow_no_expiry=args.allow_no_expiry,
                         expected_system_id=args.expect_system_id, regions=_regions(args))
    _emit(json.dumps(report.to_dict(), indent=2) if args.format == "json" else str(report), None)
    _geoip_attribution(args)
    if not report.is_valid:
        return VERIFY_INVALID
    if report.egress_verifiable:
        return VERIFY_OK
    if args.accept_unverified_egress:
        _warn("--accept-unverified-egress: the certificate records no observed destinations, so "
              f"whether the {len(g.seen_domains)} destination(s) of this session were certified "
              "was not checked; reported as valid because you asked for that")
        return VERIFY_OK
    print(f"agent-certify: exit {VERIFY_EGRESS_UNVERIFIABLE}: signature and topology are valid, "
          "egress coverage is NOT verifiable: this certificate carries no list of observed "
          f"destinations and the session reached {len(g.seen_domains)}. Re-issue the certificate "
          "without --omit-observed-destinations, or pass --accept-unverified-egress to accept "
          "the narrower check as valid.", file=sys.stderr)
    return VERIFY_EGRESS_UNVERIFIABLE


#: DB-IP's *IP to Country Lite* database is published under CC BY 4.0, which
#: asks for attribution wherever the data is used. A report that places a
#: destination in a country is a use of it, so the line is printed whenever the
#: database was read — on stderr, so it never lands inside a JSON report or an
#: HTML file, and the operator who passes a report on has seen it.
GEOIP_ATTRIBUTION = "IP geolocation by DB-IP.com, CC BY 4.0"


def _hash_projects(graphs, args) -> None:
    """Replace every graph's project name with its digest, when asked.

    Done once, on the graph, so that every output downstream — the text report,
    the JSON, the OTel span, the HTML — carries the label rather than the name.
    One place to change it is one place to get it wrong.
    """
    if not getattr(args, "hash_project", False):
        return
    # By identity: for a single session the merged graph *is* that session's
    # graph, and hashing one object twice would give the digest of a digest —
    # stable, but not the digest of the project name, so two reports of the
    # same project would not match each other.
    seen: dict[int, object] = {}
    for g in graphs:
        seen.setdefault(id(g), g)
    for g in seen.values():
        g.project = hash_project(g.project)


def _geoip_attribution(args) -> bool:
    """Print the attribution line when a GeoIP database was used. True if printed."""
    if not getattr(args, "geoip_db", None):
        return False
    print(f"agent-certify: {GEOIP_ATTRIBUTION}", file=sys.stderr)
    return True


def _safe(s: str | None) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in (s or "graph"))[:60].strip("-")


# ---------------------------------------------------------------------- main
def _baseline_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--baseline", help=f"baseline to compare against (default: {DEFAULT_BASELINE_PATH} if present)")
    g.add_argument("--no-baseline", action="store_true", help="skip anomaly detection")
    p.add_argument("--min-call-delta", type=int, default=CALL_MIN_DELTA_CALLS, metavar="N",
                   help="report a call-volume rise only when it passes the baseline maximum by at "
                        f"least N calls (default: {CALL_MIN_DELTA_CALLS}; 0 turns the floor off)")
    p.add_argument("--min-egress-delta", type=int, default=EGRESS_MIN_DELTA_BYTES, metavar="BYTES",
                   help="report an outbound-volume rise only when it passes the baseline maximum by "
                        f"at least BYTES (default: {EGRESS_MIN_DELTA_BYTES}; 0 turns the floor off)")
    p.add_argument("--min-baseline-sessions", type=int, default=MIN_BASELINE_SESSIONS, metavar="N",
                   help="sessions a baseline needs before an unknown tool is critical rather than a "
                        f"warning (default: {MIN_BASELINE_SESSIONS}; a rejected tool is always critical)")


def _otel_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--otel", action="store_true",
                   help=f"append an OpenTelemetry span per scan (OTLP/JSON) to {DEFAULT_TRACES_PATH.as_posix()}")
    p.add_argument("--otel-stdout", action="store_true",
                   help="write the OTLP/JSON spans to stdout instead (the report moves to stderr)")
    p.add_argument("--otel-file", help=f"span file (default: {DEFAULT_TRACES_PATH.as_posix()})")


def _region_args(p: argparse.ArgumentParser, dns: bool = False) -> None:
    """``--geoip-db`` (offline) and, where it is allowed, ``--resolve-dns`` (not)."""
    p.add_argument("--geoip-db", metavar="PATH",
                   help="local CSV of 'ip_start,ip_end,country' rows (DB-IP 'IP to Country Lite', "
                        "CC BY 4.0) used to put a country on an address literal. Read from disk; "
                        "no database ships with agent-certify and none is downloaded")
    if dns:
        p.add_argument("--resolve-dns", action="store_true",
                       help="resolve destination names over the network to find their region "
                            "(needs --geoip-db). THE ONE OPTION THAT MAKES A NETWORK CONNECTION: off "
                            "by default, announced on stderr, and never available from the MCP server")


def _policy_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--policy", help=f"policy to enforce (default: {DEFAULT_POLICY_PATH} if present)")
    g.add_argument("--no-policy", action="store_true", help="skip policy checks")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agent-certify", description="Structural verification of multiagent systems.")
    ap.add_argument("--version", action="version", version=f"agent-certify {__version__}")
    ap.add_argument("-q", "--quiet", action="store_true", help="hide parser warnings")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="compute FI, bridges and node roles")
    s.add_argument("path", nargs="?", default=DEFAULT_PATH, help="session .jsonl or a directory of sessions")
    s.add_argument("--format", choices=["text", "json", "markdown", "html"], default="text")
    s.add_argument("-o", "--output")
    s.add_argument("--perspective", choices=list(Perspective.NAMES), default="engineering",
                   help="labels for node roles (default: engineering)")
    _baseline_args(s)
    _policy_args(s)
    _region_args(s, dns=True)
    s.add_argument("--hash-project", action="store_true",
                   help="replace the project name with 'sha256:<12 hex>' in every output (report, JSON, OTel, HTML). A project name comes from a filesystem path and can carry a user or client name; the digest is stable, so sessions of one project still group together. Pseudonymisation, not anonymisation: a guessed name can be confirmed by hashing it")
    s.add_argument("--include-mcp", action="store_true",
                   help="add the session's calls from MCP server logs (claude-cli-nodejs cache)")
    s.add_argument("--fail-on", choices=["critical", "warning", "never"], default="critical",
                   help=f"exit {FAIL_EXIT} when an anomaly or policy violation reaches this severity (default: critical)")
    _otel_args(s)
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="watch an active session live")
    w.add_argument("path", help="session file (may not exist yet), or a project directory (newest session)")
    w.add_argument("--interval", type=float, default=30.0, help="seconds between checks (default: 30)")
    w.add_argument("--perspective", choices=list(Perspective.NAMES), default="engineering")
    w.add_argument("--scans", type=int, help="stop after this many scans (default: until Ctrl+C)")
    w.add_argument("--duration", type=float, help="stop after this many seconds (default: until Ctrl+C)")
    _baseline_args(w)
    _policy_args(w)
    _region_args(w, dns=True)
    _otel_args(w)
    w.add_argument("--hash-project", action="store_true",
                   help="replace the project name with 'sha256:<12 hex>' in every output (report, JSON, OTel, HTML). A project name comes from a filesystem path and can carry a user or client name; the digest is stable, so sessions of one project still group together. Pseudonymisation, not anonymisation: a guessed name can be confirmed by hashing it")
    w.set_defaults(func=cmd_watch)

    sp = sub.add_parser("suggest-policy", help="draft a policy from a learned baseline")
    sp.add_argument("--baseline", help=f"baseline to read (default: {DEFAULT_BASELINE_PATH})")
    sp.add_argument("-o", "--output", help=f"where to write the draft (default: {DEFAULT_POLICY_PATH})")
    sp.add_argument("--force", action="store_true", help="overwrite an existing policy file")
    sp.set_defaults(func=cmd_suggest_policy)

    m = sub.add_parser("mcp", help="run as an MCP server on stdio (claude mcp add agent-certify -- agent-certify mcp)")
    m.set_defaults(func=cmd_mcp)

    learn = sub.add_parser("learn", help="learn a statistical baseline from past sessions")
    learn.add_argument("paths", nargs="+", help="session .jsonl files and/or directories of sessions")
    learn.add_argument("-o", "--output", help=f"where to save it (default: {DEFAULT_BASELINE_PATH})")
    learn.add_argument("--include-mcp", action="store_true",
                       help="include MCP server log calls (use with `scan --include-mcp`)")
    _region_args(learn, dns=True)
    learn.add_argument("--forget-overrides", action="store_true",
                       help="discard accept/reject decisions instead of carrying them forward")
    learn.set_defaults(func=cmd_learn)

    bl = sub.add_parser("baseline", help="edit the operator decisions stored in a baseline")
    blsub = bl.add_subparsers(dest="baseline_command", required=True)

    acc = blsub.add_parser("accept", help="whitelist a tool, or one scoped invocation link")
    acc.add_argument("--tool", action="append", metavar="NAME",
                     help="tool to whitelist, e.g. Bash or tool:Bash (repeatable)")
    acc.add_argument("--link", action="append", metavar="SRC->DST",
                     help='invocation link to whitelist, e.g. "agent:Build -> deploy_staging". '
                          "Scoped: a different source calling the same target still fires. "
                          "(repeatable)")
    acc.add_argument("--domain", action="append", metavar="HOST",
                     help="network destination to whitelist, e.g. api.openai.com or "
                          '"*.openai.com" for its subdomains (repeatable)')
    acc.add_argument("--baseline", help=f"baseline to edit (default: {DEFAULT_BASELINE_PATH})")
    acc.set_defaults(func=cmd_baseline_accept)

    rej = blsub.add_parser("reject", help="permanently exclude a tool or destination from becoming normal")
    rej.add_argument("--tool", action="append", metavar="NAME",
                     help="tool that must keep firing, even after a re-learn (repeatable)")
    rej.add_argument("--domain", action="append", metavar="HOST",
                     help='destination that must keep firing, e.g. "*.cn" or api.example.com. '
                          "A wildcard covers subdomains only: \"*.alibaba.com\" does not match "
                          "alibaba.com itself (repeatable)")
    rej.add_argument("--baseline", help=f"baseline to edit (default: {DEFAULT_BASELINE_PATH})")
    rej.set_defaults(func=cmd_baseline_reject)

    shw = blsub.add_parser("show", help="print the decisions stored in a baseline")
    shw.add_argument("--baseline", help=f"baseline to read (default: {DEFAULT_BASELINE_PATH})")
    shw.add_argument("--format", choices=["text", "json"], default="text")
    shw.add_argument("-o", "--output")
    shw.set_defaults(func=cmd_baseline_show)

    b = sub.add_parser("blast", help="blast radius of a compromised node")
    b.add_argument("path", nargs="?", default=DEFAULT_PATH)
    b.add_argument("--node", required=True, help="node id or name, e.g. bash, tool:Bash, claude")
    b.add_argument("--hops", type=int, default=3)
    b.add_argument("--format", choices=["text", "json"], default="text")
    b.add_argument("-o", "--output")
    b.set_defaults(func=cmd_blast)

    k = sub.add_parser("keygen", help="create an Ed25519 signing key (writes KEY with mode 600, and KEY.pub)")
    k.add_argument("output", nargs="?", default="agent-certify.key",
                   help="private key file (default: agent-certify.key); keep it outside the repository")
    k.add_argument("--force", action="store_true", help="replace existing key files")
    k.set_defaults(func=cmd_keygen)

    c = sub.add_parser("certify", help="issue a structural certificate for a graph")
    c.add_argument("path")
    c.add_argument("--key", help="private key file from `agent-certify keygen`; omit for an unsigned certificate")
    c.add_argument("--system-id")
    c.add_argument("--validity-days", type=int, default=DEFAULT_VALIDITY_DAYS,
                   help=f"how long the certificate is valid (default: {DEFAULT_VALIDITY_DAYS})")
    c.add_argument("-o", "--output")
    c.add_argument("--allow-egress-violations", action="store_true",
                   help="issue the certificate even though the session already reaches a destination "
                        "its own rules forbid (a rejected pattern, or a forbidden region). Off by "
                        "default: certify exits 1 and names them. The violations are recorded in the "
                        "signed certificate and reported by verify")
    c.add_argument("--omit-observed-destinations", action="store_true",
                   help="keep the accepted and rejected patterns and the forbidden regions in the "
                        "certificate, but not the list of destinations this session reached. For a "
                        "certificate shared outside the organisation: observed host names can "
                        "disclose internal infrastructure. verify then checks the rejected patterns "
                        "and the forbidden regions only, and says so")
    # The certificate records the egress rules in force when it is issued, so
    # certify reads the same baseline and policy a scan would — and the same
    # local address database, to decide a region offline. No --resolve-dns:
    # issuing a certificate does not open a socket.
    _baseline_args(c)
    _policy_args(c)
    _region_args(c)
    c.set_defaults(func=cmd_certify)

    v = sub.add_parser(
        "verify",
        help="check a graph against a certificate (exit 1 on drift, 3 if egress coverage is unverifiable)",
        description="Check a session against a certificate.\n\n"
                    "Exit codes:\n"
                    "  0  valid: signature, validity window, topology and egress coverage all in order\n"
                    "  1  invalid: something was checked and did not match\n"
                    "  2  the command line was wrong (missing argument, unreadable key)\n"
                    "  3  signature and topology valid, egress coverage NOT verifiable: the certificate\n"
                    "     records no observed destinations and the session reached some, so whether those\n"
                    "     were the certified ones cannot be decided. --accept-unverified-egress makes\n"
                    "     this case 0.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    v.add_argument("certificate", nargs="?", help="certificate file from `agent-certify certify` (.cert.json)")
    v.add_argument("path", nargs="?", help="session (.jsonl, .agent-trace) or project folder to check")
    v.add_argument("--public-key", help="REQUIRED: the issuer's public key file (KEY.pub), obtained out of band")
    v.add_argument("--allow-unsigned", action="store_true",
                   help="skip the signature check (unsafe: anyone can write an unsigned certificate)")
    v.add_argument("--ignore-expiry", action="store_true", help="accept a certificate outside its validity period")
    v.add_argument("--allow-no-expiry", action="store_true",
                   help="accept a certificate that has no validity window at all (format 1, issued "
                        "before v0.5). Such a certificate never expires and there is no revocation "
                        "list, so accepting one is a decision: without this option it fails")
    v.add_argument("--accept-unverified-egress", action="store_true",
                   help="exit 0 instead of 3 when the certificate records no observed destinations "
                        "and this session reached some: accepts that coverage was not checked")
    v.add_argument("--expect-system-id", help="fail unless the certificate was issued for this system id")
    v.add_argument("--fi-tolerance", type=float, default=0.001)
    v.add_argument("--format", choices=["text", "json"], default="text")
    _region_args(v)            # --geoip-db only: verify never resolves a name
    v.set_defaults(func=cmd_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.ERROR if args.quiet else logging.WARNING, format="%(levelname)s %(message)s")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
