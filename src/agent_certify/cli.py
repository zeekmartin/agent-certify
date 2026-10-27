# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: BSL-1.1
"""Command-line interface.

    agent-certify scan <session.jsonl | project-dir> [--format text|json|markdown|html] [-o FILE]
                       [--perspective engineering|risk|compliance|monitoring|classic]
                       [--baseline FILE | --no-baseline] [--policy FILE | --no-policy] [--include-mcp]
    agent-certify watch <session.jsonl | project-dir> [--interval S] [--scans N]
                        [--baseline FILE | --no-baseline] [--policy FILE | --no-policy] [--perspective P]
    agent-certify learn <session.jsonl | dir>... [-o FILE]
    agent-certify suggest-policy [--baseline FILE] [-o FILE] [--force]
    agent-certify mcp                     # MCP server on stdio
    (scan and watch take --otel / --otel-stdout to emit OpenTelemetry spans)
    agent-certify blast <path> --node bash
    agent-certify keygen signing.key
    agent-certify certify <path> --key signing.key -o system.cert.json
    agent-certify verify system.cert.json <path>

A directory is scanned session by session and as one merged graph (every
session's agents and tools combined); ``html``, ``blast``, ``certify`` and
``verify`` use the merged graph.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from agent_certify import __version__
from agent_certify.anomaly import AnomalyDetector, AnomalyReport
from agent_certify.baseline import DEFAULT_BASELINE_PATH, Baseline, BaselineLearner, load_baseline
from agent_certify.blast import BlastRadiusAnalyzer
from agent_certify.certificate import AgentCertificate, generate_keypair
from agent_certify.graph import AgentGraph
from agent_certify.mcp_server import AgentCertifyMCPServer
from agent_certify.otel import DEFAULT_TRACES_PATH, OTelExporter
from agent_certify.parser import AutoParser, MCPLogsParser
from agent_certify.parser.auto import is_trace_dir
from agent_certify.policy import DEFAULT_POLICY_PATH, Policy, PolicyGenerator, PolicyViolation
from agent_certify.scanner import AgentFIScanner, Perspective, ScanResult
from agent_certify.watcher import SessionWatcher, latest_session

DEFAULT_PATH = "~/.claude/projects"


def _path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def load(path: str, include_mcp: bool = False) -> tuple[list[AgentGraph], AgentGraph]:
    """(per-session graphs, merged graph) for a session file or a directory.

    The format is detected from the content (Claude Code transcript, Cursor
    Agent Trace, MCP server log). ``include_mcp`` adds each session's calls from
    the MCP server logs.
    """
    p = _path(path)
    parser = AutoParser()
    try:
        if p.is_file() or is_trace_dir(p):
            graphs = [parser.parse(str(p))]
        elif p.is_dir():
            graphs = parser.parse_directory(str(p))
            if not graphs:
                raise SystemExit(f"agent-certify: no sessions (.jsonl, .agent-trace) found under {p}")
        else:
            raise SystemExit(f"agent-certify: {p} does not exist")
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}") from exc
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


# ---------------------------------------------------------------- formatting
def _fmt_duration(s: float | None) -> str:
    if not s:
        return "-"
    return f"{s / 3600:.1f}h" if s >= 3600 else f"{s / 60:.0f}m"


_LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


def _text_report(g: AgentGraph, r: ScanResult, anomalies: AnomalyReport | None = None,
                 baseline: Baseline | None = None, violations: str | None = None) -> str:
    fi_line = f"Fragility Index  {r.fi:.4f}   ({len(r.fragile_edges)}/{r.edge_count} links with tri(e)=0"
    fi_line += f"; baseline: {baseline.fi_mean:.2f} ± {baseline.fi_std:.2f})" if baseline else ")"
    lines = [
        f"Session   {g.session_id}",
        f"Project   {g.project or '-'}",
        f"Messages  {g.total_messages}   Tool calls {g.total_tool_calls}   Duration {_fmt_duration(g.duration_seconds)}",
        fi_line,
        "",
    ]
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
        "", "| Node | Kind | Calls | Errors | ΔFI | Role |", "|---|---|--:|--:|--:|---|",
    ]
    for nid in sorted(g.nodes, key=lambda n: -g.nodes[n].call_count):
        n = g.nodes[nid]
        lines.append(f"| `{nid}` | {n.kind} | {n.call_count} | {n.error_count} | "
                     f"{r.fi_deltas[nid]:+.4f} | {r.node_classifications[nid]} |")
    if anomalies is not None:
        lines += ["", f"### Anomalies: {anomalies.summary}", ""]
        lines += [f"- **{a.severity.upper()}** {a.message}" + (f" — {a.detail}" if a.detail else "")
                  for a in anomalies.anomalies]
    return "\n".join(lines)


def _session_table(graphs: list[AgentGraph], detector: AnomalyDetector | None = None) -> str:
    head = f"{'SESSION':<38} {'AGENTS':>6} {'TOOLS':>5} {'CALLS':>6} {'LINKS':>5} {'BRIDGES':>7} {'FI':>7}"
    lines = [head + ("  ANOMALIES" if detector else "")]
    for g in graphs:
        r = AgentFIScanner(g).scan()
        agents = sum(1 for n in g.nodes.values() if n.kind == "agent")
        tools = sum(1 for n in g.nodes.values() if n.kind == "tool")
        row = (f"{(g.session_id or '')[:38]:<38} {agents:>6} {tools:>5} {g.total_tool_calls:>6} "
               f"{r.edge_count:>5} {len(r.bridges):>7} {r.fi:>7.4f}")
        if detector:
            rep = detector.detect(g, r)
            row += "  " + (", ".join(f"{rep.count(s)} {s}" for s in ("critical", "warning", "info") if rep.count(s))
                           or "-")
        lines.append(row)
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
        "",
        f"Saved to {saved.as_posix()}",
    ])


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
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"agent-certify: {p} is not a valid {what} ({exc})")


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


def cmd_scan(args) -> int:
    started = datetime.now(timezone.utc)
    otel = args.otel or args.otel_stdout
    # --otel-stdout keeps stdout for OTLP lines (to pipe into a collector); the report goes to stderr.
    with contextlib.redirect_stdout(sys.stderr) if args.otel_stdout else contextlib.nullcontext():
        graphs, baseline, policy = _scan_report(args)
    if otel:
        exporter = OTelExporter()
        detector = AnomalyDetector(baseline) if baseline else None
        written = None
        for g in graphs:                                    # one span per session
            r = AgentFIScanner(g, perspective=args.perspective).scan()
            span = exporter.export_scan(g, r, detector.detect(g, r) if detector else None,
                                        policy.check(g) if policy else None, start_time=started)
            written = exporter.write(span, args.otel_file, stdout=args.otel_stdout)
        if written:
            print(f"OTel: {len(graphs)} span(s) appended to {written.as_posix()}", file=sys.stderr)
    return 0


def _scan_report(args):
    graphs, merged = load(args.path, include_mcp=args.include_mcp)
    result = AgentFIScanner(merged, perspective=args.perspective).scan()
    baseline, source = _find_baseline(args)
    policy, policy_source = _find_policy(args)
    detector = AnomalyDetector(baseline, source) if baseline else None
    # Anomalies and policy describe one session; a merged multi-session graph has no single counterpart.
    single = len(graphs) == 1
    anomalies = detector.detect(merged, result) if detector and single else None
    violations = policy.check(merged) if policy and single else None

    if args.format == "json":
        payload = {"graph": merged.to_dict(), "scan": result.to_dict()}
        if anomalies is not None:
            payload["anomalies"] = anomalies.to_dict()
        if violations is not None:
            payload["policy_violations"] = [v.to_dict() for v in violations]
        if len(graphs) > 1:
            payload["sessions"] = []
            for g in graphs:
                r = AgentFIScanner(g, perspective=args.perspective).scan()
                entry = {"session_id": g.session_id, "project": g.project, "scan": r.to_dict()}
                if detector:
                    entry["anomalies"] = detector.detect(g, r).to_dict()
                if policy:
                    entry["policy_violations"] = [v.to_dict() for v in policy.check(g)]
                payload["sessions"].append(entry)
        _emit(json.dumps(payload, indent=2), args.output)
    elif args.format == "html":
        from agent_certify.viz import render_html
        out = args.output or f"agent-graph-{_safe(merged.session_id)}.html"
        Path(out).write_text(render_html(merged, result, perspective=args.perspective, anomalies=anomalies),
                             encoding="utf-8")
        print(f"wrote {out}")
    elif args.format == "markdown":
        text = _markdown_report(merged, result, anomalies)
        if violations is not None:
            text += f"\n\n### Policy violations: {len(violations)}\n\n" + "\n".join(
                f"- **{v.severity.upper()}** {v.message} (rule: {v.rule.describe()})" for v in violations)
        _emit(text, args.output)
    else:
        text = _text_report(merged, result, anomalies, baseline if single else None,
                            _violations_text(violations) if violations is not None else None)
        if len(graphs) > 1:
            text = _session_table(graphs, detector) + "\n\nMerged graph\n============\n" + text
        if source:
            text += f"\n\nBaseline: {source} ({baseline.learned_from} sessions)"
        if policy_source:
            text += f"\nPolicy:   {policy_source} ({len(policy.rules)} rules)"
        _emit(text, args.output)
    return graphs, baseline, policy


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
    SessionWatcher(str(session), baseline=baseline, policy=policy, interval=args.interval,
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
        raise SystemExit(f"agent-certify: {exc.args[0]} does not exist")
    except ValueError as exc:
        raise SystemExit(f"agent-certify: {exc}")
    saved = learner.save(baseline, args.output)
    print(_learn_report(baseline, saved))
    return 0


def cmd_blast(args) -> int:
    _, g = load(args.path)
    try:
        report = BlastRadiusAnalyzer(g, hops=args.hops).analyze(args.node)
    except KeyError as exc:
        raise SystemExit(f"agent-certify: {exc.args[0]}")
    _emit(json.dumps(report.to_dict(), indent=2) if args.format == "json" else str(report), args.output)
    return 0


def cmd_keygen(args) -> int:
    out = Path(args.output)
    if out.exists() and not args.force:
        raise SystemExit(f"agent-certify: {out} exists (use --force to overwrite)")
    priv, pub = generate_keypair()
    out.write_text(priv + "\n", encoding="utf-8")
    Path(str(out) + ".pub").write_text(pub + "\n", encoding="utf-8")
    print(f"private key: {out}\npublic key:  {out}.pub ({pub})")
    return 0


def cmd_certify(args) -> int:
    _, g = load(args.path)
    key = _path(args.key).read_text(encoding="utf-8").strip() if args.key else None
    cert = AgentCertificate.create(g, system_id=args.system_id, signing_key=key)
    out = args.output or f"{_safe(cert.system_id)}.cert.json"
    cert.save(out)
    print(f"certificate {cert.certificate_id} -> {out}")
    print(f"  FI {cert.fi_score:.4f} | {cert.node_count} nodes, {cert.edge_count} links, "
          f"{cert.bridge_count} bridges | signed: {cert.is_signed}")
    return 0


def cmd_verify(args) -> int:
    cert = AgentCertificate.load(args.certificate)
    _, g = load(args.path)
    pub = _path(args.public_key).read_text(encoding="utf-8").strip() if args.public_key else None
    report = cert.verify(g, fi_tolerance=args.fi_tolerance, public_key=pub)
    _emit(json.dumps(report.to_dict(), indent=2) if args.format == "json" else str(report), None)
    return 0 if report.is_valid else 1


def _safe(s: str | None) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in (s or "graph"))[:60].strip("-")


# ---------------------------------------------------------------------- main
def _baseline_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--baseline", help=f"baseline to compare against (default: {DEFAULT_BASELINE_PATH} if present)")
    g.add_argument("--no-baseline", action="store_true", help="skip anomaly detection")


def _otel_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--otel", action="store_true",
                   help=f"append an OpenTelemetry span per scan (OTLP/JSON) to {DEFAULT_TRACES_PATH.as_posix()}")
    p.add_argument("--otel-stdout", action="store_true",
                   help="write the OTLP/JSON spans to stdout instead (the report moves to stderr)")
    p.add_argument("--otel-file", help=f"span file (default: {DEFAULT_TRACES_PATH.as_posix()})")


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
    s.add_argument("--perspective", choices=[n for n in Perspective.NAMES], default="engineering",
                   help="labels for node roles (default: engineering)")
    _baseline_args(s)
    _policy_args(s)
    s.add_argument("--include-mcp", action="store_true",
                   help="add the session's calls from MCP server logs (claude-cli-nodejs cache)")
    _otel_args(s)
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="watch an active session live")
    w.add_argument("path", help="session .jsonl (may not exist yet), or a project directory (newest session)")
    w.add_argument("--interval", type=float, default=30.0, help="seconds between checks (default: 30)")
    w.add_argument("--perspective", choices=list(Perspective.NAMES), default="engineering")
    w.add_argument("--scans", type=int, help="stop after this many scans (default: until Ctrl+C)")
    w.add_argument("--duration", type=float, help="stop after this many seconds (default: until Ctrl+C)")
    _baseline_args(w)
    _policy_args(w)
    _otel_args(w)
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
    learn.set_defaults(func=cmd_learn)

    b = sub.add_parser("blast", help="blast radius of a compromised node")
    b.add_argument("path", nargs="?", default=DEFAULT_PATH)
    b.add_argument("--node", required=True, help="node id or name, e.g. bash, tool:Bash, claude")
    b.add_argument("--hops", type=int, default=3)
    b.add_argument("--format", choices=["text", "json"], default="text")
    b.add_argument("-o", "--output")
    b.set_defaults(func=cmd_blast)

    k = sub.add_parser("keygen", help="create an Ed25519 signing key (writes KEY and KEY.pub)")
    k.add_argument("output")
    k.add_argument("--force", action="store_true")
    k.set_defaults(func=cmd_keygen)

    c = sub.add_parser("certify", help="issue a structural certificate for a graph")
    c.add_argument("path")
    c.add_argument("--key", help="private key file from `agent-certify keygen`; omit for an unsigned certificate")
    c.add_argument("--system-id")
    c.add_argument("-o", "--output")
    c.set_defaults(func=cmd_certify)

    v = sub.add_parser("verify", help="check a graph against a certificate (exit 1 on drift)")
    v.add_argument("certificate")
    v.add_argument("path")
    v.add_argument("--public-key", help="issuer's public key file, to check who signed")
    v.add_argument("--fi-tolerance", type=float, default=0.001)
    v.add_argument("--format", choices=["text", "json"], default="text")
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
