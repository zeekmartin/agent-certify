"""Command-line interface.

    agent-certify scan <session.jsonl | project-dir> [--format text|json|markdown|html] [-o FILE]
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
import json
import logging
import os
import sys
from pathlib import Path

from agent_certify import __version__
from agent_certify.blast import BlastRadiusAnalyzer
from agent_certify.certificate import AgentCertificate, generate_keypair
from agent_certify.graph import AgentGraph
from agent_certify.parser import ClaudeCodeParser
from agent_certify.scanner import AgentFIScanner, ScanResult

DEFAULT_PATH = "~/.claude/projects"


def _path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def load(path: str) -> tuple[list[AgentGraph], AgentGraph]:
    """(per-session graphs, merged graph) for a session file or a directory."""
    p = _path(path)
    parser = ClaudeCodeParser()
    if p.is_file():
        g = parser.parse(str(p))
        return [g], g
    if p.is_dir():
        graphs = parser.parse_directory(str(p))
        if not graphs:
            raise SystemExit(f"agent-certify: no .jsonl sessions found under {p}")
        return graphs, AgentGraph.merge(graphs, session_id=f"{p.name} ({len(graphs)} sessions)")
    raise SystemExit(f"agent-certify: {p} does not exist")


# ---------------------------------------------------------------- formatting
def _fmt_duration(s: float | None) -> str:
    if not s:
        return "-"
    return f"{s / 3600:.1f}h" if s >= 3600 else f"{s / 60:.0f}m"


def _text_report(g: AgentGraph, r: ScanResult) -> str:
    lines = [
        f"Session   {g.session_id}",
        f"Project   {g.project or '-'}",
        f"Messages  {g.total_messages}   Tool calls {g.total_tool_calls}   Duration {_fmt_duration(g.duration_seconds)}",
        "",
        f"Fragility Index  {r.fi:.4f}   ({len(r.fragile_edges)}/{r.edge_count} links with tri(e)=0)",
        (f"Nodes {r.node_count}   Links {r.edge_count}   Bridges {len(r.bridges)}   "
        f"Components {r.components}   Articulation points {len(r.articulation_points)}"),
        "",
        f"{'NODE':<52} {'KIND':<12} {'CALLS':>6} {'ERR':>4}  {'dFI':>8}  ROLE",
    ]
    order = {"CRITICAL": 0, "BUFFER": 1, "IMMUNE": 2}
    for nid in sorted(g.nodes, key=lambda n: (order[r.node_classifications[n]], -g.nodes[n].call_count, n)):
        n = g.nodes[nid]
        label = f"{nid[:14]} {n.name}" if n.kind == "agent" else nid
        lines.append(f"{label[:52]:<52} {n.kind:<12} {n.call_count:>6} {n.error_count:>4}  "
                     f"{r.fi_deltas[nid]:>+8.4f}  {r.node_classifications[nid]}")
    triangulated = sorted((e for e in g.edges if e.tri_count > 0), key=lambda e: -e.tri_count)
    if triangulated:
        lines += ["", "Links with a backup path (tri(e) > 0):"]
        lines += [f"  {e.source} -> {e.target}  tri={e.tri_count}" for e in triangulated]
    return "\n".join(lines)


def _markdown_report(g: AgentGraph, r: ScanResult) -> str:
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
    return "\n".join(lines)


def _session_table(graphs: list[AgentGraph]) -> str:
    lines = [f"{'SESSION':<38} {'AGENTS':>6} {'TOOLS':>5} {'CALLS':>6} {'LINKS':>5} {'BRIDGES':>7} {'FI':>7}"]
    for g in graphs:
        r = AgentFIScanner(g).scan()
        agents = sum(1 for n in g.nodes.values() if n.kind == "agent")
        tools = sum(1 for n in g.nodes.values() if n.kind == "tool")
        lines.append(f"{(g.session_id or '')[:38]:<38} {agents:>6} {tools:>5} {g.total_tool_calls:>6} "
                     f"{r.edge_count:>5} {len(r.bridges):>7} {r.fi:>7.4f}")
    return "\n".join(lines)


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text + ("\n" if not text.endswith("\n") else ""))


# ------------------------------------------------------------------ commands
def cmd_scan(args) -> int:
    graphs, merged = load(args.path)
    result = AgentFIScanner(merged).scan()
    if args.format == "json":
        payload = {"graph": merged.to_dict(), "scan": result.to_dict()}
        if len(graphs) > 1:
            payload["sessions"] = [{"session_id": g.session_id, "project": g.project,
                                    "scan": AgentFIScanner(g).scan().to_dict()} for g in graphs]
        _emit(json.dumps(payload, indent=2), args.output)
    elif args.format == "html":
        from agent_certify.viz import render_html
        out = args.output or f"agent-graph-{_safe(merged.session_id)}.html"
        Path(out).write_text(render_html(merged, result), encoding="utf-8")
        print(f"wrote {out}")
    elif args.format == "markdown":
        _emit(_markdown_report(merged, result), args.output)
    else:
        text = _text_report(merged, result)
        if len(graphs) > 1:
            text = _session_table(graphs) + "\n\nMerged graph\n============\n" + text
        _emit(text, args.output)
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
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agent-certify", description="Structural verification of multiagent systems.")
    ap.add_argument("--version", action="version", version=f"agent-certify {__version__}")
    ap.add_argument("-q", "--quiet", action="store_true", help="hide parser warnings")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="compute FI, bridges and node roles")
    s.add_argument("path", nargs="?", default=DEFAULT_PATH, help="session .jsonl or a directory of sessions")
    s.add_argument("--format", choices=["text", "json", "markdown", "html"], default="text")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_scan)

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
