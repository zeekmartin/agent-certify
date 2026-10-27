"""Self-contained HTML view of an agent graph.

One file, inline SVG, a few lines of inline script, no external requests.
Nodes are coloured by role (IMMUNE green, BUFFER amber, CRITICAL red), edge
width follows call count, bridges are dashed red. Hovering a node shows its
blast radius and dims everything it cannot reach.
"""
from __future__ import annotations

import html
import json
import math
from pathlib import Path

import numpy as np

from agent_certify.blast import BlastRadiusAnalyzer
from agent_certify.graph import AgentGraph
from agent_certify.scanner import AgentFIScanner, ScanResult

W, H = 960, 680
_RING = {"orchestrator": 0.0, "human": 0.55, "agent": 0.45, "tool": 0.9}


def layout(graph: AgentGraph, iterations: int = 400, seed: int = 7) -> dict[str, tuple[float, float]]:
    """Deterministic Fruchterman–Reingold layout, seeded on rings by node kind."""
    ids = sorted(graph.nodes)
    n = len(ids)
    if n == 0:
        return {}
    if n == 1:
        return {ids[0]: (W / 2, H / 2)}
    rng = np.random.default_rng(seed)
    idx = {nid: i for i, nid in enumerate(ids)}
    pos = np.zeros((n, 2))
    for i, nid in enumerate(ids):
        r = _RING.get(graph.nodes[nid].kind, 0.9)
        a = 2 * math.pi * i / n + rng.uniform(-0.1, 0.1)
        pos[i] = (r * math.cos(a), r * math.sin(a))
    edges = np.array([(idx[a], idx[b]) for a, b in graph.undirected_edges()], dtype=int).reshape(-1, 2)
    k = 1.6 / math.sqrt(n)
    t = 0.15
    for _ in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        dist = np.linalg.norm(delta, axis=2) + 1e-9
        disp = (delta / dist[..., None] * (k * k / dist)[..., None]).sum(axis=1)
        if len(edges):
            d = pos[edges[:, 0]] - pos[edges[:, 1]]
            dl = np.linalg.norm(d, axis=1, keepdims=True) + 1e-9
            f = d / dl * (dl * dl / k)
            np.add.at(disp, edges[:, 0], -f)
            np.add.at(disp, edges[:, 1], f)
        disp -= pos * 0.05                       # mild pull to the centre keeps components close
        length = np.linalg.norm(disp, axis=1, keepdims=True) + 1e-9
        pos += disp / length * np.minimum(length, t)
        t *= 0.99
    lo, hi = pos.min(axis=0), pos.max(axis=0)
    span = np.where(hi - lo < 1e-9, 1.0, hi - lo)
    margin = np.array([110.0, 70.0])
    scaled = margin + (pos - lo) / span * (np.array([W, H]) - 2 * margin)
    return {nid: (float(scaled[i, 0]), float(scaled[i, 1])) for i, nid in enumerate(ids)}


def _short(name: str, limit: int = 22) -> str:
    if name.startswith("mcp__"):
        name = name.split("__")[-1]
    return name if len(name) <= limit else name[: limit - 1] + "…"


def render_html(graph: AgentGraph, result: ScanResult | None = None, title: str | None = None) -> str:
    """Return the HTML page for ``graph``."""
    result = result or AgentFIScanner(graph).scan()
    blasts = BlastRadiusAnalyzer(graph).analyze_all()
    pos = layout(graph)
    bridge_keys = {e.key for e in result.bridges}
    max_w = max((e.weight for e in graph.edges), default=1)
    max_calls = max((n.call_count for n in graph.nodes.values()), default=1) or 1
    title = title or f"agent-certify · {graph.session_id or 'agent graph'}"

    edge_svg = []
    for e in graph.edges:
        (x1, y1), (x2, y2) = pos[e.source], pos[e.target]
        width = 1.2 + 5.0 * math.log1p(e.weight) / math.log1p(max_w)
        cls = "edge bridge" if e.key in bridge_keys else "edge"
        tip = f"{e.source} → {e.target}\n{e.weight} call(s), {e.errors} error(s), tri(e)={e.tri_count}"
        edge_svg.append(
            f'<line class="{cls}" data-a="{html.escape(e.source)}" data-b="{html.escape(e.target)}" '
            f'x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke-width="{width:.2f}">'
            f'<title>{html.escape(tip)}</title></line>')

    node_svg = []
    for nid, n in sorted(graph.nodes.items()):
        x, y = pos[nid]
        role = result.node_classifications.get(nid, "IMMUNE").lower()
        r = 9 + 13 * math.sqrt(n.call_count / max_calls) if n.kind == "tool" else 20
        if n.kind == "orchestrator":
            r = 26
        if n.kind in ("orchestrator", "agent"):
            shape = (f'<rect x="{x - r:.1f}" y="{y - r * 0.75:.1f}" width="{2 * r:.1f}" '
                     f'height="{1.5 * r:.1f}" rx="7"/>')
        elif n.kind == "human":
            shape = f'<polygon points="{x:.1f},{y - r:.1f} {x + r:.1f},{y:.1f} {x:.1f},{y + r:.1f} {x - r:.1f},{y:.1f}"/>'
        else:
            shape = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}"/>'
        label = _short(n.name if n.kind != "agent" else n.name.split(":", 1)[-1].strip() or n.name)
        node_svg.append(
            f'<g class="node {role} {n.kind}" data-id="{html.escape(nid)}" tabindex="0">{shape}'
            f'<text x="{x:.1f}" y="{y + r + 14:.1f}">{html.escape(label)}</text></g>')

    info = {}
    for nid, b in blasts.items():
        n = graph.nodes[nid]
        info[nid] = {
            "name": n.name, "kind": n.kind, "role": result.node_classifications.get(nid),
            "calls": n.call_count, "errors": n.error_count,
            "direct": b.direct_impact, "reach": b.total_reachable, "tools": b.accessible_tools,
            "fi_after": round(b.remaining_fi, 4), "fragmented": b.system_fragmented,
            "groups": len(b.components_after), "advice": b.isolation_recommendation,
        }

    d = graph.duration_seconds
    duration = "–" if not d else (f"{d / 3600:.1f} h" if d >= 3600 else f"{d / 60:.0f} min")
    stats = [
        ("Fragility Index", f"{result.fi:.4f}"),
        ("Nodes", str(result.node_count)),
        ("Links", str(result.edge_count)),
        ("Bridges", str(len(result.bridges))),
        ("Critical", str(len(result.critical_nodes))),
        ("Tool calls", str(graph.total_tool_calls)),
        ("Duration", duration),
    ]
    stat_html = "".join(f'<div class="stat"><span>{html.escape(k)}</span><b>{html.escape(v)}</b></div>'
                        for k, v in stats)
    data = json.dumps(info).replace("</", "<\\/")

    return _TEMPLATE.format(
        title=html.escape(title), stats=stat_html, w=W, h=H,
        edges="\n".join(edge_svg), nodes="\n".join(node_svg), data=data,
        project=html.escape(graph.project or ""),
    )


def save_html(graph: AgentGraph, path, result: ScanResult | None = None, title: str | None = None) -> Path:
    p = Path(path)
    p.write_text(render_html(graph, result, title), encoding="utf-8")
    return p


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#fafaf9; --fg:#1c1917; --muted:#78716c; --panel:#ffffff; --line:#a8a29e; --border:#e7e5e4;
  --immune:#16a34a; --buffer:#d97706; --critical:#dc2626; --bridge:#dc2626; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#1c1917; --fg:#f5f5f4; --muted:#a8a29e; --panel:#292524;
  --line:#78716c; --border:#44403c; --immune:#22c55e; --buffer:#f59e0b; --critical:#f87171; --bridge:#f87171; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; background:var(--bg); color:var(--fg); }}
header {{ padding:16px 20px 8px; }}
h1 {{ font-size:18px; margin:0 0 2px; }} .sub {{ color:var(--muted); font-size:13px; }}
.stats {{ display:flex; flex-wrap:wrap; gap:8px; padding:8px 20px; }}
.stat {{ background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:6px 12px; }}
.stat span {{ display:block; font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
.stat b {{ font-size:16px; font-variant-numeric:tabular-nums; }}
main {{ display:flex; flex-wrap:wrap; gap:12px; padding:8px 20px 20px; }}
.canvas {{ flex:1 1 600px; min-width:0; background:var(--panel); border:1px solid var(--border); border-radius:10px; }}
svg {{ width:100%; height:auto; display:block; }}
aside {{ flex:0 1 300px; min-width:240px; background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 14px; }}
aside h2 {{ font-size:15px; margin:0 0 6px; word-break:break-all; }}
aside dl {{ margin:0; }} aside dt {{ color:var(--muted); font-size:12px; margin-top:8px; }} aside dd {{ margin:0; word-break:break-all; }}
.edge {{ stroke:var(--line); stroke-opacity:.7; }}
.edge.bridge {{ stroke:var(--bridge); stroke-dasharray:6 4; stroke-opacity:.85; }}
.node rect, .node circle, .node polygon {{ stroke:var(--panel); stroke-width:2; cursor:pointer; }}
.node.immune > :first-child {{ fill:var(--immune); }} .node.buffer > :first-child {{ fill:var(--buffer); }}
.node.critical > :first-child {{ fill:var(--critical); }}
.node text {{ fill:var(--fg); font-size:11px; text-anchor:middle; pointer-events:none; }}
.dim {{ opacity:.12; }} .focus > :first-child {{ stroke:var(--fg); stroke-width:3; }}
.legend {{ display:flex; flex-wrap:wrap; gap:14px; font-size:12px; color:var(--muted); padding:0 20px 16px; }}
.sw {{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:5px; vertical-align:-1px; }}
</style></head><body>
<header><h1>{title}</h1><div class="sub">{project} · structural scan by agent-certify</div></header>
<div class="stats">{stats}</div>
<main>
<div class="canvas"><svg viewBox="0 0 {w} {h}" role="img" aria-label="Agent graph">
<g id="edges">{edges}</g><g id="nodes">{nodes}</g></svg></div>
<aside id="panel"><h2>Blast radius</h2><p class="sub">Hover or focus a node to see what compromising it would reach.</p></aside>
</main>
<div class="legend">
<span><i class="sw" style="background:var(--critical)"></i>CRITICAL</span>
<span><i class="sw" style="background:var(--buffer)"></i>BUFFER</span>
<span><i class="sw" style="background:var(--immune)"></i>IMMUNE</span>
<span>▭ agent · ● tool (size = calls) · ◆ human</span>
<span style="color:var(--bridge)">- - - bridge (no backup path)</span>
</div>
<script>
const INFO = {data};
const panel = document.getElementById('panel');
const nodes = [...document.querySelectorAll('.node')];
const edges = [...document.querySelectorAll('.edge')];
const esc = s => String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}})[c]);
const list = a => a.length ? a.map(esc).join(', ') : '–';
function show(id) {{
  const d = INFO[id]; if (!d) return;
  const hit = new Set([id, ...d.reach]);
  nodes.forEach(n => {{ n.classList.toggle('dim', !hit.has(n.dataset.id)); n.classList.toggle('focus', n.dataset.id === id); }});
  edges.forEach(e => e.classList.toggle('dim', !(hit.has(e.dataset.a) && hit.has(e.dataset.b))));
  panel.innerHTML = `<h2>${{esc(id)}}</h2><div class="sub">${{esc(d.kind)}} · ${{esc(d.role)}} · ${{d.calls}} call(s), ${{d.errors}} error(s)</div>
  <dl><dt>Direct impact (${{d.direct.length}})</dt><dd>${{list(d.direct)}}</dd>
  <dt>Reachable within 3 hops</dt><dd>${{d.reach.length}} node(s)</dd>
  <dt>Tools it can invoke (${{d.tools.length}})</dt><dd>${{list(d.tools)}}</dd>
  <dt>FI after isolating it</dt><dd>${{d.fi_after}}</dd>
  <dt>System after isolation</dt><dd>${{d.fragmented ? 'fragmented into ' + d.groups + ' groups' : 'stays connected'}}</dd>
  <dt>Recommendation</dt><dd>${{esc(d.advice)}}</dd></dl>`;
}}
function clear() {{ nodes.forEach(n => n.classList.remove('dim','focus')); edges.forEach(e => e.classList.remove('dim')); }}
nodes.forEach(n => {{ n.addEventListener('mouseenter', () => show(n.dataset.id)); n.addEventListener('focus', () => show(n.dataset.id)); }});
document.querySelector('svg').addEventListener('mouseleave', clear);
</script></body></html>
"""
