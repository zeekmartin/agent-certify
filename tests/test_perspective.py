import pytest

from agent_certify import AgentFIScanner, AgentGraph, Perspective
from agent_certify.cli import main
from agent_certify.viz import render_html

EXPECTED = {
    #              high            medium           low
    "engineering": ("KEYSTONE", "LOAD-BEARING", "PERIPHERAL"),
    "risk": ("HIGH RISK", "MODERATE RISK", "LOW RISK"),
    "compliance": ("UNRESTRICTED", "BOUNDED", "LOGGED"),
    "monitoring": ("WATCH", "TRACK", "IGNORE"),
    "classic": ("CRITICAL", "BUFFER", "IMMUNE"),
}


def _graph() -> AgentGraph:
    """A graph with all three levels. FI = 3/8 (0-1, 0-2, 0-3 lack a triangle).

    n0: articulation point (holds the leaf n3)             -> high
    n4, n5: removal breaks triangles 1-4-5 and 2-4-5         -> high (FI 3/8 -> 1)
    n1, n2: removal raises FI 3/8 -> 2/5, +6.7% relative     -> medium
    n3: leaf; removal lowers FI to 2/7                       -> low
    """
    g = AgentGraph()
    for i in range(6):
        g.add_node(f"n{i}", "agent")
    for a, b in [(0, 1), (0, 2), (0, 3), (1, 4), (1, 5), (2, 4), (2, 5), (4, 5)]:
        g.add_call(f"n{a}", f"n{b}")
    return g


LEVELS = {"n0": "high", "n1": "medium", "n2": "medium", "n3": "low", "n4": "high", "n5": "high"}


def test_label_tables():
    for name, (high, medium, low) in EXPECTED.items():
        assert Perspective.labels(name) == {"high": high, "medium": medium, "low": low}
    assert Perspective.labels("RISK")["high"] == "HIGH RISK"          # case-insensitive
    with pytest.raises(ValueError, match="unknown perspective"):
        Perspective.labels("astrology")
    with pytest.raises(ValueError):
        AgentFIScanner(_graph(), perspective="astrology")


def test_levels():
    r = AgentFIScanner(_graph()).scan()
    assert r.fi == pytest.approx(3 / 8)
    assert r.node_levels == LEVELS
    assert r.fi_deltas["n1"] == pytest.approx(2 / 5 - 3 / 8, abs=1e-6)


@pytest.mark.parametrize("name", list(EXPECTED))
def test_labels_per_perspective(name):
    high, medium, low = EXPECTED[name]
    words = {"high": high, "medium": medium, "low": low}
    r = AgentFIScanner(_graph(), perspective=name).scan()
    assert r.perspective == name
    assert r.node_classifications == {n: words[lvl] for n, lvl in LEVELS.items()}


def test_metrics_identical_across_perspectives():
    g = _graph()
    base = AgentFIScanner(g).scan()
    for name in EXPECTED:
        r = AgentFIScanner(g, perspective=name).scan()
        assert r.fi == base.fi
        assert r.fi_deltas == base.fi_deltas
        assert r.node_levels == base.node_levels
        assert [e.key for e in r.bridges] == [e.key for e in base.bridges]
        assert r.articulation_points == base.articulation_points
        assert r.critical_nodes == base.critical_nodes == ["n0", "n4", "n5"]
        assert r.buffer_nodes == ["n1", "n2"] and r.immune_nodes == ["n3"]


def test_with_perspective_equals_rescan():
    g = _graph()
    classic = AgentFIScanner(g).scan()
    risk = classic.with_perspective("risk")
    assert risk.node_classifications == AgentFIScanner(g, perspective="risk").scan().node_classifications
    assert classic.node_classifications["n0"] == "CRITICAL"          # original untouched
    assert risk.labels("monitoring")["n3"] == "IGNORE"
    assert risk.to_dict()["node_levels"] == LEVELS


def test_python_api_default_is_classic(star_graph):
    r = AgentFIScanner(star_graph).scan()
    assert r.perspective == "classic"
    assert r.node_classifications["claude"] == "CRITICAL"
    assert "1 critical" in r.summary()
    assert "1 keystone" in r.with_perspective("engineering").summary()


def test_cli_perspectives(session_dir, capsys):
    session = str(session_dir / "sess-1.jsonl")
    assert main(["scan", session]) == 0
    assert "KEYSTONE" in capsys.readouterr().out                     # CLI default: engineering
    for name, (high, _, low) in EXPECTED.items():
        assert main(["scan", session, "--perspective", name]) == 0
        out = capsys.readouterr().out
        assert high in out and low in out


def test_html_uses_perspective(star_graph):
    page = render_html(star_graph, perspective="monitoring")
    assert "WATCH" in page and "IGNORE" in page and "CRITICAL" not in page
    assert "monitoring perspective" in page
    page = render_html(star_graph, perspective="compliance")
    assert "UNRESTRICTED" in page and "lvl-high" in page
