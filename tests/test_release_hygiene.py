# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""The findings of the 2026-11-24 audit that were not about extraction.

Each test here stands for one identifier, and most of them pin a *claim* rather
than a behaviour: a version that matches the format it writes, an exit code that
does not say "valid" about something nobody checked, a dependency floor that
CI installs instead of merely declaring. A document that promises more than the
code does is the failure mode this file exists to prevent.
"""
from __future__ import annotations

import json
import pathlib
import re
import threading
import time

import pytest

import agent_certify
from agent_certify.certificate import (
    CURRENT_FORMAT,
    MIN_VERSION_FOR_FORMAT,
    AgentCertificate,
)
from agent_certify.cli import GEOIP_ATTRIBUTION, VERIFY_OK, main
from agent_certify.graph import AgentGraph
from agent_certify.mcp_server import MAX_INFLIGHT, AgentCertifyMCPServer, ToolError
from agent_certify.otel import OTelExporter
from agent_certify.paths import PROJECT_HASH_CHARS, hash_project
from agent_certify.scanner import AgentFIScanner
from agent_certify.viz import render_html

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read_pyproject() -> dict:
    """`pyproject.toml` as a dict.

    `tomllib` is 3.11+, and the supported floor is 3.10 — where `tomli` comes
    from the `dev` extra. A test about the declared floors has to run *at* the
    floor, or it is not testing it.
    """
    try:
        import tomllib
    except ModuleNotFoundError:                       # Python 3.10
        import tomli as tomllib
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

PROJECT = "H--acme-client-audit"


@pytest.fixture
def session_file():
    """Write one real session inside a project folder, and give back its path.

    The project name comes from the folder, which is how it comes from a path in
    the field — which is the whole reason it can carry a client's name.
    """
    def build(root, project: str, name: str = "s.jsonl"):
        folder = root / project
        folder.mkdir(parents=True, exist_ok=True)
        records = [
            {"type": "user", "timestamp": "2026-10-01T10:00:00Z",
             "message": {"role": "user", "content": "check the egress"}},
            {"type": "assistant", "timestamp": "2026-10-01T10:00:01Z",
             "message": {"role": "assistant", "content": [
                 {"type": "tool_use", "id": "t1", "name": "Bash",
                  "input": {"command": "curl -sS https://api.openai.com/v1/models"}},
                 {"type": "tool_use", "id": "t2", "name": "Read",
                  "input": {"file_path": "notes.md"}}]}},
            {"type": "user", "timestamp": "2026-10-01T10:00:05Z",
             "message": {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": "t1", "content": "ok", "is_error": False},
                 {"type": "tool_result", "tool_use_id": "t2", "content": "ok", "is_error": False}]}},
        ]
        path = folder / name
        body = "\n".join(json.dumps(r) for r in records) + "\n"
        path.write_text(body, encoding="utf-8")
        return path

    return build


@pytest.fixture
def graph_with_domain():
    graph = AgentGraph(session_id="sess-1", project=PROJECT,
                       started_at="2026-10-01T10:00:00Z", ended_at="2026-10-01T10:30:00Z")
    graph.add_node("claude", "orchestrator")
    graph.add_node("tool:Bash", "tool", "Bash")
    graph.add_call("claude", "tool:Bash", count=3)
    graph.record_egress("tool:Bash", {"api.openai.com"}, 2048)
    graph.total_tool_calls = 3
    return graph


def version_tuple(text: str) -> tuple:
    """``"0.8.0"`` or ``"0.8.0.dev0"`` as a comparable tuple, dev first.

    A tiny parser rather than `packaging`: this project has two runtime
    dependencies and a test is not the place to add a third.
    """
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:\.?(?:dev|rc|a|b)(\d+))?", text)
    assert match, f"{text!r} is not a version this project writes"
    major, minor, patch, pre = match.groups()
    # A dev/rc release precedes its final: (0, 8, 0, 0, 0) < (0, 8, 0, 1, 0).
    return (int(major), int(minor), int(patch), 0 if pre is not None else 1, int(pre or 0))


# ------------------------------------------------------------------- INT-001
def test_the_version_is_allowed_to_write_the_format_it_writes():
    """INT-001: a build must not claim a version that cannot read what it writes.

    The tree wrote ``cert_format`` 3 while calling itself 0.7.0 — a version
    whose verifier rejects a format 3 certificate outright. The assertion is
    the relation rather than a literal, so a release commit (dropping a
    ``.dev`` suffix) and a later bump both keep it true; what it forbids is a
    version *older* than the format the tree writes.
    """
    assert (version_tuple(agent_certify.__version__)
            >= version_tuple(MIN_VERSION_FOR_FORMAT[CURRENT_FORMAT])), (
        f"this tree writes cert_format {CURRENT_FORMAT}, which needs "
        f"{MIN_VERSION_FOR_FORMAT[CURRENT_FORMAT]} or later, and calls itself "
        f"{agent_certify.__version__}")


def test_every_certificate_format_declares_the_version_that_introduced_it():
    """A format without a version is a question nobody can answer in the field.

    "Which version do I need to read this?" has to have an answer, and the only
    way to keep one is to make its absence a test failure.
    """
    assert set(MIN_VERSION_FOR_FORMAT) == set(range(1, CURRENT_FORMAT + 1)), (
        "MIN_VERSION_FOR_FORMAT must have one entry per format from 1 to CURRENT_FORMAT: "
        "add the version that introduces a format in the same change that adds the format.")
    versions = [version_tuple(MIN_VERSION_FOR_FORMAT[f]) for f in sorted(MIN_VERSION_FOR_FORMAT)]
    assert versions == sorted(versions), "a later format cannot require an earlier version"


def test_this_build_is_allowed_to_write_the_format_it_writes():
    assert version_tuple(agent_certify.__version__) >= version_tuple(
        MIN_VERSION_FOR_FORMAT[CURRENT_FORMAT]), (
        f"this tree writes cert_format {CURRENT_FORMAT}, which needs "
        f"{MIN_VERSION_FOR_FORMAT[CURRENT_FORMAT]}; __version__ is {agent_certify.__version__}")


def test_the_version_in_a_certificate_is_the_one_that_wrote_it(graph_with_domain):
    cert = AgentCertificate.create(graph_with_domain)
    assert cert.agent_certify_version == agent_certify.__version__
    assert cert.cert_format == CURRENT_FORMAT


# ------------------------------------------------------------------- PRV-001
def test_a_project_name_hashes_to_a_stable_short_label():
    label = hash_project(PROJECT)
    assert label.startswith("sha256:")
    assert len(label) == len("sha256:") + PROJECT_HASH_CHARS
    assert re.fullmatch(r"sha256:[0-9a-f]{12}", label)
    assert hash_project(PROJECT) == label              # stable: sessions still group
    assert hash_project("H--other-client") != label
    assert hash_project(None) is None and hash_project("") == ""


def test_hash_project_keeps_the_name_out_of_the_json(tmp_path, capsys, session_file):
    path = session_file(tmp_path, PROJECT)
    assert main(["scan", str(path), "--format", "json", "--no-baseline", "--no-policy",
                 "--hash-project"]) == VERIFY_OK
    out = capsys.readouterr().out
    assert PROJECT not in out
    payload = json.loads(out)
    assert payload["graph"]["project"] == hash_project(PROJECT)


def test_hash_project_keeps_the_name_out_of_the_otel_span(tmp_path, capsys, session_file):
    path = session_file(tmp_path, PROJECT)
    traces = tmp_path / "spans.jsonl"
    assert main(["scan", str(path), "--no-baseline", "--no-policy", "--hash-project",
                 "--otel", "--otel-file", str(traces)]) == VERIFY_OK
    capsys.readouterr()
    text = traces.read_text(encoding="utf-8")
    assert PROJECT not in text
    assert hash_project(PROJECT) in text
    # And the attribute is the one a collector reads, not some other field.
    span = json.loads(text.splitlines()[0])
    attrs = {a["key"]: a["value"] for a in span["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]}
    assert attrs["agent_certify.project"]["stringValue"] == hash_project(PROJECT)


def test_hash_project_keeps_the_name_out_of_the_html(tmp_path, capsys, session_file):
    path = session_file(tmp_path, PROJECT)
    report = tmp_path / "r.html"
    assert main(["scan", str(path), "--format", "html", "-o", str(report),
                 "--no-baseline", "--no-policy", "--hash-project"]) == VERIFY_OK
    capsys.readouterr()
    text = report.read_text(encoding="utf-8")
    assert PROJECT not in text
    assert hash_project(PROJECT) in text


def test_without_the_flag_the_name_is_still_there(tmp_path, capsys, session_file):
    """The default is unchanged: this is an option, not a silent redaction.

    A report that quietly stopped naming its project would break every workflow
    that groups by it, and nobody asked for that.
    """
    path = session_file(tmp_path, PROJECT)
    assert main(["scan", str(path), "--format", "json", "--no-baseline", "--no-policy"]) == VERIFY_OK
    assert PROJECT in capsys.readouterr().out


def test_the_html_and_otel_exporters_hash_nothing_by_themselves(graph_with_domain):
    """The hashing lives in one place. These two only render what the graph says."""
    graph_with_domain.project = PROJECT
    result = AgentFIScanner(graph_with_domain).scan()
    assert PROJECT in render_html(graph_with_domain, result)
    exporter = OTelExporter()
    span = exporter.export_scan(graph_with_domain, result, None, None)
    assert PROJECT in json.dumps(exporter.to_otlp_json(span))


def test_a_watch_hashes_the_project_on_every_cycle(tmp_path, session_file):
    """One scan per cycle, each one hashed: the flag is not a one-off at startup."""
    from agent_certify.watcher import SessionWatcher

    path = session_file(tmp_path, PROJECT)
    seen = []
    SessionWatcher(str(path), interval=0.01, max_scans=1, max_seconds=10, hash_project=True,
                   out=lambda line: None,
                   on_scan=lambda g, *a: seen.append(g.project)).watch()
    assert seen == [hash_project(PROJECT)]

    # And without the flag the same watch reports the real name.
    plain = []
    SessionWatcher(str(path), interval=0.01, max_scans=1, max_seconds=10,
                   out=lambda line: None,
                   on_scan=lambda g, *a: plain.append(g.project)).watch()
    assert plain == [PROJECT]


# ------------------------------------------------------------------- MCP-001
def test_the_server_refuses_a_third_slow_request_instead_of_piling_up_threads():
    """MCP-001: a timeout abandons its thread, so retrying has to be refused.

    Python cannot kill a thread. A request that ran past its deadline keeps
    running, keeps its file handles and keeps its CPU — so a client that retries
    adds a scan rather than replacing one, and the server it is waiting for gets
    slower with every attempt. Three slow calls: two are abandoned, the third is
    told the server is busy, and the thread count stops growing.
    """
    server = AgentCertifyMCPServer(request_timeout=0.05)
    release = threading.Event()
    started = []

    def slow(**_kwargs):
        started.append(1)
        release.wait(10)                      # released in the finally below
        return {"ok": True}

    server._handlers["scan_topology"] = slow
    before = threading.active_count()
    try:
        errors = []
        for _ in range(3):
            with pytest.raises(ToolError) as exc:
                server._run_with_timeout(server._handlers["scan_topology"], {})
            errors.append(str(exc.value))
        assert "timed out" in errors[0] and "timed out" in errors[1]
        assert errors[2].startswith("server busy: 2 earlier request(s) still running")
        assert len(started) == 2, "the refused call must not have started any work"
        assert server.inflight() == MAX_INFLIGHT
        # Two threads live, not three: the refusal is what stops the growth.
        assert threading.active_count() - before <= MAX_INFLIGHT
    finally:
        release.set()
    for _ in range(200):                      # let the abandoned workers finish
        if server.inflight() == 0:
            break
        time.sleep(0.01)
    assert server.inflight() == 0
    assert server._abandoned == 2             # reported in the stderr log


def test_the_refusal_reaches_the_client_as_a_tool_error():
    server = AgentCertifyMCPServer(request_timeout=0.05, max_inflight=1)
    release = threading.Event()
    server._handlers["scan_topology"] = lambda **_k: release.wait(10)
    try:
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "scan_topology", "arguments": {}}}
        first = server.handle(request)
        assert first["result"]["isError"] and "timed out" in first["result"]["content"][0]["text"]
        second = server.handle(request)
        assert second["result"]["isError"]
        assert "server busy: 1 earlier request(s) still running" in second["result"]["content"][0]["text"]
    finally:
        release.set()


def test_a_fast_request_leaves_no_thread_behind():
    server = AgentCertifyMCPServer(request_timeout=5)
    server._handlers["scan_topology"] = lambda **_k: {"ok": True}
    for _ in range(5):
        assert server._run_with_timeout(server._handlers["scan_topology"], {}) == {"ok": True}
    assert server.inflight() == 0 and server._abandoned == 0


def test_the_in_flight_cap_is_at_least_one():
    assert AgentCertifyMCPServer(max_inflight=0).max_inflight == 1


# ------------------------------------------------------------------- LIC-001
def test_the_geoip_attribution_is_printed_when_the_database_was_read(tmp_path, capsys, session_file):
    db = tmp_path / "ip2country.csv"
    db.write_text('"1.0.0.0","1.255.255.255","AU"\n', encoding="utf-8")
    path = session_file(tmp_path, PROJECT)
    assert main(["scan", str(path), "--no-baseline", "--no-policy", "--geoip-db", str(db)]) == VERIFY_OK
    assert GEOIP_ATTRIBUTION in capsys.readouterr().err
    # CC BY 4.0 asks for credit where the data is used; a region report uses it.
    assert GEOIP_ATTRIBUTION == "IP geolocation by DB-IP.com, CC BY 4.0"


def test_no_attribution_without_the_database(tmp_path, capsys, session_file):
    path = session_file(tmp_path, PROJECT)
    assert main(["scan", str(path), "--no-baseline", "--no-policy"]) == VERIFY_OK
    assert "DB-IP" not in capsys.readouterr().err


def test_the_attribution_goes_to_stderr_so_it_never_lands_in_a_report(tmp_path, capsys, session_file):
    db = tmp_path / "ip2country.csv"
    db.write_text('"1.0.0.0","1.255.255.255","AU"\n', encoding="utf-8")
    path = session_file(tmp_path, PROJECT)
    assert main(["scan", str(path), "--format", "json", "--no-baseline", "--no-policy",
                 "--geoip-db", str(db)]) == VERIFY_OK
    printed = capsys.readouterr()
    assert "DB-IP" not in printed.out and GEOIP_ATTRIBUTION in printed.err
    json.loads(printed.out)                   # still a clean document


# ------------------------------------------------------------- CFG-001 / 002
def test_the_ci_matrix_and_the_classifiers_agree():
    """CFG-001/002: a claim of support is a claim that something tested it."""
    pyproject = read_pyproject()
    claimed = {c.rsplit(" :: ", 1)[-1] for c in pyproject["project"]["classifiers"]
               if c.startswith("Programming Language :: Python :: 3.")}
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    line = next(ln for ln in ci.splitlines() if ln.strip().startswith("python: ["))
    tested = set(re.findall(r'"(\d+\.\d+)"', line))
    assert claimed == tested, (
        f"classifiers claim {sorted(claimed)} and CI tests {sorted(tested)}: "
        "a version claimed and not tested is a promise nobody checked")
    assert "3.10" in tested and "3.14" in tested
    # And the floor agrees with the oldest version in the matrix.
    assert pyproject["project"]["requires-python"] == ">=3.10"
    assert min(tested, key=lambda v: tuple(map(int, v.split(".")))) == "3.10"


def test_the_package_is_beta():
    """DOC-001: a signed format, a benchmark and a security policy are not alpha."""
    pyproject = read_pyproject()
    status = [c for c in pyproject["project"]["classifiers"] if c.startswith("Development Status")]
    assert status == ["Development Status :: 4 - Beta"]


# ------------------------------------------------------------------- SCA-002
FLOORS = {"numpy": "1.26.4", "cryptography": "46.0.0"}


def test_the_dependency_floors_are_the_oldest_versions_ci_tests():
    """SCA-002: a floor is a promise that the oldest resolution still works.

    It is not a security control, because an unconstrained `pip install` takes
    the most recent release anyway — a floor only decides who cannot install
    at all, and the deployments that pin an old dependency are exactly the
    frozen images this tool is audited on. So the floors are as low as CI can
    prove: `numpy` 1.26.4 is the oldest release the suite passes on under
    Python 3.10, and `cryptography` 46.0.0 the oldest series with the Ed25519
    API and wheels for every interpreter in the matrix. The `lowest` job
    installs exactly these (see the test below).
    """
    pyproject = read_pyproject()
    floors = dict(spec.split(">=") for spec in pyproject["project"]["dependencies"])
    assert floors == FLOORS
    # And the environment the tests run in actually satisfies them.
    import cryptography
    import numpy
    for name, installed in (("numpy", numpy.__version__), ("cryptography", cryptography.__version__)):
        floor = tuple(int(p) for p in floors[name].split("."))
        have = tuple(int(p) for p in installed.split(".")[:3] if p.isdigit())
        assert have >= floor, f"{name} {installed} is below the declared floor {floors[name]}"


def test_the_floor_is_justified_where_an_auditor_will_look():
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "cryptography.io/en/latest/security/" in security
    assert ">=46.0.0" in security and ">=1.26.4" in security
    assert "oldest versions CI tests" in security        # a tested floor, not a claim about safety
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "cryptography.io/en/latest/security/" in pyproject
    assert "lowest" in pyproject                         # the job that proves the number



def test_the_dev_extra_pins_the_ruff_the_lint_job_uses():
    """A lint that passes locally and fails in CI is a lint nobody can trust.

    Two ruff versions sort imports differently, so the development install has
    to carry the same pin as the `lint` job.
    """
    pyproject = read_pyproject()
    dev = pyproject["project"]["optional-dependencies"]["dev"]
    pinned = [spec for spec in dev if spec.startswith("ruff")]
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    version = re.search(r'pip install "ruff==([0-9.]+)"', ci).group(1)
    assert pinned == [f"ruff=={version}"], (
        f"the lint job installs ruff {version} and the dev extra asks for {pinned}")


def test_the_lowest_job_installs_exactly_the_declared_floors():
    """A floor is tested or it is decoration: the job has to pin these versions.

    If someone raises a floor in `pyproject.toml` and forgets the CI job, the
    published minimum goes back to being untested. This test fails then.
    """
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    header = chr(10) + "  lowest:"
    assert header in ci
    job = ci.split(header, 1)[1].split(chr(10) + "  lint:", 1)[0]
    assert 'python-version: "3.10"' in job               # the oldest interpreter supported
    for name, floor in FLOORS.items():
        assert f'"{name}=={floor}"' in job, f"the lowest job does not pin {name}=={floor}"
    assert "pip-audit" in job and "continue-on-error: true" in job
    assert "pytest tests/" in job


# -------------------------------------------------------------------- CRY-002
def test_the_absence_of_revocation_is_documented_as_a_property():
    """CRY-002: a missing control has to be named, with the procedure that exists.

    Not a test of behaviour — there is no behaviour; that is the finding. It
    pins the documentation, because the only mitigation a user has is knowing.
    """
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "There is no revocation." in security
    assert "--validity-days" in security          # the procedure that exists today
    roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    assert "Revocation (CRY-002)" in roadmap      # and the one that does not, yet
    assert "SCA-002" in roadmap
