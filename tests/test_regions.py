# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Where a destination is, and the one option that reaches the network to find out.

The rule this suite exists to hold: **nothing here resolves anything unless the
operator asked for it on the command line**. Every test that involves DNS
replaces `socket.getaddrinfo` with a fake, and one test asserts that the real
one is never reached otherwise.
"""
import pytest
from conftest import session_graph

from agent_certify.graph import AgentGraph
from agent_certify.policy import Policy, PolicyRule, split_regions
from agent_certify.regions import (
    CCTLD,
    CCTLD_COUNTRY,
    CCTLD_EXCEPTIONS,
    CCTLD_IDN,
    IDN_CCTLD_CHECKED,
    IDN_CCTLD_COUNTRY,
    ISO_3166_1_ALPHA_2,
    OFFLINE,
    GeoIPDatabase,
    Region,
    RegionResolver,
    cctld_country,
    ip_version,
    load_geoip,
    resolver_hint,
)

ROWS = """1.0.0.0,1.0.0.255,AU
8.8.8.0,8.8.8.255,US
77.88.8.0,77.88.8.255,RU
2001:db8::,2001:db8::ffff,DE
"""


@pytest.fixture
def geoip(tmp_path):
    path = tmp_path / "ip2country.csv"
    path.write_text(ROWS, encoding="utf-8")
    return load_geoip(path)


def no_dns(host, port=None, *args, **kwargs):
    raise AssertionError(f"a name was resolved: {host!r}. Nothing may reach the network by default.")


# ------------------------------------------------------------------- ccTLDs
@pytest.mark.parametrize("host,country", [
    ("api.example.cn", "CN"),
    ("x.ru", "RU"),
    ("mail.something.by", "BY"),
    ("news.ir", "IR"),
    ("bbc.co.uk", "GB"),           # the exception everyone knows
    ("x.gb", "GB"),
    ("legacy.su", "RU"),
    ("ascension.ac", "SH"),
    ("timor.tp", "TL"),
    ("agency.eu", "EU"),           # not a country code, but a region an operator can forbid
    ("API.EXAMPLE.CN.", "CN"),     # trailing dot and case
    ("example.com", ""),
    ("deep.example.io", "IO"),     # a real ccTLD even when nobody treats it as one
    ("1.2.3.4", ""),
    ("[::1]", ""),
    ("", ""),
    ("no-dots", ""),
    (None, ""),
])
def test_cctld_country(host, country):
    assert cctld_country(host) == country


def test_the_table_is_the_iso_list_plus_the_exceptions():
    """One rule and a list of exceptions, so there is nothing to keep in step by hand."""
    assert len(ISO_3166_1_ALPHA_2) == 249                 # officially assigned, 2026
    assert len(set(ISO_3166_1_ALPHA_2)) == len(ISO_3166_1_ALPHA_2)
    assert all(len(code) == 2 and code.isupper() and code.isalpha() for code in ISO_3166_1_ALPHA_2)
    for code in ("CN", "RU", "BY", "IR", "GB", "US", "CH", "DE", "KP", "SY", "CU", "VE"):
        assert code in ISO_3166_1_ALPHA_2
    # Every two-letter ccTLD maps to a code, and only the exceptions differ
    # from their label. The internationalised labels are a third rule, pinned
    # to IANA by their own test below.
    for label, country in CCTLD_COUNTRY.items():
        if label.startswith("xn--"):
            assert IDN_CCTLD_COUNTRY[label] == country
            continue
        assert len(label) == 2 and label.islower()
        assert country == CCTLD_EXCEPTIONS.get(label, label.upper())
    assert CCTLD_COUNTRY["uk"] == "GB" and CCTLD_COUNTRY["de"] == "DE"
    assert CCTLD_COUNTRY["xn--p1ai"] == "RU"
    # The three rules together, with nothing lost to a collision.
    assert len(CCTLD_COUNTRY) == (len(ISO_3166_1_ALPHA_2) + len(CCTLD_EXCEPTIONS)
                                  + len(IDN_CCTLD_COUNTRY))


# ------------------------------------------------------------------- GeoIP
def test_no_database_ships_with_the_package():
    """A country database is the operator's to supply: none is bundled, none is downloaded."""
    import agent_certify

    root = __import__("pathlib").Path(agent_certify.__file__).parent
    assert not list(root.rglob("*.csv")) and not list(root.rglob("*.mmdb"))


@pytest.mark.parametrize("address,country", [
    ("1.0.0.1", "AU"), ("1.0.0.255", "AU"), ("8.8.8.8", "US"), ("77.88.8.8", "RU"),
    ("2001:db8::1", "DE"), ("[2001:db8::1]", "DE"),          # brackets allowed
    ("1.0.1.0", ""),                                          # just past a range
    ("0.0.0.1", ""),                                          # before every range
    ("9.9.9.9", ""), ("2001:db9::1", ""),
    ("not-an-address", ""), ("", ""),
])
def test_geoip_lookup(geoip, address, country):
    assert geoip.country(address) == country


def test_geoip_skips_unusable_rows_instead_of_refusing_the_file(tmp_path):
    """Operational data: one bad line must not stop a scan."""
    path = tmp_path / "db.csv"
    path.write_text("ip_start,ip_end,country\n"            # a header
                    "1.0.0.0,1.0.0.255,AU\n"
                    "broken\n"                              # too few columns
                    "9.9.9.9,8.8.8.8,US\n"                  # end before start
                    "1.2.3.4,1.2.3.5,USA\n"                 # not alpha-2
                    "::,ffff::,DE\n", encoding="utf-8")
    db = load_geoip(path)
    assert db.country("1.0.0.1") == "AU" and db.country("8.8.8.8") == ""
    assert db.ranges == 2 and db.skipped == 4               # header included
    assert len(db) == db.ranges


@pytest.mark.parametrize("content,message", [
    ("", "no usable address ranges"),
    ("nothing,useful\n", "no usable address ranges"),
])
def test_an_unusable_database_says_so(tmp_path, content, message):
    path = tmp_path / "empty.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_geoip(path)


def test_a_missing_database_says_so(tmp_path):
    with pytest.raises(ValueError, match="cannot read the GeoIP database"):
        load_geoip(tmp_path / "nope.csv")


def test_ip_version():
    assert ip_version("1.2.3.4") == 4 and ip_version("::1") == 6 and ip_version("[::1]") == 6
    assert ip_version("example.com") == 0 and ip_version("") == 0


# ---------------------------------------------------------------- resolution
def test_the_default_resolver_reads_names_and_nothing_else(monkeypatch):
    """OFFLINE is what the library and the MCP server use: ccTLD only."""
    monkeypatch.setattr("socket.getaddrinfo", no_dns)
    assert OFFLINE.region("api.example.cn") == Region("CN", "cctld")
    assert OFFLINE.region("example.com") == Region("", "unknown")
    assert OFFLINE.region("1.2.3.4") == Region("", "unknown")      # no database either
    assert not OFFLINE.resolve_dns and OFFLINE.geoip is None
    assert OFFLINE.lookups == 0


def test_a_database_alone_adds_address_literals_and_no_network(geoip, monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", no_dns)
    resolver = RegionResolver(geoip=geoip)
    assert resolver.region("1.0.0.1").describe() == "AU (GeoIP database on an address literal)"
    assert resolver.region("77.88.8.8") == Region("RU", "geoip")
    assert resolver.region("example.com") == Region("", "unknown")  # a name stays unknown
    assert resolver.lookups == 0


def test_resolve_dns_resolves_then_looks_up(geoip):
    calls = []

    def fake(host, port=None, *args, **kwargs):
        calls.append(host)
        return [(2, 1, 6, "", ("77.88.8.8", 0))]

    resolver = RegionResolver(geoip=geoip, resolve_dns=True, getaddrinfo=fake)
    region = resolver.region("example.com")
    assert region == Region("RU", "dns+geoip")
    assert region.describe() == "RU (DNS lookup then GeoIP database)"
    assert calls == ["example.com"]
    # Cached for the run: forty calls to the same host resolve it once.
    for _ in range(40):
        assert resolver.region("example.com").country == "RU"
    assert calls == ["example.com"] and resolver.lookups == 1
    # A ccTLD still wins: it is free and it needs no network.
    assert resolver.region("x.cn") == Region("CN", "cctld")
    assert calls == ["example.com"]


def test_resolve_dns_needs_a_database():
    with pytest.raises(ValueError, match="resolve_dns needs a GeoIP database"):
        RegionResolver(resolve_dns=True)


def test_resolution_failures_are_unknown_not_errors(geoip):
    import socket as socket_module

    def raises(host, port=None, *args, **kwargs):
        raise socket_module.gaierror("no such host")

    resolver = RegionResolver(geoip=geoip, resolve_dns=True, getaddrinfo=raises)
    assert resolver.region("nowhere.example") == Region("", "unknown")

    def slow(host, port=None, *args, **kwargs):
        import time
        time.sleep(5)
        return []

    bounded = RegionResolver(geoip=geoip, resolve_dns=True, getaddrinfo=slow, timeout=0.05)
    import time
    started = time.perf_counter()
    assert bounded.region("slow.example") == Region("", "unknown")
    assert time.perf_counter() - started < 2.0          # the deadline, not the lookup, decides

    for shape in ([], None, [(2, 1, 6, "", ())], [("nonsense",)]):
        odd = RegionResolver(geoip=geoip, resolve_dns=True,
                             getaddrinfo=lambda *_a, _shape=shape, **_k: _shape)
        assert odd.region("odd.example") == Region("", "unknown")


def test_the_number_of_lookups_is_bounded(geoip):
    resolver = RegionResolver(geoip=geoip, resolve_dns=True, max_lookups=3,
                              getaddrinfo=lambda *_a, **_k: [(2, 1, 6, "", ("8.8.8.8", 0))])
    found = [resolver.region(f"h{i}.example").country for i in range(10)]
    assert found.count("US") == 3 and resolver.lookups == 3


def test_the_warning_names_the_resolver_and_prints_once(geoip, capsys):
    resolver = RegionResolver(geoip=geoip, resolve_dns=True,
                              getaddrinfo=lambda *_a, **_k: [(2, 1, 6, "", ("8.8.8.8", 0))])
    assert resolver.warn_once() is True
    out = capsys.readouterr().err
    assert "--resolve-dns" in out and "over the network" in out and "timeout" in out
    assert resolver_hint() in out
    assert resolver.warn_once() is False and capsys.readouterr().err == ""
    # And an offline resolver has nothing to announce.
    assert RegionResolver().warn_once() is False


def test_the_resolver_hint_reads_resolv_conf_where_there_is_one(tmp_path, monkeypatch):
    """The warning must name something an operator can check, not "the network"."""
    import agent_certify.regions as regions_module

    conf = tmp_path / "resolv.conf"
    conf.write_text("# a comment\nsearch example.net\nnameserver 10.0.0.1\n"
                    "nameserver 10.0.0.2\nnameserver\n", encoding="utf-8")
    real_path = regions_module.Path

    class FakePath(type(conf)):
        def __new__(cls, *args, **kwargs):
            if args and str(args[0]) == "/etc/resolv.conf":
                return real_path(conf)
            return real_path(*args, **kwargs)

    monkeypatch.setattr(regions_module, "Path", FakePath)
    assert resolver_hint() == "the resolver(s) in /etc/resolv.conf: 10.0.0.1, 10.0.0.2"

    conf.write_text("search example.net\n", encoding="utf-8")       # no nameserver line
    assert resolver_hint() == "the operating system's configured DNS resolver"


def test_the_resolver_hint_falls_back_when_there_is_no_file():
    """On Windows there is no resolv.conf, and the hint says so rather than guessing."""
    hint = resolver_hint()
    assert hint and ("resolv.conf" in hint or hint == "the operating system's configured DNS resolver")


def test_an_empty_or_odd_host_is_unknown(geoip):
    resolver = RegionResolver(geoip=geoip)
    for host in ("", "   ", None, 42, b"x.ru"):
        assert resolver.region(host) == Region("", "unknown")


def test_regions_of_many_hosts(geoip):
    resolver = RegionResolver(geoip=geoip)
    assert {h: r.country for h, r in resolver.regions(["x.ru", "1.0.0.1", "a.com"]).items()} == {
        "x.ru": "RU", "1.0.0.1": "AU", "a.com": ""}


def test_region_describe():
    assert Region().describe() == "region unknown"
    assert Region("CN", "cctld").describe() == "CN (ccTLD)"
    assert Region("CN", "cctld").known and not Region().known


# -------------------------------------------------------------- the policy rule
def session(hosts, tool="WebFetch"):
    g = session_graph("s", {tool: 3, "Read": 1})
    g.record_egress(f"tool:{tool}", set(hosts), outbound_bytes=400)
    return g


def test_split_regions():
    assert split_regions("CN,RU") == ["CN", "RU"]
    assert split_regions(" cn , ru,CN ") == ["CN", "RU"]        # normalised and deduplicated
    for bad in ("", ",", "CHN", "C1", "C"):
        with pytest.raises(ValueError, match="country code"):
            split_regions(bad)


def test_forbidden_region_fires_with_the_country_and_the_source():
    policy = Policy([PolicyRule("forbidden_region", "CN,RU", "critical", "data must stay in the EU")])
    graph = session(["api.unknown.cn", "ok.example.com", "mirror.ru"])
    hits = policy.check(graph)
    assert [v.severity for v in hits] == ["critical", "critical"]
    assert hits[0].message == "FORBIDDEN region CN: api.unknown.cn (CN (ccTLD))"
    assert "reached by tool:WebFetch" in hits[0].observed
    assert hits[1].message.startswith("FORBIDDEN region RU: mirror.ru")
    assert all(v.rule.kind == "forbidden_region" for v in hits)


def test_forbidden_region_says_how_an_address_was_decided(geoip):
    policy = Policy([PolicyRule("forbidden_region", "RU", "critical", "x")])
    graph = session(["77.88.8.8"])
    assert policy.check(graph) == []                            # no database: nothing to say
    hits = policy.check(graph, RegionResolver(geoip=geoip))
    assert len(hits) == 1
    assert hits[0].message == ("FORBIDDEN region RU: 77.88.8.8 "
                               "(RU (GeoIP database on an address literal))")


def test_forbidden_region_says_when_dns_was_used(geoip):
    resolver = RegionResolver(geoip=geoip, resolve_dns=True,
                              getaddrinfo=lambda *_a, **_k: [(2, 1, 6, "", ("77.88.8.8", 0))])
    policy = Policy([PolicyRule("forbidden_region", "RU", "critical", "x")])
    hits = policy.check(session(["mirror.example.com"]), resolver)
    assert len(hits) == 1
    assert "DNS lookup then GeoIP database" in hits[0].message


def test_an_unknown_region_is_ignored_by_default_and_reported_when_asked():
    """A .com says nothing unless something resolves it; a .cn says CN, which is not RU."""
    graph = session(["ok.example.com", "api.unknown.cn"])
    ignore = Policy([PolicyRule("forbidden_region", "RU", "critical", "x")])
    assert ignore.check(graph) == []
    warn = Policy([PolicyRule("forbidden_region", "RU", "critical", "x", unknown_region="warning")])
    hits = warn.check(graph)
    assert [(v.severity, v.message) for v in hits] == [
        ("warning", "Region unknown for ok.example.com: cannot say whether it is in RU")]
    assert "names are not resolved" in hits[0].observed
    assert "no ccTLD, no address database match" in hits[0].observed


def test_the_rule_validates_its_own_target_and_option():
    with pytest.raises(ValueError, match="country code"):
        PolicyRule("forbidden_region", "nope", "critical", "x")
    with pytest.raises(ValueError, match="unknown_region must be one of"):
        PolicyRule("forbidden_region", "CN", "critical", "x", unknown_region="fail")
    rule = PolicyRule("forbidden_region", "ru,cn", "warning", "x")
    assert rule.regions == ["CN", "RU"] and rule.describe() == "FORBIDDEN REGION: ru,cn"
    assert PolicyRule("forbidden_tool", "Bash", "warning", "x").regions == []


def test_the_rule_survives_a_file_round_trip(tmp_path):
    path = tmp_path / "policy.json"
    Policy([PolicyRule("forbidden_region", "CN", "critical", "x", unknown_region="warning"),
            PolicyRule("forbidden_tool", "Bash", "warning", "y")]).save(path)
    stored = __import__("json").loads(path.read_text(encoding="utf-8"))
    assert stored["rules"][0]["unknown_region"] == "warning"
    assert "unknown_region" not in stored["rules"][1]       # the default is not written
    loaded = Policy.load(path)
    assert loaded.rules[0].unknown_region == "warning" and loaded.rules[1].unknown_region == "ignore"


_RULE = '{"kind": "forbidden_region", "target": "CN", "severity": "critical"'


@pytest.mark.parametrize("rule", [
    _RULE + "}",                                             # no message
    _RULE + ', "message": "x", "extra": "y"}',               # a key the format does not have
    _RULE + ', "message": "x", "unknown_region": 5}',        # not a string
])
def test_a_malformed_rule_is_refused(tmp_path, rule):
    path = tmp_path / "policy.json"
    path.write_text('{"rules": [' + rule + ']}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid policy format"):
        Policy.load(path)


def test_a_policy_written_before_this_release_still_loads(tmp_path):
    path = tmp_path / "old.json"
    path.write_text('{"rules": [{"kind": "forbidden_tool", "target": "Bash", '
                    '"severity": "warning", "message": "no shell"}], '
                    '"generated_from": null, "created_at": null}', encoding="utf-8")
    policy = Policy.load(path)
    assert policy.rules[0].unknown_region == "ignore"


def test_suggest_policy_never_drafts_a_region_rule():
    """Which countries an organisation will not send data to is not a statistic."""
    from agent_certify.baseline import BaselineLearner
    from agent_certify.policy import PolicyGenerator

    graphs = [session(["api.unknown.cn", "mirror.ru"]) for _ in range(3)]
    baseline = BaselineLearner().learn_graphs(graphs)
    assert baseline.known_domains                           # it saw the destinations
    draft = PolicyGenerator().suggest(baseline)
    assert draft.rules and not any(r.kind == "forbidden_region" for r in draft.rules)


def test_the_policy_check_never_resolves_a_name(monkeypatch):
    """The rule the MCP server depends on."""
    monkeypatch.setattr("socket.getaddrinfo", no_dns)
    policy = Policy([PolicyRule("forbidden_region", "CN,RU", "critical", "x",
                                unknown_region="warning")])
    graph = session(["ok.example.com", "api.unknown.cn", "1.2.3.4"])
    hits = policy.check(graph)                              # the default resolver, no argument
    assert [v.rule.kind for v in hits] == ["forbidden_region"] * 3
    assert sum(1 for v in hits if v.severity == "critical") == 1


def test_a_geoip_database_is_read_once_per_run(geoip, monkeypatch):
    """The resolver caches, so a session with forty calls to one host costs one lookup."""
    seen = []

    def fake(host, port=None, *args, **kwargs):
        seen.append(host)
        return [(2, 1, 6, "", ("1.0.0.1", 0))]

    resolver = RegionResolver(geoip=geoip, resolve_dns=True, getaddrinfo=fake)
    graph = session(["a.example.com"] * 1)
    for _ in range(5):
        resolver.region("a.example.com")
    Policy([PolicyRule("forbidden_region", "AU", "warning", "x")]).check(graph, resolver)
    assert seen == ["a.example.com"]


def test_a_database_object_can_be_built_directly(tmp_path):
    path = tmp_path / "d.csv"
    path.write_text("1.0.0.0,1.0.0.255,au\n", encoding="utf-8")
    db = GeoIPDatabase(path)
    assert db.country("1.0.0.7") == "AU"                    # upper-cased on load


# --------------------------------------------------------------- IDN ccTLDs
# An internationalised ccTLD is a country-code domain, and a forbidden_region
# rule has to reach it. These tests carry their own copy of the table and the
# day it was checked, so the table cannot drift from its source in silence.

#: Transcribed from the IANA Root Zone Database's machine-readable form,
#: https://data.iana.org/TLD/v1/tlds.json — every entry of ``country-code``
#: type whose label starts with ``xn--``, with that file's own
#: ``iso3166_code``. Checked on the date below; the file read was generated
#: 2026-11-23 and every entry was ``active``.
IDN_CCTLD_AT = {
    "xn--2scrj9c": "IN", "xn--3e0b707e": "KR", "xn--3hcrj9c": "IN", "xn--45br5cyl": "IN",
    "xn--45brj9c": "IN", "xn--4dbrk0ce": "IL", "xn--54b7fta0cc": "BD", "xn--80ao21a": "KZ",
    "xn--90a3ac": "RS", "xn--90ae": "BG", "xn--90ais": "BY",
    "xn--clchc0ea0b2g2a9gcd": "SG", "xn--d1alf": "MK", "xn--e1a4c": "EU",
    "xn--fiqs8s": "CN", "xn--fiqz9s": "CN", "xn--fpcrj9c3d": "IN", "xn--fzc2c9e2c": "LK",
    "xn--gecrj9c": "IN", "xn--h2breg3eve": "IN", "xn--h2brj9c": "IN",
    "xn--h2brj9c8c": "IN", "xn--j1amh": "UA", "xn--j6w193g": "HK", "xn--kprw13d": "TW",
    "xn--kpry57d": "TW", "xn--l1acc": "MN", "xn--lgbbat1ad8j": "DZ", "xn--mgb9awbf": "OM",
    "xn--mgba3a4f16a": "IR", "xn--mgbaam7a8h": "AE", "xn--mgbah1a3hjkrd": "MR",
    "xn--mgbai9azgqp6j": "PK", "xn--mgbayh7gpa": "JO", "xn--mgbbh1a": "IN",
    "xn--mgbbh1a71e": "IN", "xn--mgbc0a9azcg": "MA", "xn--mgbcpq6gpa1a": "BH",
    "xn--mgberp4a5d4ar": "SA", "xn--mgbgu82a": "IN", "xn--mgbpl2fh": "SD",
    "xn--mgbtx2b": "IQ", "xn--mgbx4cd0ab": "MY", "xn--mix891f": "MO", "xn--node": "GE",
    "xn--o3cw4h": "TH", "xn--ogbpf8fl": "SY", "xn--p1ai": "RU", "xn--pgbs0dh": "TN",
    "xn--q7ce6a": "LA", "xn--qxa6a": "EU", "xn--qxam": "GR", "xn--rvc1e0am3e": "IN",
    "xn--s9brj9c": "IN", "xn--wgbh1c": "EG", "xn--wgbl6a": "QA", "xn--xkc2al3hye2a": "LK",
    "xn--xkc2dl3a5ee0h": "IN", "xn--y9a3aq": "AM", "xn--yfro4i67o": "SG",
    "xn--ygbi2ammx": "PS"
}


def test_the_idn_cctld_table_is_pinned_to_the_day_it_was_checked():
    """Change the table, re-check IANA, change the date — all three together.

    A missing entry is not a wrong answer here, it is **no** answer: the
    destination comes back ``unknown`` and a ``forbidden_region`` rule naming
    that country passes it through. That is how ``collector.xn--p1ai`` — a
    Russian ccTLD any browser reaches — got past a rule naming ``RU``, so the
    list is pinned the way :data:`agent_certify.domains.NOT_HOSTS` is.

    Re-check at every new delegation (a new script for a country that has one,
    or a country's first) against the Root Zone Database, type
    ``country-code``, column *IDN ccTLD*:
    https://www.iana.org/domains/root/db — machine-readable at
    https://data.iana.org/TLD/v1/tlds.json
    """
    assert IDN_CCTLD_CHECKED == "2026-11-24", (
        "IDN_CCTLD_COUNTRY was edited, or the check is due: verify every entry against the "
        "IANA Root Zone Database, then update IDN_CCTLD_CHECKED and the copy in this test.")
    assert IDN_CCTLD_COUNTRY == IDN_CCTLD_AT, (
        "IDN_CCTLD_COUNTRY changed. Verify the whole table against "
        "https://data.iana.org/TLD/v1/tlds.json (type country-code, labels starting xn--, "
        "field iso3166_code), then update IDN_CCTLD_CHECKED and IDN_CCTLD_AT together.")


def test_every_entry_is_a_punycode_label_and_a_known_country():
    for label, country in IDN_CCTLD_COUNTRY.items():
        assert label.startswith("xn--") and label.islower()
        assert len(country) == 2 and country.isupper()
        # Either an assigned ISO code, or one of the exceptions already named
        # here — xn--e1a4c and xn--qxa6a are the European Union's, like .eu.
        assert country in ISO_3166_1_ALPHA_2 or country in CCTLD_EXCEPTIONS.values()


@pytest.mark.parametrize("host, country", [
    ("collector.xn--p1ai", "RU"),            # рф
    ("shop.xn--fiqs8s", "CN"),               # 中国, simplified
    ("shop.xn--fiqz9s", "CN"),               # 中國, traditional
    ("x.xn--90ais", "BY"),                   # бел
    ("api.xn--mgba3a4f16a", "IR"),           # ایران
    ("a.b.xn--p1ai", "RU"),                  # a subdomain is still under the ccTLD
    ("XN--P1AI", "RU"),                      # the label alone, any case
    ("x.xn--3e0b707e", "KR"),
    ("x.xn--j1amh", "UA"),
    ("x.xn--node", "GE"),                    # a label that reads like a word
    ("x.xn--notreal", ""),                   # not delegated: no answer invented
    ("x.example.com", ""),
])
def test_an_internationalised_cctld_names_its_country(host, country):
    assert cctld_country(host) == country


def test_the_source_is_named_apart_from_the_latin_table():
    # "ccTLD (IDN)" says which of the two tables answered: one is derived from
    # the ISO list, the other transcribed from IANA by hand.
    idn = OFFLINE.region("collector.xn--p1ai")
    assert (idn.country, idn.source) == ("RU", CCTLD_IDN)
    assert idn.describe() == "RU (ccTLD (IDN))"
    latin = OFFLINE.region("collector.example.ru")
    assert (latin.country, latin.source) == ("RU", CCTLD)
    assert latin.describe() == "RU (ccTLD)"


def test_an_internationalised_cctld_needs_no_lookup(tmp_path):
    def no_dns(host, *args, **kwargs):
        raise AssertionError(f"resolved {host!r}: a ccTLD answers offline")

    db = tmp_path / "ip2country.csv"
    db.write_text('"1.0.0.0","1.255.255.255","AU"\n', encoding="utf-8")
    resolver = RegionResolver(geoip=load_geoip(db), resolve_dns=True, getaddrinfo=no_dns)
    assert resolver.region("collector.xn--p1ai").country == "RU"
    assert resolver.lookups == 0


def test_a_forbidden_region_rule_reaches_an_internationalised_domain():
    """The point of the table: RU has to catch рф, and CN both Chinese forms."""
    graph = AgentGraph()
    graph.add_node("claude", kind="orchestrator")
    graph.record_egress("claude", {"collector.xn--p1ai", "shop.xn--fiqs8s",
                                   "shop.xn--fiqz9s", "ok.example.com"}, 2048)

    def violations(target):
        rule = PolicyRule(kind="forbidden_region", target=target, severity="critical",
                          message=f"destinations in {target} are not allowed")
        return {v.observed for v in Policy([rule]).check(graph)}

    assert any("collector.xn--p1ai" in observed for observed in violations("RU"))
    cn = violations("CN")
    assert any("shop.xn--fiqs8s" in observed for observed in cn)
    assert any("shop.xn--fiqz9s" in observed for observed in cn)
    # And nothing is invented about a destination the table says nothing about.
    assert not any("ok.example.com" in observed for observed in violations("RU") | cn)
