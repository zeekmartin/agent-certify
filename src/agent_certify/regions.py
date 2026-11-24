# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Where a destination is, decided offline.

A host name says where data went; an operator who answers to a regulator often
has to say *which country* it went to. This module turns a destination into an
ISO 3166-1 alpha-2 country code, and — this is the whole design — it says how
it knows, so a reader can weigh the answer:

=============  =========================================  ======================
source         from                                       needs
=============  =========================================  ======================
``cctld``      the host's country-code top-level domain   nothing
               (``api.example.cn`` -> ``CN``)
``geoip``      an address literal, looked up in a local   ``--geoip-db``
               database (``1.2.3.4`` -> ``AU``)
``dns+geoip``  a name resolved to an address, then that   ``--resolve-dns`` and
               address looked up                          ``--geoip-db``
``unknown``    nothing above applied                      —
=============  =========================================  ======================

**What this cannot tell you.** A ``.com`` hosted in Shanghai is ``unknown``
without resolution: there is nothing in the name to read, and the tool does not
resolve by default. A ccTLD is a *registration*, not a location — ``.io``
domains sit in Virginia, a ``.de`` site can be served from Oregon — and an
address database says where an address block is *registered*, which for a CDN
is a cache in the nearest city rather than the origin. So a region is evidence
about a destination, not a finding about data residency, and
``forbidden_region`` in a policy is a tripwire rather than a proof.

**No network, by default and everywhere.** ``cctld`` reads a string. ``geoip``
reads a file the operator supplies; **no database ships with this package** and
none is downloaded. Only :class:`RegionResolver` with ``resolve_dns=True``
makes a network call, it must be asked for explicitly on the command line, and
it is never available from the MCP server (see ``SECURITY.md`` §1).

The database format is DB-IP's *IP to Country Lite* CSV
(``ip_start,ip_end,country`` per line, one row per address range, IPv4 and IPv6
in the same file or in two), which is published under CC BY 4.0 and is what the
``--geoip-db`` flag expects. Any CSV with those three columns works.
"""
from __future__ import annotations

import csv
import ipaddress
import os
import socket
import sys
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

#: ccTLDs whose label is *not* the country code: a two-letter top-level domain
#: that does not simply uppercase to its ISO 3166-1 alpha-2 code.
CCTLD_EXCEPTIONS = {
    "uk": "GB",      # the United Kingdom registers .uk; .gb exists but is unused
    "ac": "SH",      # Ascension Island, part of Saint Helena for ISO 3166-1
    "su": "RU",      # the Soviet Union's ccTLD, still delegated and sold
    "tp": "TL",      # East Timor's retired code
    "yu": "RS",      # Yugoslavia's retired code
    "an": "CW",      # the Netherlands Antilles, dissolved
    "eu": "EU",      # not a country: exceptionally reserved for the European Union
}

#: Every officially assigned ISO 3166-1 alpha-2 code. A two-letter top-level
#: domain that is one of these *is* that country's ccTLD, which is where the
#: table comes from: the exceptions above are the only cases where the two
#: differ. Codes with no delegated ccTLD (``.bv``, ``.eh``) are harmless to
#: carry — nothing will ever be looked up under them.
ISO_3166_1_ALPHA_2 = (                                  # noqa: SIM905 — grouped to stay readable
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ "
    "BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ "
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ "
    "DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR "
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY "
    "HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT "
    "JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ "
    "LA LB LC LI LK LR LS LT LU LV LY "
    "MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ "
    "NA NC NE NF NG NI NL NO NP NR NU NZ OM "
    "PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW "
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ "
    "TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ "
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
).split()

#: ccTLD label -> country code. Built from the two rules above, so there is one
#: place to look and nothing to keep in step by hand.
CCTLD_COUNTRY = {code.lower(): code for code in ISO_3166_1_ALPHA_2} | CCTLD_EXCEPTIONS

CCTLD, GEOIP, DNS_GEOIP, UNKNOWN = "cctld", "geoip", "dns+geoip", "unknown"

#: How long one name resolution may hold the caller up, and how many of them a
#: single run may make. Both are there so that a session full of unknown hosts
#: cannot turn a scan into a stall: a lookup that misses its deadline is treated
#: as unknown, not retried.
DNS_TIMEOUT_SECONDS = 2.0
MAX_DNS_LOOKUPS = 500


@dataclass(frozen=True, slots=True)
class Region:
    """A destination's country, and how it was determined.

    ``country`` is an ISO 3166-1 alpha-2 code, or ``""`` when nothing applied;
    ``source`` is one of ``cctld``, ``geoip``, ``dns+geoip``, ``unknown``.
    """
    country: str = ""
    source: str = UNKNOWN

    @property
    def known(self) -> bool:
        return bool(self.country)

    def describe(self) -> str:
        """``"CN (ccTLD)"``, or ``"region unknown"``."""
        if not self.known:
            return "region unknown"
        label = {CCTLD: "ccTLD", GEOIP: "GeoIP database on an address literal",
                 DNS_GEOIP: "DNS lookup then GeoIP database"}.get(self.source, self.source)
        return f"{self.country} ({label})"


UNKNOWN_REGION = Region()


def cctld_country(host: str) -> str:
    """The country a host's ccTLD belongs to, or ``""``.

    ``api.example.cn`` is ``CN``; ``bbc.co.uk`` is ``GB``; ``example.com`` is
    ``""``, and so is an address literal, which has no top-level domain.
    """
    if not isinstance(host, str):
        return ""
    label = host.strip().rstrip(".").rsplit(".", 1)[-1].lower()
    return CCTLD_COUNTRY.get(label, "")


def _as_int(text: str) -> tuple[int, int] | None:
    """``("1.2.3.4")`` as ``(version, integer)``, or None when it is not an address."""
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return address.version, int(address)


def ip_version(host: str) -> int:
    """4, 6 or 0: the version of an address literal, brackets allowed (``[::1]``)."""
    parsed = _as_int(host.strip().strip("[]"))
    return parsed[0] if parsed else 0


class GeoIPDatabase:
    """Address ranges to country codes, read from a local CSV once per run.

    The file is DB-IP's *IP to Country Lite* export or anything with the same
    three columns (``ip_start,ip_end,country``). Rows are kept in two sorted
    lists, one per address family, and looked up with :mod:`bisect`: no index to
    build, no dependency to add, and a 3-million-row file answers in
    microseconds.

    Malformed rows are counted (:attr:`skipped`) and skipped rather than
    refused: a country database is operational data, and one bad line in it
    should not stop a scan.
    """

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.skipped = 0
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._ranges: dict[int, list[tuple[int, str]]] = {4: [], 6: []}
        self._load()

    def _load(self) -> None:
        rows: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
        with self.path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.reader(handle):
                if len(row) < 3:
                    self.skipped += 1 if any(field.strip() for field in row) else 0
                    continue
                first, last = _as_int(row[0]), _as_int(row[1])
                country = row[2].strip().upper()
                if (first is None or last is None or first[0] != last[0] or first[1] > last[1]
                        or len(country) != 2 or not country.isalpha()):
                    self.skipped += 1
                    continue
                rows[first[0]].append((first[1], last[1], country))
        for version, entries in rows.items():
            entries.sort()
            self._starts[version] = [start for start, _, _ in entries]
            self._ranges[version] = [(end, country) for _, end, country in entries]

    def __len__(self) -> int:
        return len(self._starts[4]) + len(self._starts[6])

    @property
    def ranges(self) -> int:
        """How many address ranges were loaded."""
        return len(self)

    def country(self, address: str) -> str:
        """The country of one address literal, or ``""`` when no range covers it."""
        parsed = _as_int(address.strip().strip("[]"))
        if parsed is None:
            return ""
        version, value = parsed
        starts = self._starts.get(version) or []
        index = bisect_right(starts, value) - 1
        if index < 0:
            return ""
        end, country = self._ranges[version][index]
        return country if value <= end else ""


def load_geoip(path: str | os.PathLike) -> GeoIPDatabase:
    """Read a country database; ``ValueError`` when the file is unusable.

    The message names the path and what was expected, because a wrong
    ``--geoip-db`` is an operator error to fix, not a secret.
    """
    try:
        database = GeoIPDatabase(path)
    except OSError as exc:
        raise ValueError(f"cannot read the GeoIP database {Path(path).as_posix()}: {exc.strerror}") from None
    if not len(database):
        raise ValueError(
            f"{Path(path).as_posix()} holds no usable address ranges; expected a CSV of "
            "'ip_start,ip_end,country' rows (DB-IP's IP to Country Lite export, CC BY 4.0)")
    return database


def resolver_hint() -> str:
    """Which resolver a DNS lookup would reach, as far as can be told offline.

    Read from ``/etc/resolv.conf`` where there is one. The point is that the
    warning printed before any lookup names something the operator can check,
    rather than "the network".
    """
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "the operating system's configured DNS resolver"
    servers = [line.split()[1] for line in text.splitlines()
               if line.strip().startswith("nameserver") and len(line.split()) > 1]
    if not servers:
        return "the operating system's configured DNS resolver"
    return "the resolver(s) in /etc/resolv.conf: " + ", ".join(servers[:3])


class RegionResolver:
    """Turns destinations into regions, offline unless explicitly told otherwise.

    Usage::

        regions = RegionResolver()                      # ccTLD only, no file, no network
        regions = RegionResolver(geoip=load_geoip(path))        # and address literals
        regions = RegionResolver(geoip=db, resolve_dns=True)    # and names, over the network

        regions.region("api.example.cn")       # Region("CN", "cctld")
        regions.region("1.2.3.4")              # Region("AU", "geoip") with a database
        regions.region("example.com")          # Region("", "unknown") unless resolve_dns

    ``resolve_dns`` requires a database — an address with nothing to look it up
    in says nothing — and :meth:`warn_once` prints what it is about to do.

    **Every answer is cached for the life of the resolver, including the
    failures.** A name that did not resolve, or whose lookup ran past the
    deadline, stays ``unknown`` and is never looked up again: a long ``watch``
    would otherwise retry an unreachable host on every cycle, leaving a dead
    thread behind each time, and :attr:`max_lookups` is a budget for the run
    rather than for each cycle. Hold one resolver for the process and both
    properties follow (``SessionWatcher`` does).
    """

    def __init__(self, geoip: GeoIPDatabase | None = None, resolve_dns: bool = False,
                 timeout: float = DNS_TIMEOUT_SECONDS, max_lookups: int = MAX_DNS_LOOKUPS,
                 getaddrinfo=None):
        if resolve_dns and geoip is None:
            raise ValueError("resolve_dns needs a GeoIP database: an address alone names no country")
        self.geoip = geoip
        self.resolve_dns = bool(resolve_dns)
        self.timeout = float(timeout)
        self.max_lookups = int(max_lookups)
        self.lookups = 0                      # names actually resolved, for the report
        self._getaddrinfo = getaddrinfo or socket.getaddrinfo
        self._cache: dict[str, Region] = {}
        self._warned = False

    # ------------------------------------------------------------------ api
    def region(self, host: str) -> Region:
        """The region of one destination. Never raises."""
        if not isinstance(host, str) or not host.strip():
            return UNKNOWN_REGION
        key = host.strip().rstrip(".").lower()
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        region = self._resolve(key)
        self._cache[key] = region
        return region

    def regions(self, hosts) -> dict[str, Region]:
        """``{host: Region}`` for an iterable of hosts, in one pass."""
        return {host: self.region(host) for host in sorted(hosts)}

    def warn_once(self, out=None) -> bool:
        """Print what ``resolve_dns`` is about to do, once. True when it printed.

        The warning is the point of the option: a tool that says it makes no
        network connections must say so out loud the one time it does.
        """
        if not self.resolve_dns or self._warned:
            return False
        self._warned = True
        print(f"agent-certify: --resolve-dns: resolving destination names over the network via "
              f"{resolver_hint()}. Each unknown host is looked up once, with a "
              f"{self.timeout:g}s timeout, up to {self.max_lookups} names.",
              file=out or sys.stderr)
        return True

    # ------------------------------------------------------------ internals
    def _resolve(self, host: str) -> Region:
        country = cctld_country(host)
        if country:
            return Region(country, CCTLD)
        if ip_version(host):
            found = self.geoip.country(host) if self.geoip else ""
            return Region(found, GEOIP) if found else UNKNOWN_REGION
        if not self.resolve_dns or self.geoip is None or self.lookups >= self.max_lookups:
            return UNKNOWN_REGION
        for address in self._addresses(host):
            found = self.geoip.country(address)
            if found:
                return Region(found, DNS_GEOIP)
        return UNKNOWN_REGION

    def _addresses(self, host: str) -> list[str]:
        """Addresses ``host`` resolves to, bounded by :attr:`timeout`. Never raises.

        :func:`socket.getaddrinfo` takes no timeout argument — it is a blocking
        call into the C library — so it runs in a **daemon thread** and the
        caller stops waiting when the deadline passes. A lookup that misses it
        is treated as unknown and never retried; its thread finishes into
        nothing and does not hold up the process, which is why this is a daemon
        thread rather than a pooled one (a pool's shutdown joins its workers,
        and waiting out a hung resolver is exactly what the deadline exists to
        prevent).
        """
        import threading

        self.lookups += 1
        self.warn_once()
        answers: list = []

        def lookup() -> None:
            try:
                answers.extend(self._getaddrinfo(host, None) or ())
            except (OSError, UnicodeError, ValueError, TypeError):
                pass                              # a name that will not resolve is unknown

        worker = threading.Thread(target=lookup, name=f"agent-certify-dns-{host[:40]}", daemon=True)
        worker.start()
        worker.join(self.timeout)
        if worker.is_alive():
            return []                             # past the deadline: unknown, and nothing waits
        out = []
        for answer in answers:
            try:
                address = answer[4][0]
            except (IndexError, TypeError, KeyError):
                continue
            if isinstance(address, str) and address not in out:
                out.append(address)
        return out


#: The resolver everything uses unless it is handed another one: names read,
#: nothing resolved, no file. :func:`agent_certify.policy.Policy.check` and the
#: MCP server take this and nothing else.
OFFLINE = RegionResolver()
