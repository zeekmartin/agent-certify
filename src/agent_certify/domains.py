# agent-certify — Structural verification of multiagent systems
# Copyright 2026 Cognitive Engineering (Switzerland)
# SPDX-License-Identifier: Apache-2.0
"""Network destinations: where an agent's tool calls point.

An agent graph says which tools ran. It does not say *where they went* — and
for anyone who has to answer where their data is processed, that is the
question. A single MCP server or HTTP tool pointed at a different host changes
the answer without changing the topology at all.

This module finds the destinations in a session's own logs and matches them
against the patterns an operator has accepted or rejected
(:mod:`agent_certify.baseline`), so
:class:`~agent_certify.anomaly.AnomalyDetector` can report a call to a host
that is new, or one that was forbidden.

What counts as a destination
----------------------------

Logs have no agreed field for this, so extraction is deliberately broad but
not indiscriminate:

* **Any full URL**, wherever it appears in a tool call's arguments:
  ``https://api.openai.com/v1/chat`` gives ``api.openai.com``. Schemes read:
  ``http``, ``https``, ``ws``, ``wss``, ``ftp``, ``ftps``.
* **A bare host**, but only as the value of a field that names one —
  ``url``, ``uri``, ``endpoint``, ``host``, ``domain``, ``base_url``,
  ``server``, ``origin``, ``proxy`` and their plurals (see
  :data:`NETWORK_KEYS`). ``{"host": "db.internal"}`` gives ``db.internal``.

A bare domain-looking word *anywhere* is not a destination. That distinction
is what keeps the feature usable: a session that reads a file mentioning
``example.com``, or greps for ``alibaba.com``, has contacted nobody, and
reporting it as egress would bury the real finding. For the same reason a tool
*result* is scanned only when that call's own arguments carried a URL — a
search result listing thirty hosts is content the agent read, not hosts it
called (see :func:`extract_call_domains`).

Hosts are stored as written, lowercased, without credentials, port or trailing
dot. Nothing is resolved: an IP literal in a URL is kept as the destination it
is, and a hostname is never turned into an address. A pattern is matched
against the name the agent used, which is the thing the operator decided
about.

Limits
------

Logs are untrusted input, so a walk is bounded: :data:`MAX_SCAN_DEPTH` levels,
:data:`MAX_SCAN_STRINGS` strings, :data:`MAX_STRING_CHARS` characters of any
one string and :data:`MAX_DOMAINS` hosts per call. A deeply nested or enormous
argument costs a bounded amount of work and is then left alone.
"""
from __future__ import annotations

import re

#: Fields whose value is a destination even without a scheme.
NETWORK_KEYS = frozenset({
    "url", "urls", "uri", "uris", "endpoint", "endpoints", "host", "hosts", "hostname", "hostnames",
    "domain", "domains", "base_url", "baseurl", "base_uri", "server", "servers", "origin",
    "api_base", "api_url", "api_host", "proxy", "proxy_url", "webhook", "webhook_url", "address",
})

MAX_SCAN_DEPTH = 8            # nesting levels walked into one argument object
MAX_SCAN_STRINGS = 2000       # strings examined per call
MAX_STRING_CHARS = 64 * 1024  # characters examined of any one string
MAX_DOMAINS = 200             # hosts kept per call

_URL = re.compile(r"(?:https?|wss?|ftps?)://(?P<host>[^\s/?#\\\"'<>()\[\]{},;]+)", re.IGNORECASE)
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOST = re.compile(r"""
    ^(?=.{1,253}$)                      # a hostname is at most 253 characters
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+   # one or more labels, each ending in alphanumeric
    [a-z]{2,63}$                        # a letters-only public suffix
""", re.IGNORECASE | re.VERBOSE)


def normalise_host(raw: str | None) -> str | None:
    """A URL's authority as a bare host: no credentials, no port, lowercase.

    ``"User:pw@API.OpenAI.com:443."`` becomes ``"api.openai.com"``. An IPv6
    literal keeps its brackets (``"[::1]"``), since that is what distinguishes
    it from a port. Returns None when nothing usable is left.
    """
    if not isinstance(raw, str):
        return None
    host = raw.strip().strip("\"'").split("@")[-1]           # drop any userinfo
    if host.startswith("["):                                  # IPv6 literal: [::1]:8080
        end = host.find("]")
        host = host[:end + 1] if end != -1 else host
    else:
        host = host.split(":")[0]                             # drop the port
    host = host.rstrip(".").lower()
    return host or None


def domains_in_text(text: str) -> set[str]:
    """Hosts of every full URL in ``text`` (no bare hostnames)."""
    if not isinstance(text, str):
        return set()
    found = set()
    for m in _URL.finditer(text[:MAX_STRING_CHARS]):
        host = normalise_host(m.group("host"))
        if host:
            found.add(host)
    return found


#: Final labels that make a dotted word a filename rather than a host. A
#: network-named field is unlikely to hold one, but "notes.md" and "data.csv"
#: are valid hostnames by shape, and reporting them as egress would be noise.
NOT_HOSTS = frozenset({
    "md", "txt", "json", "jsonl", "csv", "tsv", "yml", "yaml", "toml", "ini", "cfg", "conf", "env",
    "log", "lock", "xml", "html", "htm", "css", "js", "jsx", "ts", "tsx", "py", "pyc", "rb", "go",
    "rs", "java", "sh", "bat", "ps1", "sql", "db", "sqlite", "png", "jpg", "jpeg", "gif", "svg",
    "pdf", "zip", "tar", "gz", "whl", "exe", "dll", "so", "bak", "tmp", "cert", "pem", "key",
})


def host_in_value(value: str) -> str | None:
    """``value`` as a bare host, when it looks like one. For network-named fields only.

    An address literal counts: ``{"host": "1.2.3.4"}`` is as much a
    destination as a name, and a URL's authority already keeps one. Nothing is
    resolved in either direction — a name is never turned into an address.
    """
    host = normalise_host(value)
    if not host:
        return None
    if _IPV4.match(host) or host.startswith("["):
        return host
    return host if _HOST.match(host) and host.rsplit(".", 1)[-1] not in NOT_HOSTS else None


def extract_domains(payload, network_key: bool = False) -> set[str]:
    """Every destination in ``payload`` (a tool call's arguments, say).

    Walks dicts, lists and strings within the module's limits. ``network_key``
    treats the payload itself as the value of a field that names a host, so
    ``extract_domains("db.internal", network_key=True)`` finds it while
    ``extract_domains("db.internal")`` does not.
    """
    found: set[str] = set()
    _walk(payload, network_key, found, [0], 0)
    return found


def _walk(value, network_key: bool, found: set[str], budget: list[int], depth: int) -> None:
    if len(found) >= MAX_DOMAINS or budget[0] >= MAX_SCAN_STRINGS or depth > MAX_SCAN_DEPTH:
        return
    if isinstance(value, str):
        budget[0] += 1
        hosts = domains_in_text(value)
        if network_key:
            bare = host_in_value(value)
            if bare:
                hosts.add(bare)
        for host in sorted(hosts):
            if len(found) >= MAX_DOMAINS:        # one string can hold hundreds of URLs
                return
            found.add(host)
        return
    if isinstance(value, dict):
        for key, inner in value.items():
            # A nested object under a network-named key is not itself a host,
            # but its own keys may be ("endpoint": {"host": ...}).
            named = isinstance(key, str) and key.strip().lower() in NETWORK_KEYS
            _walk(inner, named, found, budget, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for inner in value:
            _walk(inner, network_key, found, budget, depth + 1)   # ["urls": [...]] keeps the key's meaning


def extract_call_domains(arguments, result=None) -> set[str]:
    """Destinations of one tool call: its arguments, and its result if it was a network call.

    The result is scanned only when the arguments already carried a
    destination. A tool whose arguments point nowhere did not make a network
    call, so hosts in what it returned are content it read — a file, a search
    result — and not places it went. That keeps `Read` of a document full of
    URLs from reading as egress.
    """
    found = extract_domains(arguments)
    if found and result is not None:
        found |= extract_domains(result)
    return found if len(found) <= MAX_DOMAINS else set(sorted(found)[:MAX_DOMAINS])


# --------------------------------------------------------------------- patterns
def normalise_pattern(raw: str) -> str:
    """An operator's ``--domain`` argument as a stored pattern.

    Accepts a host (``api.openai.com``), a wildcard (``*.cn``), a leading dot
    (``.cn``, same thing) or a whole URL, whose host is taken. Raises
    ``ValueError`` naming what was expected — a pattern the operator cannot
    spell is worse than one they are told how to spell.
    """
    text = (raw or "").strip().strip("\"'")
    if not text:
        raise ValueError("domain is empty")
    if text in ("*", "*.", ".", "**"):
        raise ValueError(
            f"{raw!r} would match every host; there is no need for it — a domain that is not in the "
            "baseline already fires as new_domain. Reject a specific suffix instead, e.g. \"*.cn\"")
    inner = _URL.search(text)
    if inner:
        host = normalise_host(inner.group("host"))
        if not host:
            raise ValueError(f"{raw!r} has no host in it")
        return host
    wildcard = text.startswith(("*.", "."))
    body = text.removeprefix("*.").removeprefix(".") if wildcard else text
    host = normalise_host(body)
    if not host:
        raise ValueError(f"{raw!r} is not a domain or pattern; expected e.g. api.openai.com or \"*.cn\"")
    if "*" in host:
        raise ValueError(f"{raw!r}: a wildcard is only supported as a leading \"*.\", e.g. \"*.alibaba.com\"")
    return f"*.{host}" if wildcard else host


def domain_matches(domain: str, pattern: str) -> bool:
    """Does ``domain`` match ``pattern``?

    ``api.openai.com`` matches only itself. ``*.cn`` matches any host ending in
    ``.cn`` — ``api.unknown.cn`` yes, ``cn`` no — and ``*.alibaba.com`` matches
    ``x.alibaba.com`` but **not** ``alibaba.com``: a wildcard covers
    subdomains, and the bare domain is a destination of its own that deserves
    its own decision.
    """
    host = normalise_host(domain)
    if not host:
        return False
    pattern = (pattern or "").strip().lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])        # "*.cn" -> endswith ".cn"
    return host == pattern


def matching_pattern(domain: str, patterns) -> str | None:
    """The pattern in ``patterns`` that ``domain`` matches, most specific first, or None.

    Most specific first so a message can name the decision that is doing the
    work: with both ``api.unknown.cn`` and ``*.cn`` on record, the exact host
    is the one reported.
    """
    hits = [p for p in patterns if domain_matches(domain, p)]
    return max(hits, key=lambda p: (not p.startswith("*."), len(p))) if hits else None
