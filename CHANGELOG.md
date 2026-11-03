# Changelog

All notable changes to agent-certify are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.7.0] - 2026-11-03

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
