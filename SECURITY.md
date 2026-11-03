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
descriptions, call and error counts, project folder names, session ids and
**network destinations** — the host names a session's tool calls pointed at
(see §6).

Prompt text is never extracted. Tool inputs and tool outputs are **read but
not returned**: they are walked for host names only, and nothing else of them
leaves the parser — not the argument text, not the result text, not URL
credentials, ports or paths. If that metadata is sensitive in your setting, do
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

**What is kept.** Only host names, lowercased, with URL credentials, port, path
and query discarded, and nothing resolved: a name is never turned into an
address. No argument text, result text, prompt or file content is kept at any
point. The hosts live on the graph (`seen_domains`) and on the calling node, so
a report can say which tool reached which host.

**What is stored on disk.** `agent-certify learn` writes every host it saw into
`known_domains` in `.agent-certify/baseline.json`, alongside the `*.cn`-style
patterns an operator accepted or rejected. That file is a plain list of host
names the sessions contacted; treat it like the rest of §5 and review it before
publishing it. Certificates do **not** carry destinations: `graph_hash()` covers
node roles, kinds and links only, which is also why certificates issued before
v0.7.0 still verify.

**What is transmitted.** When a session reaches a host the baseline never saw,
or one matching a rejected pattern, the host name appears in the anomaly's
`message`, `value` and `detail` fields. Those fields are returned verbatim to
the MCP client by the `check_anomalies` tool. They also appear in text,
Markdown, JSON and HTML reports, and in the `message` attribute of an
`anomaly.*` OTel span event — which, if you export spans, leaves the machine.
A host name is therefore the one piece of tool-call *content* that can travel
out of this tool.

**Review rule.** Any feature that reads a new category of input data — a new
field, a new part of a record, anything beyond the structural metadata listed
in §1 — requires a review and an update of this document in the same change.
Network destinations shipped in v0.7.0 without one, and this section is the
correction.

## Supported versions

Security fixes go into the latest minor version.
