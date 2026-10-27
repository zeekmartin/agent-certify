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
- bounds each request to 30 seconds and every directory scan in depth (5
  levels), file count (1,000) and line size (10 MB).

What the server does return is structural metadata of sessions inside those
roots: tool names (including MCP server and tool names), sub-agent types and
descriptions, call and error counts, project folder names and session ids.
Prompts, tool inputs and tool outputs are never extracted. If that metadata is
sensitive in your setting, do not register the server, or start it from a
working directory that contains nothing else.

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

## Supported versions

Security fixes go into the latest minor version.
