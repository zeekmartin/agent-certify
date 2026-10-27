# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in agent-certify,
please report it by emailing david.martin@cognitive-engineering.dev.

Do NOT open a public issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide
a fix timeline within 7 days.

## Scope

agent-certify processes local log files and does not
make network connections (except the MCP stdio server,
which communicates via stdin/stdout only). The primary
security concern is the certificate signing keys.
