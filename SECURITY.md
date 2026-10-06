# Security

## Reporting

Report vulnerabilities privately via GitHub Security Advisories
(“Report a vulnerability” on the repo's Security tab), or email
info@tdvorak.dev. Do not open a public issue for undisclosed
vulnerabilities.

## Threat model

envdiff is built around a hard rule: **secret values never leave the host
that has them, and never enter snapshots, diffs, logs, or output.** Values
are SHA-256-hashed in place (truncated to 16 hex chars); comparisons are
hash-equality only.

- Tier 0 probes make outbound network calls (DNS, TLS, TCP, HTTP) — TLS
  verification is never skipped.
- Tier 1 pipes a generated, read-only POSIX shell script through
  `ssh host sh -s`. The script contains no writes, no installs, no
  privilege escalation. Review it: it's generated from a fixed template.
- Tier 2 parses local `.env`, compose, and workflow files — key names and
  hashes only.

If any flag or code path causes a plaintext secret value to appear in
output, that's a critical reportable bug.
