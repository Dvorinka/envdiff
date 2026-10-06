<h1 align="center">envdiff</h1>

<p align="center">
  Environment discrepancy detector.<br>
  Prove the environments differ — or don't.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#probe-catalog">Probes</a> ·
  <a href="#the-envdiffyml-manifest">Configuration</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/Dvorinka/envdiff/actions/workflows/ci.yml"><img src="https://github.com/Dvorinka/envdiff/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Dvorinka/envdiff/releases"><img src="https://img.shields.io/github/v/release/Dvorinka/envdiff" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Dvorinka/envdiff" alt="License"></a>
</p>

## What is envdiff?

envdiff is a single-binary Go CLI that answers the question every
"works on my machine" incident is really asking: *what is actually
different between the two environments?* It probes environments at three
honesty tiers, produces comparable JSON snapshots, diffs them into a
severity-ranked report, and turns the result into a CI-runnable
environment lint.

It exists because every project accumulates an env contract nobody
verifies: `.env` drifts from `.env.example`, the deploy host's DNS moved,
the cert expires in 12 days, prod runs Go 1.23 while CI tests 1.24.
`diff .env .env.example` shows values and structure, not presence;
`dig`/`curl`/`openssl` one-off checks aren't comparable. envdiff makes
them comparable.

The sleeper feature: `envdiff check` expectations like
`dns.mx: in.example.org → inbound-smtp.eu-west-1.amazonaws.com` catch
MX-on-apex-class bugs in one CI run instead of three rounds of manual
`dig` across resolvers.

## Honesty tiers

| Tier | Spec | Access needed | What it proves |
|---|---|---|---|
| 0 | `net://host` | none — just network | DNS, TLS, ports, HTTP endpoints |
| 1 | `ssh://host` | ssh | remote env keys (hashed), runtime versions, docker, listeners, disk |
| 2 | `local` / files | none | `.env`, `.env.example`, compose, CI secret references |

Tier 2 runs in CI with zero credentials. Tier 1 executes a read-only
generated shell script piped through `ssh host sh -s` — nothing is
installed or written on the remote host.

## Features

- **Never leaks secrets** — env values are SHA-256-hashed on the host
  that has them (truncated to 16 hex chars) *before* anything leaves.
  Snapshots contain `{key, hash}` pairs, never plaintext.
- **DNS multi-resolver** — queries system, `1.1.1.1`, and `8.8.8.8`;
  divergent answers flag split-DNS and propagation issues.
- **Verified TLS** — real `crypto/tls` handshake, never
  `InsecureSkipVerify`. Reports validity, issuer, SANs, expiry days.
- **Port classification** — `open`, `closed`, `filtered`, `error`.
- **Snapshot + diff** — `scan` writes portable JSON; `diff` compares any
  two snapshots, including saved ones, severity-ranked.
- **`check` as environment lint** — `.envdiff.yml` declares expectations;
  CI and post-deploy hooks verify them.
- **Agent-ready** — every command emits stable snake_case JSON.

## Quick Start

```bash
go install github.com/Dvorinka/envdiff/cmd/envdiff@latest
```

Or from source (Go 1.23+):

```bash
git clone https://github.com/Dvorinka/envdiff.git && cd envdiff
go build -o envdiff ./cmd/envdiff
```

```bash
envdiff scan --target local --out local.json
envdiff scan --target net://app.example.com --out prod.json
envdiff diff local.json prod.json
envdiff check                       # verify .envdiff.yml expectations
envdiff probe tls app.example.com   # single ad-hoc probe
```

## Commands

### `envdiff scan --target <spec> [--out file]`

Produces a snapshot JSON. Always machine-readable.

- `--target local` — Tier 2 local scan (`.env`, compose, workflows,
  local versions, docker, listeners, disk).
- `--target net://host` — Tier 0 network probes.
- `--target ssh://host` — Tier 1 remote shell probes.
- `--target file://path/snapshot.json` — load a prior snapshot.

Individual probe errors land in the snapshot as `error` entries — they
don't abort the scan.

### `envdiff diff <a.json> <b.json> [--json]`

Compares two snapshots into a severity-ranked report. Works on saved
snapshots — no live access needed.

### `envdiff check [--target <spec>] [--baseline <snapshot.json>] [--json]`

The CI gate. Reads `.envdiff.yml`, probes the target, evaluates every
expectation.

`--baseline known-good.json` additionally diffs the target against a
saved snapshot: anything that changed relative to a captured good state
fires as a finding (`expectation` = baseline value, `observed` = live
value). No manifest required — "match prod's known-good state" is a
complete contract by itself.

Exit codes: `0` all pass · `1` warnings · `2` critical drift ·
`5` operational/config error (ssh failure, malformed manifest, malformed
snapshot or baseline).

### `envdiff probe <dns|tls|port|http> <args...> [--json]`

Ad-hoc single probe:

```bash
envdiff probe dns MX in.example.com
envdiff probe tls app.example.com 443
envdiff probe port app.example.com 443
envdiff probe http https://app.example.com/health '"ok"'
```

`envdiff version` prints the binary version.

## Probe catalog

**Tier 0 — network:**

| Probe | Checks | Implementation |
|---|---|---|
| `dns` | A, AAAA, MX, TXT, CNAME, NS + cross-resolver divergence | `net.Resolver` with per-server dialers |
| `tls` | chain validity, expiry days, SANs | `tls.Dial`, `InsecureSkipVerify=false` |
| `port` | TCP open/closed/filtered | `net.DialTimeout`, 5s |
| `http` | status, headers, body substring | `net/http`, 10s timeout |

**Tier 1 — remote shell (ssh):** `env_keys` (hashed), `versions` (go,
node, python, docker, compose), `docker_ps`, `docker_images`,
`listeners`, `disk`. One generated POSIX script via `ssh host sh -s`;
first lines are `# envdiff probe — read-only, no writes, no installs`
and `set -euo pipefail`.

**Tier 2 — local files:** `.env` vs `.env.example` (presence + hash),
`docker-compose*.yml` service env, `.github/workflows/*` secret
references.

## The `.envdiff.yml` manifest

All sections optional — `check` runs only what is declared:

```yaml
dns:
  - record: app.example.com
    type: A
    expect: 57.131.194.151
  - record: in.example.com
    type: MX
    expect: "10 inbound-smtp.eu-west-1.amazonaws.com"

tls:
  - host: app.example.com
    min_expiry_days: 30
    expect_san: app.example.com

ports:
  - host: app.example.com
    port: 443
    expect: open            # open | closed | filtered

http:
  - url: https://app.example.com/api/health
    expect_status: 200
    expect_body_contains: '"ok":true'
    expect_header:
      content-type: application/json

env_keys:                   # presence-only — values never compared
  - DATABASE_URL
  - JWT_SECRET

docker:
  - image: ghcr.io/org/api          # exists/pullable
  - image: ghcr.io/org/web
    digest: sha256:a1b2c3d4...      # or exact digest

versions:                   # prefix match: "1.23" matches 1.23.4
  go: "1.23"
  node: "24"
  python: "3.12"
  docker: "27"
```

## Security posture

- Values never appear anywhere: snapshots, diffs, logs — hashes only.
- Hash computed on the owning host; remote values never transit the wire.
- TLS verification is never disabled.
- SSH probes are read-only, no writes, no installs.
- CI usage (Tier 0 + Tier 2) needs no credentials at all.

## Development

```bash
go build ./...
go test ./...      # fixtures under testdata/
go vet ./...
gofmt -l .
```

Stdlib first; the only dependency is `gopkg.in/yaml.v3`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
