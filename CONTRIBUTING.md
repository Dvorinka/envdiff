# Contributing

Contributions welcome. The bar is a green pre-push gate and a test for any
non-trivial logic.

## Workflow

1. Fork, branch from `main`.
2. Make the change. Keep it small — one concern per PR.
3. Run the gate:

   ```bash
   gofmt -l .
   go vet ./...
   go test ./...
   go build ./...
   ```

4. Open a PR describing *why*, not just *what*.

## Conventions

- Single Go module, standard library first. New dependencies need
  justification in the PR.
- Probes are pure functions returning typed results; probe errors go into
  the snapshot as `error` entries — they never abort a scan.
- **Never emit plaintext env values** — hashes only, computed on the
  owning host. Any PR that weakens this is rejected outright.
- TLS verification is never disabled.
- JSON output is a contract: stable snake_case keys.
- Fixtures live in `testdata/` — snapshot pairs, env files, compose files.

## Reporting bugs

Include the manifest or target spec used, `envdiff <cmd> --json` output,
and expected vs actual result.
