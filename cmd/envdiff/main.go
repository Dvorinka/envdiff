// envdiff — environment discrepancy detector.
// Answers "why does this work on my machine?" — DNS, TLS, ports, HTTP,
// hashed env keys, versions, docker, and repo files, in one snapshot.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Dvorinka/envdiff/internal"
)

const usage = `envdiff — environment discrepancy detector

Usage:
  envdiff scan  [--target <spec>] [--out <file>] [--root <dir>]
  envdiff diff  <a.json> <b.json> [--json]
  envdiff check [--target <spec>] [--config <file>] [--root <dir>] [--json]
  envdiff probe <dns|tls|port|http> <args...> [--json]

Targets: local (default), net://host, ssh://[user@]host, file://snapshot.json
Exit codes: 0 clean, 1 warnings, 2 critical, 5 error.
`

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(5)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(5)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	target := fs.String("target", "local", "scan/check target spec")
	out := fs.String("out", "", "output file for scan (default stdout)")
	root := fs.String("root", ".", "repo root for Tier-2 probes")
	config := fs.String("config", "", "path to .envdiff.yml")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(5)
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		fail(err)
	}

	switch cmd {
	case "scan":
		s, err := internal.Scan(abs, *target)
		if err != nil {
			fail(err)
		}
		if err := internal.WriteSnapshot(s, *out); err != nil {
			fail(err)
		}
	case "diff":
		if fs.NArg() < 2 {
			fmt.Fprintln(os.Stderr, "usage: envdiff diff <a.json> <b.json>")
			os.Exit(5)
		}
		a, err := internal.ReadSnapshot(fs.Arg(0))
		if err != nil {
			fail(err)
		}
		b, err := internal.ReadSnapshot(fs.Arg(1))
		if err != nil {
			fail(err)
		}
		res := internal.Diff(a, b)
		if *jsonOut {
			internal.WriteJSON(os.Stdout, res)
		} else {
			internal.Report(os.Stdout, a.Target, b.Target, res)
		}
		os.Exit(internal.ExitCode(res))
	case "check":
		m, err := internal.LoadManifest(abs, *config)
		if err != nil {
			fail(err)
		}
		var s internal.Snapshot
		if *target == "" || *target == "local" {
			s, err = internal.Scan(abs, "local")
		} else {
			s, err = internal.Scan(abs, *target)
		}
		if err != nil {
			fail(err)
		}
		res := internal.Check(abs, m, s)
		if *jsonOut {
			internal.WriteJSON(os.Stdout, res)
		} else {
			internal.CheckReport(os.Stdout, *target, res)
		}
		os.Exit(internal.ExitCode(res))
	case "probe":
		p, err := internal.Probe(fs.Args())
		if err != nil {
			fail(err)
		}
		if *jsonOut {
			internal.WriteJSON(os.Stdout, p)
		} else {
			b, _ := json.MarshalIndent(p.Result, "", "  ")
			fmt.Println(string(b))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(5)
	}
}
