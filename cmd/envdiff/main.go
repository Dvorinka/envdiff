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
	"strings"

	"github.com/Dvorinka/envdiff/internal"
)

// version is stamped at release: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `envdiff — environment discrepancy detector

Usage:
  envdiff scan  [--target <spec>] [--out <file>] [--root <dir>]
  envdiff diff  <a.json> <b.json> [--json]
  envdiff check [--target <spec>] [--config <file>] [--baseline <snapshot.json>] [--root <dir>] [--json]
  envdiff probe <dns|tls|port|http> <args...> [--json]
  envdiff version
  envdiff completion <bash|zsh|fish>

Targets: local (default), net://host, ssh://[user@]host, file://snapshot.json
Exit codes: 0 clean, 1 warnings, 2 critical, 5 error.
`

// flagTakesValue reports whether a flag name expects a value argument.
func flagTakesValue(name string) bool {
	switch strings.TrimLeft(name, "-") {
	case "target", "out", "root", "config", "baseline":
		return true
	}
	return false
}

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
	if cmd == "version" || cmd == "--version" || cmd == "-version" {
		fmt.Println("envdiff", version)
		return
	}
	if cmd == "completion" && len(os.Args) >= 3 {
		s, err := internal.Completion(os.Args[2])
		if err != nil {
			fail(err)
		}
		fmt.Print(s)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	target := fs.String("target", "local", "scan/check target spec")
	out := fs.String("out", "", "output file for scan (default stdout)")
	root := fs.String("root", ".", "repo root for Tier-2 probes")
	config := fs.String("config", "", "path to .envdiff.yml")
	baseline := fs.String("baseline", "", "known-good snapshot to diff the target against (check)")
	// flags may come after positional args (diff a.json b.json --json)
	argv := append([]string{}, os.Args[2:]...)
	var flags, pos []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(argv) && flagTakesValue(a) {
				i++
				flags = append(flags, argv[i])
			}
		} else {
			pos = append(pos, a)
		}
	}
	if err := fs.Parse(append(flags, pos...)); err != nil {
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
		if *baseline != "" {
			base, err := internal.ReadSnapshot(*baseline)
			if err != nil {
				fail(fmt.Errorf("invalid baseline snapshot: %w", err))
			}
			res = internal.MergeBaseline(res, internal.Diff(base, s))
		}
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
