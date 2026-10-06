package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON encodes v as indented JSON.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Report writes the ranked human-readable diff report.
func Report(w io.Writer, titleA, titleB string, r DiffResult) {
	fmt.Fprintf(w, "Environment diff: %s vs %s\n\n", titleA, titleB)
	sections := []struct {
		name, sev string
	}{
		{"CRITICAL", "critical"},
		{"WARNING", "warning"},
		{"OK", "ok"},
	}
	for _, sec := range sections {
		var group []Finding
		for _, f := range r.Findings {
			if f.Severity == sec.sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\n", sec.name)
		for _, f := range group {
			fmt.Fprintf(w, "  %-28s %s\n", pad(f.Key), f.Detail)
		}
		fmt.Fprintln(w)
	}
}

// CheckReport renders check findings (expectation vs observed).
func CheckReport(w io.Writer, target string, r DiffResult) {
	fmt.Fprintf(w, "envdiff check — %s\n\n", target)
	for _, sec := range []struct{ name, sev string }{
		{"CRITICAL", "critical"}, {"WARNING", "warning"}, {"OK", "ok"},
	} {
		var group []Finding
		for _, f := range r.Findings {
			if f.Severity == sec.sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\n", sec.name)
		for _, f := range group {
			fmt.Fprintf(w, "  %-28s expect: %s | got: %s\n", pad(f.Key), f.Expectation, f.Observed)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%d critical, %d warning, %d ok\n",
		r.Summary.Critical, r.Summary.Warning, r.Summary.OK)
}

func pad(s string) string {
	if len(s) > 28 {
		return s[:25] + "..."
	}
	return s + strings.Repeat(" ", 28-len(s))
}

// ExitCode maps a DiffResult to the envdiff contract:
// 0 pass, 1 warnings only, 2 critical.
func ExitCode(r DiffResult) int {
	if r.Summary.Critical > 0 {
		return 2
	}
	if r.Summary.Warning > 0 {
		return 1
	}
	return 0
}
