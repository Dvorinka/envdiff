package internal

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Dvorinka/envdiff/internal/probes"
)

// Finding is one drift result between two snapshots or vs expectations.
type Finding struct {
	Severity    string `json:"severity"` // critical | warning | ok
	Category    string `json:"category"`
	Key         string `json:"key"`
	A           string `json:"a"`
	B           string `json:"b"`
	Detail      string `json:"detail"`
	Expectation string `json:"expectation,omitempty"`
	Observed    string `json:"observed,omitempty"`
}

// DiffResult is the JSON contract for `envdiff diff` and `check`.
type DiffResult struct {
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

// Summary counts findings by severity.
type Summary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	OK       int `json:"ok"`
	Total    int `json:"total"`
}

func summarize(fs []Finding) Summary {
	var s Summary
	for _, f := range fs {
		switch f.Severity {
		case "critical":
			s.Critical++
		case "warning":
			s.Warning++
		default:
			s.OK++
		}
	}
	s.Total = len(fs)
	return s
}

// SortFindings orders critical, warning, ok; category then key within.
func SortFindings(fs []Finding) {
	ord := map[string]int{"critical": 0, "warning": 1, "ok": 2}
	sort.SliceStable(fs, func(i, j int) bool {
		if ord[fs[i].Severity] != ord[fs[j].Severity] {
			return ord[fs[i].Severity] < ord[fs[j].Severity]
		}
		if fs[i].Category != fs[j].Category {
			return fs[i].Category < fs[j].Category
		}
		return fs[i].Key < fs[j].Key
	})
}

func diff(sev, cat, key, a, b, detail string) Finding {
	return Finding{Severity: sev, Category: cat, Key: key, A: a, B: b, Detail: detail}
}

func keySet(list []probes.EnvKeyHash) map[string]string {
	m := map[string]string{}
	for _, e := range list {
		m[e.Key] = e.Hash
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Diff compares two snapshots into a ranked finding list.
// a is the "reference" side, b the compared side.
func Diff(a, b Snapshot) DiffResult {
	var fs []Finding

	// env keys: presence + hash comparison only — never values
	ka, kb := keySet(a.EnvKeys), keySet(b.EnvKeys)
	for _, k := range sortedKeys(union(ka, kb)) {
		ha, inA := ka[k]
		hb, inB := kb[k]
		keyA, keyB := "present", "present"
		if !inA {
			keyA = "missing"
		}
		if !inB {
			keyB = "missing"
		}
		switch {
		case inA && inB && ha != hb:
			fs = append(fs, diff("warning", "env_key", k, ha, hb, "value hash mismatch — different values"))
		case !inA || !inB:
			fs = append(fs, diff("critical", "env_key", k, keyA, keyB,
				fmt.Sprintf("env key %s in %s, %s in %s", keyA, a.Target, keyB, b.Target)))
		default:
			fs = append(fs, diff("ok", "env_key", k, "same", "same", "hash match"))
		}
	}

	// versions
	for _, tool := range sortedKeys(unionStr(a.Versions, b.Versions)) {
		va, vb := a.Versions[tool], b.Versions[tool]
		if va == vb {
			fs = append(fs, diff("ok", "version", tool, va, vb, "match"))
		} else {
			fs = append(fs, diff("critical", "version", tool, orDash(va), orDash(vb),
				fmt.Sprintf("%s %s vs %s %s", a.Target, orDash(va), b.Target, orDash(vb))))
		}
	}

	// dns
	fs = append(fs, diffDNS(a, b)...)
	// tls
	fs = append(fs, diffTLS(a, b)...)
	// ports
	fs = append(fs, diffPorts(a, b)...)
	// http
	fs = append(fs, diffHTTP(a, b)...)
	// docker images by repo:tag
	fs = append(fs, diffDocker(a, b)...)
	// listeners
	fs = append(fs, diffListeners(a, b)...)
	// env_file key sets
	fs = append(fs, diffEnvFile(a, b)...)
	// disk pressure
	fs = append(fs, diffDisk(a, b)...)

	SortFindings(fs)
	return DiffResult{Findings: fs, Summary: summarize(fs)}
}

func union(a, b map[string]string) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

func unionStr(a, b map[string]string) map[string]bool { return union(a, b) }

func orDash(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

func diffDNS(a, b Snapshot) []Finding {
	var fs []Finding
	type rk struct{ rec, typ string }
	am := map[rk]probes.DNSResult{}
	for _, d := range a.DNS {
		am[rk{d.Record, d.Type}] = d
	}
	for _, db := range b.DNS {
		da, ok := am[rk{db.Record, db.Type}]
		if !ok {
			continue
		}
		key := db.Record + " " + db.Type
		av, bv := strings.Join(da.Values, ","), strings.Join(db.Values, ",")
		switch {
		case da.Error != "" && db.Error != "":
			// both failed — nothing to compare
		case equalStringSets(da.Values, db.Values) && !da.Divergent && !db.Divergent:
			fs = append(fs, diff("ok", "dns", key, av, bv, "match"))
		case !equalStringSets(da.Values, db.Values):
			fs = append(fs, diff("critical", "dns", key, av, bv, "record values differ"))
		default:
			fs = append(fs, diff("warning", "dns", key, av, bv, "resolver divergence"))
		}
	}
	return fs
}

func diffTLS(a, b Snapshot) []Finding {
	var fs []Finding
	am := map[string]probes.TLSResult{}
	for _, t := range a.TLS {
		am[t.Host] = t
	}
	for _, tb := range b.TLS {
		ta, ok := am[tb.Host]
		if !ok {
			ta = probes.TLSResult{Host: tb.Host}
		}
		key := tb.Host
		if tb.Error != "" && ta.Error != "" {
			continue
		}
		if (ta.Error != "") != (tb.Error != "") {
			fs = append(fs, diff("critical", "tls", key, orErr(ta), orErr(tb), "TLS handshake state differs"))
			continue
		}
		if tb.Error != "" {
			continue
		}
		// both OK — compare expiry
		worst := tb.ExpiryDays
		if ta.ExpiryDays < worst {
			worst = ta.ExpiryDays
		}
		switch {
		case worst < 14:
			fs = append(fs, diff("critical", "tls", key,
				fmt.Sprintf("%d", ta.ExpiryDays), fmt.Sprintf("%d", tb.ExpiryDays),
				fmt.Sprintf("cert expires in %d days", worst)))
		case worst < 30:
			fs = append(fs, diff("warning", "tls", key,
				fmt.Sprintf("%d", ta.ExpiryDays), fmt.Sprintf("%d", tb.ExpiryDays),
				fmt.Sprintf("cert expires in %d days", worst)))
		case ta.ExpiryDays != tb.ExpiryDays:
			fs = append(fs, diff("ok", "tls", key,
				fmt.Sprintf("%d", ta.ExpiryDays), fmt.Sprintf("%d", tb.ExpiryDays), "valid"))
		default:
			fs = append(fs, diff("ok", "tls", key, "valid", "valid", "valid"))
		}
	}
	return fs
}

func orErr(t probes.TLSResult) string {
	if t.Error != "" {
		return "error: " + t.Error
	}
	return "valid"
}

func diffPorts(a, b Snapshot) []Finding {
	var fs []Finding
	type pk struct {
		host string
		port int
	}
	am := map[pk]probes.PortResult{}
	for _, p := range a.Ports {
		am[pk{p.Host, p.Port}] = p
	}
	for _, pb := range b.Ports {
		pa, ok := am[pk{pb.Host, pb.Port}]
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d", pb.Host, pb.Port)
		if pa.State == pb.State {
			fs = append(fs, diff("ok", "port", key, pa.State, pb.State, "match"))
		} else {
			fs = append(fs, diff("warning", "port", key, pa.State, pb.State,
				fmt.Sprintf("%s on %s, %s on %s", pa.State, a.Target, pb.State, b.Target)))
		}
	}
	return fs
}

func diffHTTP(a, b Snapshot) []Finding {
	var fs []Finding
	am := map[string]probes.HTTPResult{}
	for _, h := range a.HTTP {
		am[h.URL] = h
	}
	for _, hb := range b.HTTP {
		ha, ok := am[hb.URL]
		if !ok {
			continue
		}
		if ha.Status == hb.Status {
			fs = append(fs, diff("ok", "http", hb.URL, fmt.Sprint(ha.Status), fmt.Sprint(hb.Status), "match"))
		} else {
			fs = append(fs, diff("warning", "http", hb.URL, fmt.Sprint(ha.Status), fmt.Sprint(hb.Status), "status differs"))
		}
	}
	return fs
}

func diffDocker(a, b Snapshot) []Finding {
	var fs []Finding
	if a.Docker == nil || b.Docker == nil {
		return fs
	}
	am := map[string]string{}
	for _, im := range a.Docker.Images {
		am[im.Repo+":"+im.Tag] = im.Digest
	}
	for _, ib := range b.Docker.Images {
		da, ok := am[ib.Repo+":"+ib.Tag]
		key := ib.Repo + ":" + ib.Tag
		if !ok {
			fs = append(fs, diff("warning", "docker_image", key, "(absent)", ib.Digest,
				"image present in "+b.Target+" only"))
			continue
		}
		if da == ib.Digest {
			fs = append(fs, diff("ok", "docker_image", key, ib.Digest, ib.Digest, "digest match"))
		} else {
			fs = append(fs, diff("warning", "docker_image", key, da, ib.Digest, "digest mismatch"))
		}
	}
	return fs
}

func diffListeners(a, b Snapshot) []Finding {
	var fs []Finding
	am := map[int]bool{}
	for _, l := range a.Listeners {
		am[l.Port] = true
	}
	bm := map[int]bool{}
	for _, l := range b.Listeners {
		bm[l.Port] = true
	}
	ports := map[int]bool{}
	for p := range am {
		ports[p] = true
	}
	for p := range bm {
		ports[p] = true
	}
	var sorted []int
	for p := range ports {
		sorted = append(sorted, p)
	}
	sort.Ints(sorted)
	for _, p := range sorted {
		key := fmt.Sprintf("port %d", p)
		inA, inB := am[p], bm[p]
		switch {
		case inA && inB:
			fs = append(fs, diff("ok", "listener", key, "listening", "listening", "match"))
		case inA:
			fs = append(fs, diff("warning", "listener", key, "listening", "absent", "not listening on "+b.Target))
		default:
			fs = append(fs, diff("warning", "listener", key, "absent", "listening", "not listening on "+a.Target))
		}
	}
	return fs
}

func diffEnvFile(a, b Snapshot) []Finding {
	var fs []Finding
	if a.EnvFile == nil || b.EnvFile == nil {
		return fs
	}
	for _, k := range a.EnvFile.MissingInExample {
		fs = append(fs, diff("critical", "env_file", k, "in .env", "not in .env.example",
			fmt.Sprintf("%s: %s missing from .env.example", a.Target, k)))
	}
	for _, k := range b.EnvFile.MissingInExample {
		fs = append(fs, diff("critical", "env_file", k, "in .env", "not in .env.example",
			fmt.Sprintf("%s: %s missing from .env.example", b.Target, k)))
	}
	for _, k := range a.EnvFile.OrphanInExample {
		fs = append(fs, diff("warning", "env_file", k, "in .env.example", "not in .env",
			fmt.Sprintf("%s: %s orphaned in .env.example", a.Target, k)))
	}
	return fs
}

func diffDisk(a, b Snapshot) []Finding {
	var fs []Finding
	am := map[string]probes.Disk{}
	for _, d := range a.Disk {
		am[d.Mount] = d
	}
	for _, db := range b.Disk {
		da, ok := am[db.Mount]
		if !ok {
			continue
		}
		worst := db.UsedPct
		if da.UsedPct > worst {
			worst = da.UsedPct
		}
		if worst >= 90 {
			fs = append(fs, diff("critical", "disk", db.Mount,
				fmt.Sprintf("%d%%", da.UsedPct), fmt.Sprintf("%d%%", db.UsedPct),
				fmt.Sprintf("disk %d%% full", worst)))
		} else if worst >= 80 {
			fs = append(fs, diff("warning", "disk", db.Mount,
				fmt.Sprintf("%d%%", da.UsedPct), fmt.Sprintf("%d%%", db.UsedPct),
				fmt.Sprintf("disk %d%% full", worst)))
		}
	}
	return fs
}

// MergeBaseline folds baseline-diff findings into a check result.
// Findings where the baseline and target agree (severity "ok") are
// dropped — a matching environment is not news.
func MergeBaseline(res DiffResult, bl DiffResult) DiffResult {
	for _, f := range bl.Findings {
		if f.Severity == "ok" {
			continue
		}
		f.Expectation = f.A
		f.Observed = f.B
		res.Findings = append(res.Findings, f)
	}
	SortFindings(res.Findings)
	res.Summary = summarize(res.Findings)
	return res
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa, sb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
