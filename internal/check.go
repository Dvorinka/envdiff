package internal

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/Dvorinka/envdiff/internal/probes"
)

// Check evaluates a .envdiff.yml manifest against a snapshot.
// Tier coverage depends on what the target could probe.
func Check(root string, m Manifest, s Snapshot) DiffResult {
	var fs []Finding

	for _, e := range m.DNS {
		res := probes.DNS(e.Record, e.Type)
		key := e.Record + " " + e.Type
		exp := e.Expect
		switch {
		case res.Error != "":
			fs = append(fs, Finding{Severity: "critical", Category: "dns", Key: key,
				Expectation: exp, Observed: "error: " + res.Error,
				Detail: "DNS lookup failed"})
		case contains(res.Values, exp):
			fs = append(fs, Finding{Severity: "ok", Category: "dns", Key: key,
				Expectation: exp, Observed: strings.Join(res.Values, ", "), Detail: "match"})
		case len(res.Values) == 0:
			fs = append(fs, Finding{Severity: "critical", Category: "dns", Key: key,
				Expectation: exp, Observed: "(no " + e.Type + " record)",
				Detail: fmt.Sprintf("%s record not found — expected %s", e.Type, exp)})
		default:
			fs = append(fs, Finding{Severity: "critical", Category: "dns", Key: key,
				Expectation: exp, Observed: strings.Join(res.Values, ", "),
				Detail: "value mismatch"})
		}
	}

	for _, e := range m.TLS {
		res := probes.TLS(e.Host, 443)
		min := e.MinExpiryDays
		if min == 0 {
			min = 30
		}
		switch {
		case res.Error != "":
			fs = append(fs, Finding{Severity: "critical", Category: "tls", Key: e.Host,
				Expectation: "valid cert", Observed: "error: " + res.Error,
				Detail: "TLS handshake failed"})
		case res.ExpiryDays < min:
			fs = append(fs, Finding{Severity: "critical", Category: "tls", Key: e.Host,
				Expectation: fmt.Sprintf(">= %d days", min),
				Observed:    fmt.Sprintf("%d days", res.ExpiryDays),
				Detail:      fmt.Sprintf("cert expires in %d days — threshold %d", res.ExpiryDays, min)})
		case e.ExpectSAN != "" && !contains(res.SANs, e.ExpectSAN):
			fs = append(fs, Finding{Severity: "critical", Category: "tls", Key: e.Host,
				Expectation: "SAN " + e.ExpectSAN, Observed: strings.Join(res.SANs, ", "),
				Detail: "expected SAN missing"})
		default:
			fs = append(fs, Finding{Severity: "ok", Category: "tls", Key: e.Host,
				Expectation: fmt.Sprintf(">= %d days", min),
				Observed:    fmt.Sprintf("%d days", res.ExpiryDays), Detail: "valid"})
		}
	}

	for _, e := range m.Ports {
		res := probes.Port(e.Host, e.Port)
		key := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if res.State == e.Expect {
			fs = append(fs, Finding{Severity: "ok", Category: "port", Key: key,
				Expectation: e.Expect, Observed: res.State, Detail: "match"})
		} else {
			fs = append(fs, Finding{Severity: "critical", Category: "port", Key: key,
				Expectation: e.Expect, Observed: res.State,
				Detail: fmt.Sprintf("expected %s, got %s", e.Expect, res.State)})
		}
	}

	for _, e := range m.HTTP {
		res := probes.HTTP(e.URL, e.ExpectBodyContains, true)
		want := e.ExpectStatus
		if want == 0 {
			want = 200
		}
		bad := res.Error != "" || res.Status != want ||
			(e.ExpectBodyContains != "" && (res.BodyContains == nil || !*res.BodyContains))
		for h, hv := range e.ExpectHeader {
			if !strings.EqualFold(res.Headers[strings.ToLower(h)], hv) {
				bad = true
			}
		}
		if bad {
			obs := fmt.Sprintf("status %d", res.Status)
			if res.Error != "" {
				obs = "error: " + res.Error
			}
			fs = append(fs, Finding{Severity: "critical", Category: "http", Key: e.URL,
				Expectation: fmt.Sprintf("status %d", want), Observed: obs,
				Detail: "HTTP expectation failed"})
		} else {
			fs = append(fs, Finding{Severity: "ok", Category: "http", Key: e.URL,
				Expectation: fmt.Sprintf("status %d", want),
				Observed:    fmt.Sprintf("status %d", res.Status), Detail: "match"})
		}
	}

	// env_keys presence: .env/.env.example/ci_secrets for local targets,
	// hashed remote env keys for ssh targets.
	if len(m.EnvKeys) > 0 {
		present := map[string]bool{}
		source := ""
		if len(s.EnvKeys) > 0 {
			for _, k := range s.EnvKeys {
				present[k.Key] = true
			}
			source = "remote env"
		} else {
			if s.EnvFile != nil {
				for _, k := range s.EnvFile.Keys {
					present[k] = true
				}
				for _, k := range s.EnvFile.ExampleKeys {
					present[k] = true
				}
			}
			for _, k := range s.CISecrets {
				present[k] = true
			}
			source = ".env/.env.example/CI secrets"
		}
		for _, k := range m.EnvKeys {
			if present[k] {
				fs = append(fs, Finding{Severity: "ok", Category: "env_key", Key: k,
					Expectation: "present", Observed: "present", Detail: "declared in " + source})
			} else {
				fs = append(fs, Finding{Severity: "critical", Category: "env_key", Key: k,
					Expectation: "present", Observed: "missing",
					Detail: "not found in " + source})
			}
		}
	}

	for _, e := range m.Docker {
		if e.Digest == "" {
			// pullability check — docker manifest inspect
			err := exec.Command("docker", "manifest", "inspect", e.Image).Run()
			if err != nil {
				fs = append(fs, Finding{Severity: "warning", Category: "docker", Key: e.Image,
					Expectation: "pullable", Observed: "not inspectable",
					Detail: "docker manifest inspect failed (auth? network? image missing?)"})
			} else {
				fs = append(fs, Finding{Severity: "ok", Category: "docker", Key: e.Image,
					Expectation: "pullable", Observed: "pullable", Detail: "manifest found"})
			}
			continue
		}
		// digest expectation vs snapshot images
		want := e.Digest
		found := ""
		if s.Docker != nil {
			for _, im := range s.Docker.Images {
				ref := im.Repo + ":" + im.Tag
				if ref == e.Image || im.Repo == e.Image {
					found = im.Digest
				}
			}
		}
		switch {
		case found == "":
			fs = append(fs, Finding{Severity: "critical", Category: "docker", Key: e.Image,
				Expectation: want, Observed: "(not in snapshot)",
				Detail: "image not found in target"})
		case found == want:
			fs = append(fs, Finding{Severity: "ok", Category: "docker", Key: e.Image,
				Expectation: want, Observed: found, Detail: "digest match"})
		default:
			fs = append(fs, Finding{Severity: "critical", Category: "docker", Key: e.Image,
				Expectation: want, Observed: found, Detail: "digest mismatch"})
		}
	}

	// versions: prefix match against local tools or snapshot versions
	for _, pair := range sortedMap(m.Versions) {
		tool, want := pair.k, pair.v
		got := s.Versions[tool]
		if got == "" {
			got = localVersion(tool)
		}
		if got == "" {
			fs = append(fs, Finding{Severity: "warning", Category: "version", Key: tool,
				Expectation: want, Observed: "(not installed)",
				Detail: "tool not found on target"})
			continue
		}
		if strings.HasPrefix(got, want) {
			fs = append(fs, Finding{Severity: "ok", Category: "version", Key: tool,
				Expectation: want, Observed: got, Detail: "match"})
		} else {
			fs = append(fs, Finding{Severity: "critical", Category: "version", Key: tool,
				Expectation: want, Observed: got, Detail: "version mismatch"})
		}
	}

	SortFindings(fs)
	return DiffResult{Findings: fs, Summary: summarize(fs)}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

type kv struct{ k, v string }

func sortedMap(m map[string]string) []kv {
	var out []kv
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].k < out[j].k })
	return out
}

var localVersionCmd = map[string][]string{
	"go":     {"go", "version"},
	"node":   {"node", "--version"},
	"python": {"python3", "--version"},
	"docker": {"docker", "--version"},
	"git":    {"git", "--version"},
}

func localVersion(tool string) string {
	args, ok := localVersionCmd[tool]
	if !ok {
		return ""
	}
	out, err := exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(out))
	fields := strings.Fields(s)
	last := fields[len(fields)-1]
	last = strings.TrimPrefix(last, "v")
	last = strings.TrimPrefix(last, "go")
	return strings.TrimSuffix(last, ",")
}
