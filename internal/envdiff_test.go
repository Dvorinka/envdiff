package internal_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dvorinka/envdiff/internal"
	"github.com/Dvorinka/envdiff/internal/probes"
)

func td(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"../testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnvFiles(t *testing.T) {
	res := probes.EnvFiles(td(t, "envfiles"))
	if res == nil {
		t.Fatal("nil result")
	}
	if strings.Join(res.MissingInExample, ",") != "RESEND_API_KEY" {
		t.Errorf("missing_in_example = %v", res.MissingInExample)
	}
	if strings.Join(res.OrphanInExample, ",") != "OLD_KEY" {
		t.Errorf("orphan_in_example = %v", res.OrphanInExample)
	}
}

func TestCompose(t *testing.T) {
	res := probes.Compose(td(t, "compose"))
	if res == nil {
		t.Fatal("nil result")
	}
	api := res.Services["api"]
	if api.Image != "ghcr.io/dvorinka/invico-api:latest" {
		t.Errorf("api image = %q", api.Image)
	}
	want := map[string]bool{"DATABASE_URL": true, "JWT_SECRET": true}
	for _, k := range api.EnvKeys {
		delete(want, k)
	}
	if len(want) != 0 {
		t.Errorf("missing env keys: %v (got %v)", want, api.EnvKeys)
	}
	worker := res.Services["worker"]
	if strings.Join(worker.EnvKeys, ",") != "REDIS_HOST" {
		t.Errorf("worker env_keys = %v, want [REDIS_HOST]", worker.EnvKeys)
	}
}

func TestCISecrets(t *testing.T) {
	got := probes.CISecrets(td(t, "workflows"))
	joined := strings.Join(got, ",")
	for _, want := range []string{"DATABASE_URL", "RESEND_WEBHOOK_SECRET", "VPS_SSH_KEY", "GITHUB_TOKEN"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ci_secrets missing %s (got %v)", want, got)
		}
	}
}

func TestDiffSnapshots(t *testing.T) {
	a, err := internal.ReadSnapshot(td(t, "snapshot_a.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := internal.ReadSnapshot(td(t, "snapshot_b.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := internal.Diff(a, b)
	got := map[string]internal.Finding{}
	for _, f := range res.Findings {
		got[f.Category+"|"+f.Key] = f
	}

	checks := []struct{ cat, key, sev string }{
		{"env_key", "DATABASE_URL", "critical"},
		{"env_key", "JWT_SECRET", "ok"},
		{"version", "go", "critical"},
		{"version", "node", "ok"},
		{"dns", "app.invico.org A", "ok"},
		{"tls", "app.invico.org", "critical"}, // 12 days < 14
	}
	for _, c := range checks {
		f, ok := got[c.cat+"|"+c.key]
		if !ok {
			t.Errorf("missing finding %s %q", c.cat, c.key)
			continue
		}
		if f.Severity != c.sev {
			t.Errorf("%s %q: severity %q, want %q (detail: %s)", c.cat, c.key, f.Severity, c.sev, f.Detail)
		}
	}
	if res.Summary.Critical != 3 {
		t.Errorf("critical = %d, want 3", res.Summary.Critical)
	}
	if internal.ExitCode(res) != 2 {
		t.Errorf("exit = %d, want 2", internal.ExitCode(res))
	}
}

func TestSnapshotNoPlaintext(t *testing.T) {
	// envfile probe must never carry values — only key names.
	res := probes.EnvFiles(td(t, "envfiles"))
	for _, k := range append(res.Keys, res.ExampleKeys...) {
		if strings.Contains(k, "=") {
			t.Errorf("value leaked into key: %q", k)
		}
	}
	// fixture value must not appear anywhere in the key list
	if strings.Contains(strings.Join(res.Keys, ","), "dev-secret") {
		t.Error("plaintext secret leaked into snapshot")
	}
}

func TestBaselineMerge(t *testing.T) {
	// snapshot_b has drift vs snapshot_a — baseline check should surface it
	a, err := internal.ReadSnapshot(td(t, "snapshot_a.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := internal.ReadSnapshot(td(t, "snapshot_b.json"))
	if err != nil {
		t.Fatal(err)
	}
	bl := internal.Diff(a, b)
	res := internal.MergeBaseline(internal.DiffResult{}, bl)
	if res.Summary.Critical == 0 {
		t.Fatal("baseline drift should produce critical findings")
	}
	for _, f := range res.Findings {
		if f.Severity == "ok" {
			t.Fatalf("ok findings shouldn't survive baseline merge: %+v", f)
		}
	}
	// identical snapshots → nothing to report
	same := internal.Diff(a, a)
	res = internal.MergeBaseline(internal.DiffResult{}, same)
	if res.Summary.Total != 0 {
		t.Fatalf("identical baseline should be quiet, got %d", res.Summary.Total)
	}
}
