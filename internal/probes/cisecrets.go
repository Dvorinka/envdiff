package probes

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var secretRef = regexp.MustCompile(`secrets\.([A-Z_][A-Z0-9_]*)`)

// CISecrets extracts secrets.* names referenced by GitHub workflow files
// under dir/.github/workflows. Names only — values never exist here.
func CISecrets(dir string) []string {
	wfDir := filepath.Join(dir, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".yml" && filepath.Ext(name) != ".yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(wfDir, name))
		if err != nil {
			continue
		}
		for _, m := range secretRef.FindAllSubmatch(b, -1) {
			set[string(m[1])] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
