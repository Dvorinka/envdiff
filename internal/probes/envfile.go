package probes

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// EnvFileResult compares .env against .env.example key sets.
// Values are never read.
type EnvFileResult struct {
	Keys             []string `json:"keys"`
	ExampleKeys      []string `json:"example_keys"`
	MissingInExample []string `json:"missing_in_example"`
	OrphanInExample  []string `json:"orphan_in_example"`
}

var envLine = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// envKeys parses a dotenv file and returns key names only.
func envKeys(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := envLine.FindStringSubmatch(line); m != nil {
			keys = append(keys, m[1])
		}
	}
	sort.Strings(keys)
	return keys
}

// EnvFiles compares dir/.env against dir/.env.example.
// Returns nil when neither file exists.
func EnvFiles(dir string) *EnvFileResult {
	env := envKeys(filepath.Join(dir, ".env"))
	example := envKeys(filepath.Join(dir, ".env.example"))
	if env == nil && example == nil {
		return nil
	}
	res := &EnvFileResult{Keys: env, ExampleKeys: example}
	inExample := map[string]bool{}
	for _, k := range example {
		inExample[k] = true
	}
	inEnv := map[string]bool{}
	for _, k := range env {
		inEnv[k] = true
	}
	for _, k := range env {
		if !inExample[k] {
			res.MissingInExample = append(res.MissingInExample, k)
		}
	}
	for _, k := range example {
		if !inEnv[k] {
			res.OrphanInExample = append(res.OrphanInExample, k)
		}
	}
	return res
}
