package internal

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Manifest mirrors .envdiff.yml — declared environment expectations.
type Manifest struct {
	DNS []struct {
		Record string `yaml:"record"`
		Type   string `yaml:"type"`
		Expect string `yaml:"expect"`
	} `yaml:"dns"`
	TLS []struct {
		Host          string `yaml:"host"`
		MinExpiryDays int    `yaml:"min_expiry_days"`
		ExpectSAN     string `yaml:"expect_san"`
	} `yaml:"tls"`
	Ports []struct {
		Host   string `yaml:"host"`
		Port   int    `yaml:"port"`
		Expect string `yaml:"expect"`
	} `yaml:"ports"`
	HTTP []struct {
		URL                string            `yaml:"url"`
		ExpectStatus       int               `yaml:"expect_status"`
		ExpectBodyContains string            `yaml:"expect_body_contains"`
		ExpectHeader       map[string]string `yaml:"expect_header"`
	} `yaml:"http"`
	EnvKeys []string `yaml:"env_keys"`
	Docker  []struct {
		Image  string `yaml:"image"`
		Digest string `yaml:"digest"`
	} `yaml:"docker"`
	Versions map[string]string `yaml:"versions"`
}

// LoadManifest reads .envdiff.yml. Missing file returns an empty manifest
// unless explicitPath was given (then it's an error).
func LoadManifest(root, explicitPath string) (Manifest, error) {
	var m Manifest
	p := explicitPath
	if p == "" {
		p = filepath.Join(root, ".envdiff.yml")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) && explicitPath == "" {
			return m, nil
		}
		return m, fmt.Errorf("cannot read %s: %w", p, err)
	}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("malformed .envdiff.yml: %w", err)
	}
	return m, nil
}
