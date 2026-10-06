package probes

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"
)

// ComposeService is one service's image + env key names (values ignored).
type ComposeService struct {
	Image   string   `json:"image"`
	EnvKeys []string `json:"env_keys"`
	Ports   []string `json:"ports,omitempty"`
}

// ComposeResult is the extracted view of a docker-compose file.
type ComposeResult struct {
	Services map[string]ComposeService `json:"services"`
}

type composeFile struct {
	Services map[string]struct {
		Image       string `yaml:"image"`
		Environment any    `yaml:"environment"`
		Ports       []any  `yaml:"ports"`
	} `yaml:"services"`
}

func envKeySet(env any) []string {
	set := map[string]bool{}
	switch e := env.(type) {
	case []any: // list form: - KEY=value
		for _, item := range e {
			if s, ok := item.(string); ok {
				if k := keyPart(s); k != "" {
					set[k] = true
				}
			}
		}
	case map[string]any: // map form: KEY: value
		for k := range e {
			set[k] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keyPart(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i]
		}
	}
	return s // bare KEY with no value still declares the key
}

// Compose parses docker-compose.yml / compose.yml in dir.
// Returns nil when no compose file exists.
func Compose(dir string) *ComposeResult {
	var path string
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cf composeFile
	if yaml.Unmarshal(b, &cf) != nil {
		return nil
	}
	res := &ComposeResult{Services: map[string]ComposeService{}}
	for name, svc := range cf.Services {
		var ports []string
		for _, p := range svc.Ports {
			switch v := p.(type) {
			case string:
				ports = append(ports, v)
			case int:
				ports = append(ports, strconv.Itoa(v))
			case float64:
				ports = append(ports, strconv.Itoa(int(v)))
			case map[string]any:
				if pub, ok := v["published"]; ok {
					if s, ok := pub.(string); ok {
						ports = append(ports, s)
					}
				}
			}
		}
		res.Services[name] = ComposeService{
			Image:   svc.Image,
			EnvKeys: envKeySet(svc.Environment),
			Ports:   ports,
		}
	}
	return res
}
