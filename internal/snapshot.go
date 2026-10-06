package internal

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Dvorinka/envdiff/internal/probes"
)

// DockerSection holds container and image state from a Tier-1 probe.
type DockerSection struct {
	Containers []probes.DockerPS    `json:"containers,omitempty"`
	Images     []probes.DockerImage `json:"images,omitempty"`
}

// Snapshot is the envdiff scan output contract. Missing probes are omitted —
// the absence of a key means that tier wasn't run.
type Snapshot struct {
	Target    string                `json:"target"`
	ScannedAt string                `json:"scanned_at"`
	Tier      string                `json:"tier"`
	DNS       []probes.DNSResult    `json:"dns,omitempty"`
	TLS       []probes.TLSResult    `json:"tls,omitempty"`
	Ports     []probes.PortResult   `json:"ports,omitempty"`
	HTTP      []probes.HTTPResult   `json:"http,omitempty"`
	EnvKeys   []probes.EnvKeyHash   `json:"env_keys,omitempty"`
	Versions  map[string]string     `json:"versions,omitempty"`
	Docker    *DockerSection        `json:"docker,omitempty"`
	Listeners []probes.Listener     `json:"listeners,omitempty"`
	Disk      []probes.Disk         `json:"disk,omitempty"`
	EnvFile   *probes.EnvFileResult `json:"env_file,omitempty"`
	Compose   *probes.ComposeResult `json:"compose,omitempty"`
	CISecrets []string              `json:"ci_secrets,omitempty"`
}

// WriteSnapshot serializes a snapshot to disk (or stdout when path is "-").
func WriteSnapshot(s Snapshot, path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ReadSnapshot loads a snapshot JSON file.
func ReadSnapshot(path string) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, fmt.Errorf("cannot read snapshot %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("invalid snapshot %s: %w", path, err)
	}
	return s, nil
}
