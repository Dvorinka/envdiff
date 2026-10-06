package internal

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Dvorinka/envdiff/internal/probes"
)

// Scan produces a snapshot for a target spec:
//
//	local           Tier 2 files + Tier 1 local shell + Tier 0 localhost
//	net://host      Tier 0 only — DNS, TLS, ports, HTTP
//	ssh://[u@]host  Tier 0 remote + Tier 1 via ssh + Tier 2 from cwd
//	file://path     load a prior snapshot
func Scan(root, target string) (Snapshot, error) {
	s := Snapshot{
		Target:    target,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}
	switch {
	case target == "" || target == "local":
		s.Tier = "local"
		scanLocal(&s, root)
	case strings.HasPrefix(target, "net://"):
		host := strings.TrimPrefix(target, "net://")
		s.Tier = "net"
		scanNet(&s, host)
	case strings.HasPrefix(target, "ssh://"):
		host := strings.TrimPrefix(target, "ssh://")
		s.Tier = "ssh"
		scanNet(&s, stripUser(host))
		facts, err := probes.Shell(host)
		if err != nil {
			return s, err
		}
		applyFacts(&s, facts)
		scanLocalFiles(&s, root)
	case strings.HasPrefix(target, "file://"):
		path := strings.TrimPrefix(target, "file://")
		return ReadSnapshot(path)
	default:
		return s, fmt.Errorf("unknown target %q — use local, net://host, ssh://host, or file://path", target)
	}
	return s, nil
}

func stripUser(host string) string {
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// scanNet runs Tier-0 probes against a remote host: DNS, TLS, ports, HTTP.
func scanNet(s *Snapshot, host string) {
	for _, rt := range []string{"A", "AAAA", "MX"} {
		s.DNS = append(s.DNS, probes.DNS(host, rt))
	}
	s.TLS = append(s.TLS, probes.TLS(host, 443))
	for _, p := range []int{22, 80, 443} {
		s.Ports = append(s.Ports, probes.Port(host, p))
	}
	s.HTTP = append(s.HTTP, probes.HTTP("https://"+host+"/", "", true))
}

// scanLocal runs Tier 0 against localhost plus Tier 1 + Tier 2 locally.
func scanLocal(s *Snapshot, root string) {
	host, _ := os.Hostname()
	s.DNS = append(s.DNS, probes.DNS("localhost", "A"))
	if host != "" && host != "localhost" {
		s.DNS = append(s.DNS, probes.DNS(host, "A"))
	}
	facts, _ := probes.Shell("") // best-effort; missing tools are fine
	applyFacts(s, facts)
	scanLocalFiles(s, root)
}

// scanLocalFiles runs Tier-2 probes against the repo at root.
func scanLocalFiles(s *Snapshot, root string) {
	s.EnvFile = probes.EnvFiles(root)
	s.Compose = probes.Compose(root)
	s.CISecrets = probes.CISecrets(root)
	s.K8s = probes.K8sManifests(root)
}

func applyFacts(s *Snapshot, f probes.RemoteFacts) {
	s.EnvKeys = f.EnvKeys
	s.Versions = f.Versions
	s.Listeners = f.Listeners
	s.Disk = f.Disk
	if len(f.DockerPS) > 0 || len(f.DockerImages) > 0 {
		s.Docker = &DockerSection{Containers: f.DockerPS, Images: f.DockerImages}
	}
}
