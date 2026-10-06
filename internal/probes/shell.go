package probes

import (
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// EnvKeyHash is an env var name plus a truncated SHA-256 of its value.
// The raw value never leaves the host it was hashed on.
type EnvKeyHash struct {
	Key  string `json:"key"`
	Hash string `json:"hash"`
}

// DockerPS is one running container.
type DockerPS struct {
	Image  string `json:"image"`
	Status string `json:"status"`
}

// DockerImage is one local image with its digest.
type DockerImage struct {
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

// Listener is a TCP listening socket.
type Listener struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Process  string `json:"process,omitempty"`
}

// Disk is free space on one mount.
type Disk struct {
	Mount   string  `json:"mount"`
	FreeGB  float64 `json:"free_gb"`
	UsedPct int     `json:"used_pct"`
}

// RemoteFacts is everything a Tier-1 shell probe returns.
type RemoteFacts struct {
	EnvKeys      []EnvKeyHash      `json:"env_keys,omitempty"`
	Versions     map[string]string `json:"versions,omitempty"`
	DockerPS     []DockerPS        `json:"-"`
	DockerImages []DockerImage     `json:"-"`
	Listeners    []Listener        `json:"listeners,omitempty"`
	Disk         []Disk            `json:"disk,omitempty"`
}

// probeScript is POSIX sh, read-only. set -u only: pipefail is a bashism
// and -e would abort on the first missing tool — partial results are data.
const probeScript = `#!/bin/sh
# envdiff probe - read-only, no writes, no installs
set -u

hash() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | cut -c1-16
	else
		openssl dgst -sha256 | awk '{print $NF}' | cut -c1-16
	fi
}

# env_keys: hash values on the host, never transmit plaintext
env | cut -d= -f1 | sort | while IFS= read -r k; do
	case "$k" in ''|*[!A-Za-z0-9_]*) continue;; esac
	v=$(printenv "$k" 2>/dev/null || true)
	if [ -n "$v" ]; then
		printf 'env_key=%s=%s\n' "$k" "$(printf '%s' "$v" | hash)"
	fi
done

printf 'version=go=%s\n' "$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
printf 'version=node=%s\n' "$(node --version 2>/dev/null | sed 's/^v//')"
printf 'version=python=%s\n' "$(python3 --version 2>/dev/null | awk '{print $2}')"
printf 'version=docker=%s\n' "$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')"
printf 'version=git=%s\n' "$(git --version 2>/dev/null | awk '{print $3}')"

docker ps --format '{{.Image}}|{{.Status}}' 2>/dev/null | while IFS='|' read -r img status; do
	printf 'docker_ps=%s=%s\n' "$img" "$status"
done || true

docker images --digests --format '{{.Repository}}:{{.Tag}}|{{.Digest}}' 2>/dev/null | while IFS='|' read -r ref digest; do
	case "$ref" in *'<none>'*) continue;; esac
	printf 'docker_image=%s=%s\n' "$ref" "$digest"
done || true

if command -v ss >/dev/null 2>&1; then
	ss -tlnH 2>/dev/null | awk '{n=split($4,a,":"); printf "listener=%s=%s\n", a[n], "tcp"}'
elif command -v netstat >/dev/null 2>&1; then
	netstat -tln 2>/dev/null | awk 'NR>2 {n=split($4,a,":"); printf "listener=%s=%s\n", a[n], "tcp"}'
fi

df -Pk / /home /var /tmp 2>/dev/null | awk 'NR>1 || $6 != "Mounted" { if ($6 ~ /^\//) printf "disk=%s=%s,%s\n", $6, $4, $5 }' | sort -u
`

// parseFacts turns key=value probe output into RemoteFacts.
func parseFacts(out []byte) RemoteFacts {
	f := RemoteFacts{Versions: map[string]string{}}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		typ, rest, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val, ok := strings.Cut(rest, "=")
		if !ok {
			key = rest
			val = ""
		}
		switch typ {
		case "env_key":
			f.EnvKeys = append(f.EnvKeys, EnvKeyHash{Key: key, Hash: val})
		case "version":
			if val != "" {
				f.Versions[key] = val
			}
		case "docker_ps":
			f.DockerPS = append(f.DockerPS, DockerPS{Image: key, Status: val})
		case "docker_image":
			repo, tag, _ := strings.Cut(key, ":")
			f.DockerImages = append(f.DockerImages, DockerImage{Repo: repo, Tag: tag, Digest: val})
		case "listener":
			if p, err := strconv.Atoi(key); err == nil {
				f.Listeners = append(f.Listeners, Listener{Port: p, Protocol: val})
			}
		case "disk":
			kb, pct, _ := strings.Cut(val, ",")
			kbf, _ := strconv.ParseFloat(kb, 64)
			pcti, _ := strconv.Atoi(strings.TrimSuffix(pct, "%"))
			f.Disk = append(f.Disk, Disk{Mount: key, FreeGB: kbf / 1048576, UsedPct: pcti})
		}
	}
	sort.Slice(f.EnvKeys, func(i, j int) bool { return f.EnvKeys[i].Key < f.EnvKeys[j].Key })
	sort.Slice(f.Disk, func(i, j int) bool { return f.Disk[i].Mount < f.Disk[j].Mount })
	return f
}

// Shell runs the read-only probe script. If host is empty it runs locally
// via `sh -s`; otherwise it pipes through `ssh host sh -s`.
// BatchMode + ConnectTimeout keep it non-interactive for agents.
func Shell(host string) (RemoteFacts, error) {
	var cmd *exec.Cmd
	if host == "" {
		cmd = exec.Command("sh", "-s")
	} else {
		cmd = exec.Command("ssh",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=10",
			"-o", "StrictHostKeyChecking=accept-new",
			host, "sh", "-s")
	}
	cmd.Stdin = strings.NewReader(probeScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		where := "local"
		if host != "" {
			where = host
		}
		return RemoteFacts{}, fmt.Errorf("shell probe on %s failed: %v: %s", where, err, strings.TrimSpace(stderr.String()))
	}
	return parseFacts(stdout.Bytes()), nil
}
