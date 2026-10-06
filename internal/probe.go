package internal

import (
	"fmt"
	"strconv"

	"github.com/Dvorinka/envdiff/internal/probes"
)

// ProbeResult is the JSON contract for `envdiff probe`.
type ProbeResult struct {
	Probe  string         `json:"probe"`
	Args   map[string]any `json:"args"`
	Result any            `json:"result"`
}

// Probe dispatches an ad-hoc single probe:
//
//	envdiff probe dns MX example.com
//	envdiff probe tls example.com [port]
//	envdiff probe port example.com 443
//	envdiff probe http https://example.com/health [substring]
func Probe(args []string) (ProbeResult, error) {
	if len(args) < 1 {
		return ProbeResult{}, fmt.Errorf("usage: envdiff probe <dns|tls|port|http> ...")
	}
	p := ProbeResult{Probe: args[0], Args: map[string]any{}}
	switch args[0] {
	case "dns":
		if len(args) < 3 {
			return p, fmt.Errorf("usage: envdiff probe dns <TYPE> <record>")
		}
		p.Args["type"], p.Args["record"] = args[1], args[2]
		p.Result = probes.DNS(args[2], args[1])
	case "tls":
		if len(args) < 2 {
			return p, fmt.Errorf("usage: envdiff probe tls <host> [port]")
		}
		port := 443
		if len(args) >= 3 {
			port, _ = strconv.Atoi(args[2])
		}
		p.Args["host"], p.Args["port"] = args[1], port
		p.Result = probes.TLS(args[1], port)
	case "port":
		if len(args) < 3 {
			return p, fmt.Errorf("usage: envdiff probe port <host> <port>")
		}
		port, err := strconv.Atoi(args[2])
		if err != nil {
			return p, fmt.Errorf("invalid port %q", args[2])
		}
		p.Args["host"], p.Args["port"] = args[1], port
		p.Result = probes.Port(args[1], port)
	case "http":
		if len(args) < 2 {
			return p, fmt.Errorf("usage: envdiff probe http <url> [substring]")
		}
		want := ""
		if len(args) >= 3 {
			want = args[2]
		}
		p.Args["url"], p.Args["expect_body_contains"] = args[1], want
		p.Result = probes.HTTP(args[1], want, true)
	default:
		return p, fmt.Errorf("unknown probe %q — use dns, tls, port, http", args[0])
	}
	return p, nil
}
