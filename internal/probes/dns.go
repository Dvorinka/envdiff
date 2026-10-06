// Package probes holds the envdiff probe implementations. Each probe is a
// pure function: target in, structured result out, no shared state.
package probes

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DNSResult is one DNS lookup's outcome across resolvers.
type DNSResult struct {
	Record    string   `json:"record"`
	Type      string   `json:"type"`
	Values    []string `json:"values"`
	Resolver  string   `json:"resolver"`
	Divergent bool     `json:"divergent"`
	Error     string   `json:"error,omitempty"`
}

func publicResolver(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

func lookupOnce(ctx context.Context, r *net.Resolver, record, rtype string) ([]string, error) {
	switch rtype {
	case "A", "AAAA":
		ips, err := r.LookupIP(ctx, strings.ToLower(rtype), record)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out, nil
	case "MX":
		mxs, err := r.LookupMX(ctx, record)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, m := range mxs {
			out = append(out, mxString(m))
		}
		return out, nil
	case "TXT":
		return r.LookupTXT(ctx, record)
	case "CNAME":
		c, err := r.LookupCNAME(ctx, record)
		if err != nil {
			return nil, err
		}
		return []string{c}, nil
	case "NS":
		nss, err := r.LookupNS(ctx, record)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, n := range nss {
			out = append(out, n.Host)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported DNS type %s", rtype)
}

func mxString(m *net.MX) string {
	return strconv.Itoa(int(m.Pref)) + " " + strings.TrimSuffix(m.Host, ".")
}

func sortedCopy(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

func equalSets(a, b []string) bool {
	a, b = sortedCopy(a), sortedCopy(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DNS queries a record against the system resolver plus public resolvers
// (1.1.1.1, 8.8.8.8) and reports divergence — split-horizon DNS and
// propagation lag show up as divergent: true.
func DNS(record, rtype string) DNSResult {
	res := DNSResult{Record: record, Type: rtype, Resolver: "system"}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	resolvers := []struct {
		name string
		r    *net.Resolver
	}{
		{"system", net.DefaultResolver},
		{"1.1.1.1", publicResolver("1.1.1.1")},
		{"8.8.8.8", publicResolver("8.8.8.8")},
	}
	var base []string
	baseSet := false
	var others [][]string
	for _, rs := range resolvers {
		vals, err := lookupOnce(ctx, rs.r, record, rtype)
		if err != nil {
			if rs.name == "system" {
				// retry once after 2s per spec, then mark error
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
				vals, err = lookupOnce(ctx, rs.r, record, rtype)
				if err != nil {
					res.Error = err.Error()
					continue
				}
			} else {
				continue
			}
		}
		if !baseSet {
			base = vals
			baseSet = true
			res.Resolver = rs.name
		} else {
			others = append(others, vals)
		}
	}
	res.Values = base
	for _, o := range others {
		if !equalSets(base, o) {
			res.Divergent = true
			break
		}
	}
	if res.Values == nil {
		res.Values = []string{}
	}
	return res
}
