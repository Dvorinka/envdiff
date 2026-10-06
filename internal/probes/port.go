package probes

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// PortResult is the TCP reachability state of host:port.
type PortResult struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	State string `json:"state"` // open | closed | filtered | error
	Error string `json:"error,omitempty"`
}

// Port dials host:port with a 5s timeout and classifies the outcome:
// open (connected), closed (refused), filtered (timeout), error (other).
func Port(host string, port int) PortResult {
	res := PortResult{Host: host, Port: port}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 5*time.Second)
	if err == nil {
		conn.Close()
		res.State = "open"
		return res
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		res.State = "filtered"
		return res
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		res.State = "closed"
	case strings.Contains(msg, "no such host"):
		res.State = "error"
		res.Error = "DNS resolution failed"
	default:
		res.State = "error"
		res.Error = msg
	}
	return res
}
