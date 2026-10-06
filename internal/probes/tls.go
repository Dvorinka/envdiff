package probes

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// TLSResult describes the certificate chain presented by host:port.
// Verification is never skipped — the point of the probe is to verify.
type TLSResult struct {
	Host       string   `json:"host"`
	Valid      bool     `json:"valid"`
	ExpiryDays int      `json:"expiry_days"`
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	SANs       []string `json:"sans"`
	Error      string   `json:"error,omitempty"`
}

// TLS performs a verified TLS handshake and reports cert validity, expiry
// in days, subject, issuer, and SANs.
func TLS(host string, port int) TLSResult {
	res := TLSResult{Host: host, SANs: []string{}}
	addr := net.JoinHostPort(host, itoaOr(port, 443))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		res.Error = "no peer certificates"
		return res
	}
	cert := state.PeerCertificates[0]
	res.Valid = true
	res.ExpiryDays = int(time.Until(cert.NotAfter).Hours() / 24)
	res.Subject = cert.Subject.String()
	res.Issuer = cert.Issuer.String()
	res.SANs = cert.DNSNames
	if res.SANs == nil {
		res.SANs = []string{}
	}
	return res
}

func itoaOr(port, def int) string {
	if port == 0 {
		port = def
	}
	return fmt.Sprintf("%d", port)
}
