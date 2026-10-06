package probes

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPResult is the outcome of a single HTTP GET.
type HTTPResult struct {
	URL          string            `json:"url"`
	Status       int               `json:"status"`
	BodyContains *bool             `json:"body_contains,omitempty"`
	Headers      map[string]string `json:"headers"`
	Error        string            `json:"error,omitempty"`
}

var interestingHeaders = []string{
	"content-type", "server", "strict-transport-security", "location",
}

// HTTP fetches url with a 10s timeout. If want is non-empty, body_contains
// reports whether the (first 256KB of the) body contains it.
func HTTP(url, want string, follow bool) HTTPResult {
	res := HTTPResult{URL: url, Headers: map[string]string{}}
	client := &http.Client{Timeout: 10 * time.Second}
	if !follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "envdiff/1.0")
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	for _, h := range interestingHeaders {
		if v := resp.Header.Get(h); v != "" {
			res.Headers[h] = v
		}
	}
	if want != "" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		ok := strings.Contains(string(body), want)
		res.BodyContains = &ok
	}
	return res
}
