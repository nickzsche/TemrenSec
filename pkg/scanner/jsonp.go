package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// JSONPCallbackScanner probes for endpoints that wrap their JSON response in an
// attacker-supplied callback name — the classic JSONP CSRF/data-exfil bug.
type JSONPCallbackScanner struct{}

func NewJSONPCallbackScanner() *JSONPCallbackScanner { return &JSONPCallbackScanner{} }

func (s *JSONPCallbackScanner) Name() string { return "JSONP Callback Abuse" }

func (s *JSONPCallbackScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	canary := "TemrenJsonpCallback"
	candidates := []string{"callback", "cb", "jsonp", "json_callback", "_callback"}
	target = strings.TrimRight(target, "?&")
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	var findings []Finding
	for _, p := range candidates {
		full := target + sep + p + "=" + canary
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if strings.HasPrefix(strings.TrimSpace(string(body)), canary+"(") {
			findings = append(findings, Finding{
				URL: full, Title: "JSONP Endpoint with Attacker-Controlled Callback",
				Description: "Server wrapped its JSON in a callback name we supplied. If the endpoint returns authenticated data, any third-party site can read it cross-origin.",
				Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Parameter: p, Payload: canary, Timestamp: time.Now(),
				OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5,
			})
			return findings, nil
		}
	}
	return findings, nil
}
