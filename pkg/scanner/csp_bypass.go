package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// CSPBypassScanner analyses the Content-Security-Policy header for well-known
// bypass primitives: 'unsafe-inline', 'unsafe-eval', wildcards in script-src,
// or hosts that allow JSONP (googleapis, cloudflare CDN minified scripts).
type CSPBypassScanner struct{}

func NewCSPBypassScanner() *CSPBypassScanner { return &CSPBypassScanner{} }

func (s *CSPBypassScanner) Name() string { return "CSP Bypass Surface" }

var jsonpHosts = []string{
	"ajax.googleapis.com",
	"cdnjs.cloudflare.com",
	"www.gstatic.com",
}

func (s *CSPBypassScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	csp := resp.Header.Get("Content-Security-Policy")
	resp.Body.Close()
	if csp == "" {
		return nil, nil // already reported by SecurityHeaders scanner
	}
	low := strings.ToLower(csp)
	var notes []string
	if strings.Contains(low, "'unsafe-inline'") && strings.Contains(low, "script-src") {
		notes = append(notes, "script-src allows 'unsafe-inline'")
	}
	if strings.Contains(low, "'unsafe-eval'") {
		notes = append(notes, "policy allows 'unsafe-eval'")
	}
	if strings.Contains(low, "script-src *") || strings.Contains(low, "script-src http:") {
		notes = append(notes, "script-src wildcard / scheme-only host")
	}
	for _, h := range jsonpHosts {
		if strings.Contains(low, h) {
			notes = append(notes, "host with known JSONP endpoints in script-src: "+h)
			break
		}
	}
	if len(notes) == 0 {
		return nil, nil
	}
	return []Finding{{
		URL: target, Title: "CSP Has Bypass Surface",
		Description: "Content-Security-Policy contains directives that nullify XSS protection: " + strings.Join(notes, "; "),
		Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
		Evidence: csp, Timestamp: time.Now(),
		OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.4,
	}}, nil
}
