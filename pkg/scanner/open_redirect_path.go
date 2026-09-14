package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// OpenRedirectPathScanner detects open redirects that take a path segment instead of
// a query parameter — common in /redirect/{url} / /go/{slug} style routes.
type OpenRedirectPathScanner struct{}

func NewOpenRedirectPathScanner() *OpenRedirectPathScanner { return &OpenRedirectPathScanner{} }

func (s *OpenRedirectPathScanner) Name() string { return "Open Redirect (Path)" }

var redirectMarkers = []string{
	"//evil.example",
	"/\\\\evil.example",
	"/evil.example",
	"//google.com@evil.example",
	"/%2f%2fevil.example",
}

func (s *OpenRedirectPathScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	cli := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 8 * time.Second,
	}
	_ = client // we need to inspect Location header, so use a non-following client.

	candidates := []string{"/redirect", "/r", "/go", "/url", "/forward", "/login/oauth/return"}
	target = strings.TrimRight(target, "/")
	var findings []Finding
	for _, base := range candidates {
		for _, m := range redirectMarkers {
			full := target + base + m
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
			resp, err := cli.Do(req)
			if err != nil {
				continue
			}
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(loc, "evil.example") {
				findings = append(findings, Finding{
					URL: full, Title: "Open Redirect via Path Segment",
					Description: "Server issued a 3xx redirect to attacker-controlled host. Useful in phishing chains and OAuth account takeover.",
					Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
					Payload: m, Evidence: "Location: " + loc,
					Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 6.1,
				})
			}
		}
	}
	return findings, nil
}
