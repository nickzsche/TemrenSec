package scanner

import (
	"context"
	"net/http"
	"net/url"
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
			// A real open redirect sends the browser OFF-ORIGIN to the attacker
			// host. Resolve Location against the request URL and require the
			// resulting host to actually be evil.example — otherwise a same-origin
			// normalization redirect (e.g. "//evil.example" collapsed to the
			// relative path "/redirect/evil.example") is a false positive even
			// though the string "evil.example" appears in it.
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && redirectsToHost(full, loc, "evil.example") {
				findings = append(findings, Finding{
					URL: full, Title: "Open Redirect via Path Segment",
					Description: "Server issued a 3xx redirect to attacker-controlled host. Useful in phishing chains and OAuth account takeover.",
					Severity:    SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
					Payload: m, Evidence: "Location: " + loc,
					Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 6.1,
				})
			}
		}
	}
	return findings, nil
}

// redirectsToHost resolves a Location header against the request URL and reports
// whether the browser would actually be sent to wantHost (off-origin). This
// distinguishes a genuine open redirect from a same-origin normalization
// redirect whose path merely contains the marker string.
func redirectsToHost(requestURL, location, wantHost string) bool {
	if location == "" {
		return false
	}
	base, err := url.Parse(requestURL)
	if err != nil {
		return false
	}
	loc, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	resolved := base.ResolveReference(loc)
	return strings.EqualFold(resolved.Hostname(), wantHost)
}
