package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// WellKnownScanner enumerates RFC 8615 .well-known endpoints and reports which
// are genuinely published versus recommended-but-missing.
type WellKnownScanner struct{}

func NewWellKnownScanner() *WellKnownScanner { return &WellKnownScanner{} }

func (s *WellKnownScanner) Name() string { return ".well-known Inventory" }

var wellKnowns = []struct {
	path    string
	expect  bool // true == should exist (warn if missing)
	purpose string
}{
	{"/.well-known/security.txt", true, "RFC 9116 security contact"},
	{"/.well-known/change-password", true, "RFC 8959 password-manager hint"},
	{"/.well-known/openid-configuration", false, "OIDC discovery"},
	{"/.well-known/oauth-authorization-server", false, "RFC 8414 OAuth metadata"},
	{"/.well-known/assetlinks.json", false, "Android applinks"},
	{"/.well-known/apple-app-site-association", false, "iOS universal links"},
	{"/.well-known/host-meta", false, "Webfinger"},
	{"/.well-known/matrix/server", false, "Matrix delegation"},
}

func (s *WellKnownScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	var findings []Finding

	// Catch-all control: a .well-known path that cannot exist. If the server
	// answers 200 with an HTML shell here, it serves one page for every path
	// (SPA fallback). In that case a 200 on a real .well-known path proves
	// nothing, so "present" must be judged by the body differing from this
	// control — otherwise every endpoint would be falsely "discovered".
	ctrlStatus, ctrlBody := s.fetch(ctx, client, target+"/.well-known/temren-nonexistent-4417")
	catchAll := ctrlStatus == 200

	for _, w := range wellKnowns {
		status, body := s.fetch(ctx, client, target+w.path)

		present := status == 200
		if present && catchAll {
			// Only real if it differs from the catch-all shell and isn't just
			// another HTML page (well-known resources are JSON/text).
			isHTMLShell := strings.Contains(strings.ToLower(string(body)), "<html")
			present = !similarLen(len(body), len(ctrlBody)) && !isHTMLShell
		}

		if !present && w.expect {
			findings = append(findings, Finding{
				URL: target + w.path, Title: "Missing " + w.path,
				Description: "Recommended .well-known endpoint not served (" + w.purpose + "). Consider publishing.",
				Severity:    SeverityInfo, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "informational",
			})
		}
		if present {
			findings = append(findings, Finding{
				URL: target + w.path, Title: "Discovered " + w.path,
				Description: w.purpose + " is published.",
				Severity:    SeverityInfo, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "informational",
			})
		}
	}
	return findings, nil
}

// fetch returns (status, body) for a GET, or (0, nil) on error.
func (s *WellKnownScanner) fetch(ctx context.Context, client *httpengine.Client, u string) (int, []byte) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()
	return resp.StatusCode, body
}
