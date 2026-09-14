package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// WellKnownScanner enumerates RFC 8615 .well-known endpoints (security.txt, change-password,
// appspecific, openid-configuration, oauth-authorization-server) and warns on the missing-but-expected ones.
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
	for _, w := range wellKnowns {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+w.path, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		present := resp.StatusCode == 200
		if !present && w.expect {
			findings = append(findings, Finding{
				URL: target + w.path, Title: "Missing " + w.path,
				Description: "Recommended .well-known endpoint not served (" + w.purpose + "). Consider publishing.",
				Severity: SeverityInfo, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "informational",
			})
		}
		if present {
			findings = append(findings, Finding{
				URL: target + w.path, Title: "Discovered " + w.path,
				Description: w.purpose + " is published.",
				Severity: SeverityInfo, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "informational",
			})
		}
	}
	return findings, nil
}
