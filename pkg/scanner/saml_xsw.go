package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SAMLEndpointScanner detects SAML ACS / SLO endpoints and looks for
// loose XML processing that would enable XSW (XML Signature Wrapping) attacks.
type SAMLEndpointScanner struct{}

func NewSAMLEndpointScanner() *SAMLEndpointScanner { return &SAMLEndpointScanner{} }

func (s *SAMLEndpointScanner) Name() string { return "SAML XSW Surface" }

var samlPaths = []string{
	"/saml/acs", "/saml2/acs", "/saml/login", "/sso/saml",
	"/Shibboleth.sso/SAML2/POST", "/auth/saml/callback",
}

func (s *SAMLEndpointScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	var findings []Finding
	for _, p := range samlPaths {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+p, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 &&
			(strings.Contains(strings.ToLower(string(body)), "saml") || resp.Header.Get("Location") != "") {
			findings = append(findings, Finding{
				URL: target + p, Title: "SAML ACS Endpoint Reachable",
				Description: "SAML endpoint accessible; review for XML Signature Wrapping (XSW), unsigned assertion acceptance, replay window, and audience restriction. Test with samlraider or python-saml regression suite.",
				Severity: SeverityMedium, Confidence: ConfidenceLow, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 5.3,
			})
		}
	}
	return findings, nil
}
