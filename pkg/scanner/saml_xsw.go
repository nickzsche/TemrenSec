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
	// Strong SAML markers — real endpoints emit these, unlike a 404 page that
	// merely reflects the requested "/saml/..." path.
	markers := []string{"samlresponse", "samlrequest", "urn:oasis:names:tc:saml", "<samlp:", "assertionconsumerservice", "entitydescriptor"}
	for _, p := range samlPaths {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+p, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()

		lower := strings.ToLower(string(body))
		hasMarker := false
		for _, mk := range markers {
			if strings.Contains(lower, mk) {
				hasMarker = true
				break
			}
		}
		loc := resp.Header.Get("Location")
		samlRedirect := loc != "" && (strings.Contains(strings.ToLower(loc), "saml") || strings.Contains(strings.ToLower(loc), "sso"))

		// Genuinely reachable only if the server actually serves it (200 with a
		// real SAML marker) or redirects into an SSO flow. A 404/403 — even one
		// whose error page reflects the word "saml" from the URL — is not a hit.
		reachable := (resp.StatusCode == 200 && hasMarker) || (resp.StatusCode >= 300 && resp.StatusCode < 400 && samlRedirect)

		// Soft-404 guard: if a random sibling answers the same way, this path
		// isn't special.
		if reachable && resp.StatusCode == 200 {
			if cs, cbody := s.fetch(ctx, client, siblingSAML(target, p)); cs == 200 && similarLen(len(body), cbody) {
				reachable = false
			}
		}

		if reachable {
			findings = append(findings, Finding{
				URL: target + p, Title: "SAML ACS Endpoint Reachable",
				Description: "SAML endpoint accessible; review for XML Signature Wrapping (XSW), unsigned assertion acceptance, replay window, and audience restriction. Test with samlraider or python-saml regression suite.",
				Severity:    SeverityMedium, Confidence: ConfidenceLow, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 5.3,
			})
		}
	}
	return findings, nil
}

// fetch returns (status, bodyLen) for a GET, or (0,0) on error.
func (s *SAMLEndpointScanner) fetch(ctx context.Context, client *httpengine.Client, u string) (int, int) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return 0, 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	resp.Body.Close()
	return resp.StatusCode, len(body)
}

// siblingSAML builds a random sibling of the SAML path for soft-404 comparison.
func siblingSAML(target, p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return target + p + "-temren404zzq"
	}
	return target + p[:i] + "/temren404zzq"
}
