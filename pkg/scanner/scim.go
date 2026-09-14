package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SCIMEnumerationScanner checks for unauthenticated SCIM 2.0 user/group endpoints.
type SCIMEnumerationScanner struct{}

func NewSCIMEnumerationScanner() *SCIMEnumerationScanner { return &SCIMEnumerationScanner{} }

func (s *SCIMEnumerationScanner) Name() string { return "SCIM Endpoint Enumeration" }

func (s *SCIMEnumerationScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	var findings []Finding
	for _, p := range []string{"/scim/v2/Users", "/scim/v2/Groups", "/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+p, nil)
		req.Header.Set("Accept", "application/scim+json")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if resp.StatusCode == 200 && strings.Contains(strings.ToLower(string(body)), "schemas") {
			findings = append(findings, Finding{
				URL: target + p, Title: "Unauthenticated SCIM Endpoint",
				Description: "SCIM endpoint responded to an unauthenticated request. Attackers can enumerate users, groups, or even create accounts depending on the schema.",
				Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A01:2021-Broken Access Control", CVSSScore: 7.5,
			})
		}
	}
	return findings, nil
}
