package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// GraphQLCSRFScanner detects GraphQL servers that accept form-encoded POSTs (no preflight),
// enabling cross-site request forgery against mutations.
type GraphQLCSRFScanner struct{}

func NewGraphQLCSRFScanner() *GraphQLCSRFScanner { return &GraphQLCSRFScanner{} }

func (s *GraphQLCSRFScanner) Name() string { return "GraphQL CSRF (no preflight)" }

func (s *GraphQLCSRFScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	form := url.Values{}
	form.Set("query", "{ __typename }")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode == 200 && strings.Contains(string(body), "__typename") {
		return []Finding{{
			URL: target, Title: "GraphQL CSRF — Form-Encoded POST Accepted",
			Description: "Server accepted GraphQL operations sent as application/x-www-form-urlencoded. Browsers send these without CORS preflight, so any authenticated mutation is exploitable via CSRF.",
			Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: "A01:2021-Broken Access Control", CVSSScore: 7.5,
		}}, nil
	}
	return nil, nil
}
