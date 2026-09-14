package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// GraphQLFieldSuggestionScanner pokes the GraphQL endpoint with intentionally typo'd
// field names and looks for "Did you mean…" suggestions, which leak schema even when
// introspection is disabled.
type GraphQLFieldSuggestionScanner struct{}

func NewGraphQLFieldSuggestionScanner() *GraphQLFieldSuggestionScanner {
	return &GraphQLFieldSuggestionScanner{}
}

func (s *GraphQLFieldSuggestionScanner) Name() string { return "GraphQL Field Suggestion Leak" }

func (s *GraphQLFieldSuggestionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	probe := map[string]string{"query": "{ temren_doesnt_exist_qwerty }"}
	buf, _ := json.Marshal(probe)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	low := strings.ToLower(string(body))
	if strings.Contains(low, "did you mean") || strings.Contains(low, "suggestion") {
		return []Finding{{
			URL: target, Title: "GraphQL Server Leaks Schema via Suggestions",
			Description: "Server returned \"Did you mean ...\" hints for unknown fields. Even with introspection disabled, attackers can extract the schema by enumeration.",
			Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Evidence: "suggestion in error", Timestamp: time.Now(),
			OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.3,
		}}, nil
	}
	return nil, nil
}
