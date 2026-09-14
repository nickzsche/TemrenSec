package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// HTTPParameterPollutionScanner duplicates query parameters and checks whether the
// backend uses the first / last / concatenated value differently from a single-value control —
// often the prelude to authorization bypass.
type HTTPParameterPollutionScanner struct{}

func NewHTTPParameterPollutionScanner() *HTTPParameterPollutionScanner {
	return &HTTPParameterPollutionScanner{}
}

func (s *HTTPParameterPollutionScanner) Name() string { return "HTTP Parameter Pollution" }

func (s *HTTPParameterPollutionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	if !strings.Contains(target, "?") {
		return nil, nil
	}
	idx := strings.Index(target, "?")
	base, query := target[:idx], target[idx+1:]
	// Duplicate every key.
	parts := strings.Split(query, "&")
	if len(parts) == 0 {
		return nil, nil
	}
	pollutedURL := base + "?" + query + "&" + query
	req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, pollutedURL, nil)
	body1 := getBody(ctx, client, req1)
	body2 := getBody(ctx, client, req2)
	if body1 != "" && body2 != "" && body1 != body2 {
		return []Finding{{
			URL: target, Title: "HTTP Parameter Pollution Behaviour Differs",
			Description: "Duplicating every query parameter changed the server's response. Authorization, access-control, or pricing logic may differ when the backend picks the unexpected occurrence.",
			Severity: SeverityMedium, Confidence: ConfidenceLow, Scanner: s.Name(),
			Payload: pollutedURL, Evidence: "control != polluted",
			Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.3,
		}}, nil
	}
	return nil, nil
}

func getBody(ctx context.Context, client *httpengine.Client, req *http.Request) string {
	resp, err := client.Do(ctx, req)
	if err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	resp.Body.Close()
	return string(b)
}
