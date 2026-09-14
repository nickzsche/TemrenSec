package scanner

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/temren/pkg/httpengine"
)

// HTTPMethodOverrideScanner exploits middleware that honors X-HTTP-Method-Override
// to bypass route-level method restrictions (often allowing DELETE/PUT on GET-only routes).
type HTTPMethodOverrideScanner struct{}

func NewHTTPMethodOverrideScanner() *HTTPMethodOverrideScanner {
	return &HTTPMethodOverrideScanner{}
}

func (s *HTTPMethodOverrideScanner) Name() string { return "HTTP Method Override Bypass" }

func (s *HTTPMethodOverrideScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	// Control: PUT directly (probably 405 or 401).
	control := status(ctx, client, target, http.MethodPut, nil)
	if control != http.StatusMethodNotAllowed && control != http.StatusUnauthorized && control != http.StatusForbidden {
		return nil, nil
	}
	override := status(ctx, client, target, http.MethodPost, map[string]string{
		"X-HTTP-Method-Override": "PUT",
		"X-HTTP-Method":          "PUT",
		"X-Method-Override":      "PUT",
	})
	if override < 400 || override == http.StatusMethodNotAllowed && control != override {
		return []Finding{{
			URL: target, Title: "X-HTTP-Method-Override Honored",
			Description: "Server allows POST + X-HTTP-Method-Override to invoke PUT, bypassing method-level access control. Authorization decisions made on HTTP verb are circumventable.",
			Severity: SeverityHigh, Confidence: ConfidenceMedium, Scanner: s.Name(),
			Evidence: "control=" + http.StatusText(control) + " override=" + http.StatusText(override),
			Timestamp: time.Now(), OWASPCategory: "A01:2021-Broken Access Control", CVSSScore: 7.5,
		}}, nil
	}
	return nil, nil
}

func status(ctx context.Context, client *httpengine.Client, target, method string, headers map[string]string) int {
	req, _ := http.NewRequestWithContext(ctx, method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}
