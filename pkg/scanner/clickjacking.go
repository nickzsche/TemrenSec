package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// ClickjackingScanner checks whether the response has anti-framing protection
// (X-Frame-Options or CSP frame-ancestors). Missing both ⇒ vulnerable.
type ClickjackingScanner struct{}

func NewClickjackingScanner() *ClickjackingScanner { return &ClickjackingScanner{} }

func (s *ClickjackingScanner) Name() string { return "Clickjacking Protection" }

func (s *ClickjackingScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	resp.Body.Close()
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")
	hasFA := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo == "" && !hasFA {
		return []Finding{{
			URL: target, Title: "Clickjacking — No Frame Protection",
			Description: "Neither X-Frame-Options nor CSP frame-ancestors is set. An attacker site can iframe this page and trick users into clicking on it.",
			Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 6.1,
		}}, nil
	}
	return nil, nil
}
