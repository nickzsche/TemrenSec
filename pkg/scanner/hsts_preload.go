package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// HSTSPreloadScanner checks that the HSTS header would be accepted by hstspreload.org:
// max-age ≥ 31536000, includeSubDomains, preload.
type HSTSPreloadScanner struct{}

func NewHSTSPreloadScanner() *HSTSPreloadScanner { return &HSTSPreloadScanner{} }

func (s *HSTSPreloadScanner) Name() string { return "HSTS Preload Eligibility" }

func (s *HSTSPreloadScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	resp.Body.Close()
	h := resp.Header.Get("Strict-Transport-Security")
	if h == "" {
		return []Finding{{
			URL: target, Title: "HSTS Header Missing",
			Description: "Site does not send Strict-Transport-Security. SSL-strip attacks remain possible until first visit.",
			Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 5.3,
		}}, nil
	}
	low := strings.ToLower(h)
	hasIncludeSubdomains := strings.Contains(low, "includesubdomains")
	hasPreload := strings.Contains(low, "preload")
	var maxAge int64
	for _, part := range strings.Split(low, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			var v int64
			for _, c := range part[len("max-age="):] {
				if c < '0' || c > '9' {
					break
				}
				v = v*10 + int64(c-'0')
			}
			maxAge = v
		}
	}
	if maxAge >= 31536000 && hasIncludeSubdomains && hasPreload {
		return nil, nil
	}
	missing := []string{}
	if maxAge < 31536000 {
		missing = append(missing, "max-age<31536000")
	}
	if !hasIncludeSubdomains {
		missing = append(missing, "includeSubDomains")
	}
	if !hasPreload {
		missing = append(missing, "preload")
	}
	return []Finding{{
		URL: target, Title: "HSTS Not Preload-Eligible",
		Description: "Header present but fails the hstspreload.org criteria. Missing: " + strings.Join(missing, ", "),
		Severity: SeverityLow, Confidence: ConfidenceHigh, Scanner: s.Name(),
		Evidence: h, Timestamp: time.Now(),
		OWASPCategory: "A02:2021-Cryptographic Failures", CVSSScore: 3.7,
	}}, nil
}
