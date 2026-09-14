package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// OpenRedirectScanner tests for open redirect vulnerabilities
type OpenRedirectScanner struct{}

func NewOpenRedirectScanner() *OpenRedirectScanner {
	return &OpenRedirectScanner{}
}

func (s *OpenRedirectScanner) Name() string {
	return "Open Redirect"
}

func (s *OpenRedirectScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	redirectPayloads := []string{
		"https://evil.com",
		"//evil.com",
		"///evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	}

	for param := range query {
		for _, payload := range redirectPayloads {
			testQuery := url.Values{}
			for k, v := range query {
				if k == param {
					testQuery.Set(k, payload)
				} else {
					testQuery.Set(k, v[0])
				}
			}

			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			resp, err := client.Get(ctx, testURL)
			if err != nil {
				continue
			}

			loc := resp.Header.Get("Location")

			if loc != "" && (strings.Contains(loc, "evil.com") || strings.Contains(loc, "javascript:") || strings.Contains(loc, "data:")) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Open Redirect Vulnerability",
					Description: "Open redirect found in parameter: " + param,
					Severity:    SeverityMedium,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "Redirect to: " + loc,
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
			}

			resp.Body.Close()
		}
	}

	return findings, nil
}

