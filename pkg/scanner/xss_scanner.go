package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// XSSScanner detects Cross-Site Scripting vulnerabilities
type XSSScanner struct{}

func NewXSSScanner() *XSSScanner {
	return &XSSScanner{}
}

func (s *XSSScanner) Name() string {
	return "Cross-Site Scripting (XSS)"
}

// Scan tests for XSS vulnerabilities
func (s *XSSScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	for param, vals := range query {
		_ = vals
		for _, payload := range payloads.XSS {
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

			body, _ := readBody(resp)
			resp.Body.Close()

			// Check if payload is reflected
			if s.isPayloadReflected(payload, string(body)) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Reflected XSS",
					Description: "Cross-Site Scripting vulnerability detected in parameter: " + param,
					Severity:    SeverityHigh,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "Payload reflected in response without proper encoding",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

// isPayloadReflected checks if XSS payload is reflected in response
func (s *XSSScanner) isPayloadReflected(payload, body string) bool {
	// Check for direct reflection
	if strings.Contains(body, payload) {
		return true
	}

	// Check for common XSS patterns in response
	xssIndicators := []string{
		"<script>alert",
		"onerror=alert",
		"onload=alert",
		"onfocus=alert",
		"onmouseover=alert",
	}

	lowerBody := strings.ToLower(body)
	for _, indicator := range xssIndicators {
		if strings.Contains(lowerBody, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

