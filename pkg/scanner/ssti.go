package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

type SSTIScanner struct{}

func NewSSTIScanner() *SSTIScanner {
	return &SSTIScanner{}
}

func (s *SSTIScanner) Name() string {
	return "Server-Side Template Injection (SSTI)"
}

func (s *SSTIScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	for param, values := range query {
		originalValue := values[0]

		for _, payload := range payloads.SSTI {
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

			bodyStr := string(body)

			if s.detectSSTI(bodyStr, payload) {
				findings = append(findings, Finding{
					URL:           testURL,
					Title:         "Server-Side Template Injection (SSTI)",
					Description:   "SSTI vulnerability detected in parameter: " + param,
					Severity:      SeverityCritical,
					Confidence:    ConfidenceHigh,
					Payload:       payload,
					Evidence:      "Template injection expression evaluated in response",
					Scanner:       s.Name(),
					Timestamp:     time.Now(),
					OWASPCategory: "A03:2021 - Injection",
				})
				break
			}
		}

		query.Set(param, originalValue)
	}

	return findings, nil
}

func (s *SSTIScanner) detectSSTI(body, payload string) bool {
	if strings.Contains(body, "49") {
		return true
	}

	sstiErrorPatterns := []string{
		"Jinja2",
		"TemplateSyntaxError",
		"Internal Server Error",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range sstiErrorPatterns {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) && strings.Contains(body, payload) {
			return true
		}
	}

	return false
}