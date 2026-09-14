package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// PrototypePollutionScanner detects prototype pollution
type PrototypePollutionScanner struct{}

func NewPrototypePollutionScanner() *PrototypePollutionScanner {
	return &PrototypePollutionScanner{}
}

func (s *PrototypePollutionScanner) Name() string {
	return "Prototype Pollution"
}

func (s *PrototypePollutionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	payloads := []string{
		"__proto__[test]=pollution",
		"__proto__.test=pollution",
		"constructor.prototype.test=pollution",
		"{ \"__proto__\": { \"test\": \"pollution\" } }",
		"constructor[prototype][test]=pollution",
		"__proto__[isAdmin]=true",
		"__proto__[isAdmin]=true&__proto__[isAdmin]=true",
	}

	for param := range query {
		for _, payload := range payloads {
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

			if strings.Contains(string(body), "pollution") || strings.Contains(string(body), "__proto__") {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Potential Prototype Pollution",
					Description: "Input appears to be reflected without sanitization",
					Severity:    SeverityHigh,
					Confidence:  ConfidenceMedium,
					Payload:     payload,
					Evidence:    "Prototype pollution pattern detected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

