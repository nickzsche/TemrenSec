package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

type NoSQLInjectionScanner struct{}

func NewNoSQLInjectionScanner() *NoSQLInjectionScanner {
	return &NoSQLInjectionScanner{}
}

func (s *NoSQLInjectionScanner) Name() string {
	return "NoSQL Injection"
}

func (s *NoSQLInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}
	normalBody, _ := readBody(resp)
	resp.Body.Close()
	normalStr := string(normalBody)

	for param, values := range query {
		originalValue := values[0]

		for _, payload := range payloads.NoSQLInjection {
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

			if s.detectNoSQLError(bodyStr) {
				findings = append(findings, Finding{
					URL:           testURL,
					Title:         "NoSQL Injection",
					Description:   "NoSQL injection vulnerability detected in parameter: " + param,
					Severity:      SeverityCritical,
					Confidence:    ConfidenceHigh,
					Payload:       payload,
					Evidence:      "NoSQL error pattern detected in response",
					Scanner:       s.Name(),
					Timestamp:     time.Now(),
					OWASPCategory: "A03:2021 - Injection",
				})
				break
			}

			if s.detectBooleanBased(normalStr, bodyStr) {
				findings = append(findings, Finding{
					URL:           testURL,
					Title:         "NoSQL Injection (Boolean-Based)",
					Description:   "NoSQL boolean-based injection detected in parameter: " + param,
					Severity:      SeverityCritical,
					Confidence:    ConfidenceMedium,
					Payload:       payload,
					Evidence:      "Response differs significantly from normal request",
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

func (s *NoSQLInjectionScanner) detectNoSQLError(body string) bool {
	patterns := []string{
		"MongoError",
		"MongoServerError",
		"$gt",
		"BSON",
		"not authorized",
	}

	lowerBody := strings.ToLower(body)
	for _, pattern := range patterns {
		if strings.Contains(lowerBody, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (s *NoSQLInjectionScanner) detectBooleanBased(normalBody, injectedBody string) bool {
	if len(normalBody) == 0 || len(injectedBody) == 0 {
		return false
	}

	if normalBody == injectedBody {
		return false
	}

	normalLen := len(normalBody)
	injectedLen := len(injectedBody)

	diff := float64(normalLen - injectedLen)
	if normalLen > 0 {
		ratio := diff / float64(normalLen)
		if ratio < -0.5 || ratio > 0.5 {
			return true
		}
	}

	return false
}
