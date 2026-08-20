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

	baseline := fetchBaselineBody(ctx, client, target)

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

			if s.detectSSTI(bodyStr, payload, baseline) {
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

// detectSSTI reports whether the template expression was evaluated.
//
// It takes the baseline so an arithmetic result the page already contains does
// not count. The previous version returned true whenever the body contained the
// bare string "49" anywhere — a price, an identifier, part of a hash — which
// made any such page a Critical finding. "Internal Server Error" was also
// treated as proof, so any 500 counted.
func (s *SSTIScanner) detectSSTI(body, payload, baseline string) bool {
	// 7*7 evaluated: the result must be attributable to the payload and must not
	// already be on the page.
	if MarkerIsEvaluated(body, payload, "49", baseline) {
		return true
	}

	// A template error naming a specific engine is good evidence, provided the
	// baseline was not already producing it.
	engineErrors := []string{
		"jinja2",
		"templatesyntaxerror",
		"freemarker.core",
		"org.apache.velocity",
		"twig\\error",
	}

	lowerBaseline := strings.ToLower(baseline)
	lowerBody := strings.ToLower(body)
	for _, pattern := range engineErrors {
		if strings.Contains(lowerBody, pattern) && !strings.Contains(lowerBaseline, pattern) {
			return true
		}
	}

	return false
}
