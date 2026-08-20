package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
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

	baseline := fetchBaselineBody(ctx, client, target)

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

			// "__proto__" is part of the payload, so finding it in the response
			// only means the endpoint reflects input — every reflecting parameter
			// used to produce a High finding here. The marker only counts if the
			// payload's own reflection cannot account for it.
			marker := ""
			for _, candidate := range []string{"__proto__", "pollution"} {
				if MarkerIsEvaluated(string(body), payload, candidate, baseline) {
					marker = candidate
					break
				}
			}
			if marker != "" {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Potential Prototype Pollution",
					Description: "Polluted property surfaced in the response for parameter: " + param,
					Severity:    SeverityHigh,
					Confidence:  ConfidenceMedium,
					Payload:     payload,
					Evidence: "Marker " + quote(marker) + " present after injection, absent from the " +
						"unmodified response, and not attributable to the payload being echoed back",
					Scanner:   s.Name(),
					Timestamp: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
