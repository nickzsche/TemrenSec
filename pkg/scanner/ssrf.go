package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"time"
)

// SSRFScanner detects Server-Side Request Forgery
type SSRFScanner struct{}

func NewSSRFScanner() *SSRFScanner {
	return &SSRFScanner{}
}

func (s *SSRFScanner) Name() string {
	return "Server-Side Request Forgery (SSRF)"
}

// Scan tests for SSRF
func (s *SSRFScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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

	for param, vals := range query {
		_ = vals
		for _, payload := range payloads.SSRF {
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

			if s.detectSSRFResponse(string(body), payload, baseline) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Server-Side Request Forgery",
					Description: "SSRF vulnerability detected in parameter: " + param,
					Severity:    SeverityHigh,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "Response indicates internal resource access",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

// detectSSRFResponse checks for SSRF indicators
// detectSSRFResponse reports whether the response contains content that could
// only have come from the server fetching the injected URL.
//
// Two earlier rules made this fire on any endpoint that echoed its input:
//
//   - "computeMetadata" and "metadata.google" are substrings of the payloads
//     themselves, so a reflected payload supplied its own evidence;
//   - a file:// payload returning any non-empty body at all was treated as a
//     confirmed finding, which is every endpoint that returns anything.
//
// Now a marker counts only when the payload's own reflection cannot explain it
// and the unmodified response did not already contain it.
func (s *SSRFScanner) detectSSRFResponse(body, payload, baseline string) bool {
	// Content that indicates the server actually retrieved something internal.
	indicators := []string{
		"root:x:",
		"/bin/bash",
		"[fonts]",
		"[extensions]",
		"ami-id",
		"instance-id",
		"local-hostname",
		"local-ipv4",
		"iam/security-credentials",
		"\"accessKeyId\"",
	}

	for _, ind := range indicators {
		if MarkerIsEvaluated(body, payload, ind, baseline) {
			return true
		}
	}

	return false
}
