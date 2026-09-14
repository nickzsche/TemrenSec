package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IDORScanner detects Insecure Direct Object References
type IDORScanner struct{}

func NewIDORScanner() *IDORScanner {
	return &IDORScanner{}
}

func (s *IDORScanner) Name() string {
	return "Insecure Direct Object Reference (IDOR)"
}

// Scan tests for IDOR
func (s *IDORScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()

	idParams := []string{"id", "user_id", "userId", "user", "account", "file", "document", "order", "profile"}

	for _, param := range idParams {
		if values, exists := query[param]; exists {
			originalValue := values[0]

			testValues := []string{"0", "1", "-1", "2", "999999"}

			for _, testValue := range testValues {
				if testValue == originalValue {
					continue
				}

				testQuery := url.Values{}
				for k, v := range query {
					if k == param {
						testQuery.Set(k, testValue)
					} else {
						testQuery.Set(k, v[0])
					}
				}

				testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

				resp, err := client.Get(ctx, testURL)
				if err != nil {
					continue
				}

				if resp.StatusCode == http.StatusOK {
					body, _ := readBody(resp)

					if len(body) > 0 && !strings.Contains(string(body), "error") &&
						!strings.Contains(string(body), "unauthorized") {
						findings = append(findings, Finding{
							URL:         testURL,
							Title:       "Potential IDOR",
							Description: "Possible IDOR vulnerability in parameter: " + param + ". Changed from " + originalValue + " to " + testValue,
							Severity:    SeverityMedium,
							Confidence:  ConfidenceMedium,
							Payload:     testValue,
							Evidence:    "Different ID returned valid response",
							Scanner:     s.Name(),
							Timestamp:   time.Now(),
						})
					}
				}
				resp.Body.Close()
			}
		}
	}

	return findings, nil
}

