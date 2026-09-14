package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// ErrorHandlingScanner detects mishandling of exceptional conditions (OWASP 2025 A10)
type ErrorHandlingScanner struct{}

func NewErrorHandlingScanner() *ErrorHandlingScanner {
	return &ErrorHandlingScanner{}
}

func (s *ErrorHandlingScanner) Name() string {
	return "Mishandling of Exceptional Conditions"
}

func (s *ErrorHandlingScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	testPaths := []string{
		"/%00",
		"/null",
		"/undefined",
		"/%ff",
		"/.git/HEAD",
		"/..\\..\\..\\",
		"/?null=",
		"/?undefined=",
		"/?NaN=",
		"/?infinity=",
	}

	for _, path := range testPaths {
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		testURL := u.Scheme + "://" + u.Host + path

		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		resp.Body.Close()

		bodyStr := string(body)

		exceptionPatterns := []string{
			"NullPointerException",
			"undefined is not",
			"Cannot read property",
			"TypeError:",
			"ReferenceError:",
			"SyntaxError:",
			"RangeError:",
			"Error:",
			"Exception:",
			"HTTP 500",
			"Internal Server Error",
			"is not defined",
			"is null",
			"is undefined",
			"failing open",
			"exception occurred",
		}

		for _, pattern := range exceptionPatterns {
			if strings.Contains(bodyStr, pattern) {
				findings = append(findings, Finding{
					URL:               testURL,
					Title:             "Improper Exception Handling",
					Description:       "Application fails to properly handle exceptional conditions",
					Severity:          SeverityMedium,
					Confidence:        ConfidenceMedium,
					Payload:           path,
					Evidence:          "Exception detected: " + pattern,
					Scanner:           s.Name(),
					Timestamp:         time.Now(),
					OWASPCategory2025: "A10:2025-Mishandling of Exceptional Conditions",
				})
				break
			}
		}
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, err
	}

	body, _ := readBody(resp)
	resp.Body.Close()

	bodyStr := string(body)

	if strings.Contains(bodyStr, "200 OK") || strings.Contains(bodyStr, "HTTP/1.1 200") {
		if !strings.Contains(bodyStr, "login") && !strings.Contains(bodyStr, "error") {
			findings = append(findings, Finding{
				URL:               target,
				Title:             "Potential Fail-Open Condition",
				Description:       "Application may fail open under certain conditions",
				Severity:          SeverityHigh,
				Confidence:        ConfidenceMedium,
				Evidence:          "Successful response without proper authentication checks",
				Scanner:           s.Name(),
				Timestamp:         time.Now(),
				OWASPCategory2025: "A10:2025-Mishandling of Exceptional Conditions",
			})
		}
	}

	return findings, nil
}

