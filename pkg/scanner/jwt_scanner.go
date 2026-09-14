package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"regexp"
	"strings"
	"time"
)

// JWTScanner analyzes JWT tokens
type JWTScanner struct{}

func NewJWTScanner() *JWTScanner {
	return &JWTScanner{}
}

func (s *JWTScanner) Name() string {
	return "JWT Analysis"
}

func (s *JWTScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}

	body, _ := readBody(resp)
	resp.Body.Close()
	bodyStr := string(body)
	headers := resp.Header

	jwtPatterns := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

	matches := jwtPatterns.FindAllString(bodyStr, -1)
	for _, match := range matches {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "JWT Token Found in Response",
			Description: "Potential JWT token exposed in page source",
			Severity:    SeverityHigh,
			Confidence:  ConfidenceMedium,
			Payload:     match[:min(50, len(match))] + "...",
			Evidence:    "Token found - ensure it doesn't contain sensitive data",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	for _, cookie := range headers.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(cookie), "jwt") || strings.Contains(strings.ToLower(cookie), "token") {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "JWT in Cookie",
				Description: "JWT or token found in cookie",
				Severity:    SeverityMedium,
				Confidence:  ConfidenceLow,
				Evidence:    cookie,
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

