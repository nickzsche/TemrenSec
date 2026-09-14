package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// PathTraversalScanner detects directory traversal vulnerabilities
type PathTraversalScanner struct{}

func NewPathTraversalScanner() *PathTraversalScanner {
	return &PathTraversalScanner{}
}

func (s *PathTraversalScanner) Name() string {
	return "Path Traversal"
}

func (s *PathTraversalScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		for _, payload := range payloads.PathTraversal {
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

			if s.detectPathTraversal(string(body)) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Path Traversal",
					Description: "Directory traversal vulnerability detected in parameter: " + param,
					Severity:    SeverityHigh,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "Sensitive file content detected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

func (s *PathTraversalScanner) detectPathTraversal(body string) bool {
	indicators := []string{
		"root:x:0:0:",
		"www-data:x:",
		"[boot loader]",
		"[mci dll]",
		"Windows",
		"Microsoft",
		"[Registry]",
	}
	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	return false
}

