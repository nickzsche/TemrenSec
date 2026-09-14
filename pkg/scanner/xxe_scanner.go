package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// XXEScanner detects XML External Entity attacks
type XXEScanner struct{}

func NewXXEScanner() *XXEScanner {
	return &XXEScanner{}
}

func (s *XXEScanner) Name() string {
	return "XML External Entity (XXE)"
}

func (s *XXEScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	for _, payload := range payloads.XXE {
		testURL := u.Scheme + "://" + u.Host + u.Path

		resp, err := client.Post(ctx, testURL, "application/xml", strings.NewReader(payload))
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		resp.Body.Close()

		if s.detectXXE(string(body)) {
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "XML External Entity (XXE)",
				Description: "XXE vulnerability detected - external entity processing enabled",
				Severity:    SeverityHigh,
				Confidence:  ConfidenceHigh,
				Payload:     payload,
				Evidence:    "External entity processed in XML response",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

func (s *XXEScanner) detectXXE(body string) bool {
	indicators := []string{
		"root:",
		"bin/bash",
		"[fonts]",
		"[extensions]",
		"www-data",
		"root:x:0:0",
	}
	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	return false
}

