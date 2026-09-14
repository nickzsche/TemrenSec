package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"strings"
	"time"
)

// HoneypotDetector identifies potential honeypots
type HoneypotDetector struct{}

func NewHoneypotDetector() *HoneypotDetector {
	return &HoneypotDetector{}
}

func (s *HoneypotDetector) Name() string {
	return "Honeypot Detection"
}

func (s *HoneypotDetector) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return findings, nil
	}

	body, _ := readBody(resp)
	resp.Body.Close()
	bodyStr := string(body)

	honeypotIndicators := []string{
		"shodan",
		"projecthoneypot",
		"threatcrowd",
		"malware",
		"hpfeed",
		"phoneyx",
		"kippo",
		"glastopf",
		"amun",
		"dionaea",
		"thug",
		"Capture",
		"Honeypot",
		"Fake",
		"Bot",
		"automated",
		"crawler",
		"scanner",
	}

	matchCount := 0
	matchedIndicators := []string{}
	for _, indicator := range honeypotIndicators {
		if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(indicator)) {
			matchCount++
			matchedIndicators = append(matchedIndicators, indicator)
		}
	}

	if matchCount >= 3 {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "⚠️ POTENTIAL HONEYPOT DETECTED",
			Description: "This endpoint shows multiple honeypot indicators. Recommend reducing scan intensity.",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceMedium,
			Evidence:    "Matched: " + strings.Join(matchedIndicators, ", "),
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	if client.IsHoneypot() {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "🚨 HONEYPOT CONFIRMED",
			Description: "Multiple 429 responses detected. Target may be a honeypot. Scan reduced to minimum rate.",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Evidence:    "Adaptive rate limit triggered",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

