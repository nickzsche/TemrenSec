package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"strings"
	"time"
)

// VulnerableComponentsScanner detects vulnerable/outdated components
type VulnerableComponentsScanner struct{}

func NewVulnerableComponentsScanner() *VulnerableComponentsScanner {
	return &VulnerableComponentsScanner{}
}

func (s *VulnerableComponentsScanner) Name() string {
	return "Vulnerable Components"
}

func (s *VulnerableComponentsScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}

	body, _ := readBody(resp)
	resp.Body.Close()

	bodyStr := string(body)

	patterns := []struct {
		pattern  string
		version  string
		name     string
		severity Severity
	}{
		{"jquery-1\\.", "1.x", "jQuery 1.x (EOL)", SeverityMedium},
		{"jquery-2\\.", "2.x", "jQuery 2.x (EOL)", SeverityMedium},
		{"bootstrap-3", "3.x", "Bootstrap 3.x (EOL)", SeverityLow},
		{"angular.js", "AngularJS 1.x", "AngularJS 1.x (EOL)", SeverityMedium},
		{"prototype", "Prototype.js", "Prototype.js (deprecated)", SeverityLow},
		{"MooTools", "MooTools", "MooTools (deprecated)", SeverityLow},
		{"swagger-ui", "Swagger UI", "Swagger UI exposed", SeverityHigh},
		{"api-docs", "API Docs", "API documentation exposed", SeverityMedium},
	}

	for _, p := range patterns {
		if strings.Contains(bodyStr, p.pattern) {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "Vulnerable Component: " + p.name,
				Description: p.name + " detected - check for latest secure version",
				Severity:    p.severity,
				Confidence:  ConfidenceMedium,
				Payload:     p.version,
				Evidence:    "Component version pattern found in response",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	if strings.Contains(bodyStr, "version") && strings.Contains(bodyStr, "deprecated") {
		findings = append(findings, Finding{
			URL:         target,
			Title:       "Deprecated Component Usage",
			Description: "Page mentions deprecated components",
			Severity:    SeverityLow,
			Confidence:  ConfidenceLow,
			Evidence:    "Deprecated keyword found",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

