package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"strings"
	"time"
)

// LoggingMonitoringScanner detects logging and monitoring issues
type LoggingMonitoringScanner struct{}

func NewLoggingMonitoringScanner() *LoggingMonitoringScanner {
	return &LoggingMonitoringScanner{}
}

func (s *LoggingMonitoringScanner) Name() string {
	return "Logging & Monitoring"
}

func (s *LoggingMonitoringScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}

	body, _ := readBody(resp)
	resp.Body.Close()

	bodyStr := string(body)

	errorPatterns := []string{
		"Warning: ",
		"Fatal error:",
		"Parse error:",
		"Call Stack:",
		"Stack trace:",
		"Exception:",
		"at java.lang.",
		"at php/",
		"at org.apache",
		"Traceback (most recent call last)",
		"Debug Trace",
		"SQL Error",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyStr, pattern) {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "Detailed Error Messages Exposed",
				Description: "Application reveals detailed error information",
				Severity:    SeverityMedium,
				Confidence:  ConfidenceMedium,
				Payload:     pattern,
				Evidence:    "Error pattern detected in response: " + pattern,
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	debugPatterns := []string{
		"DEBUG:",
		"[DEBUG]",
		"console.log",
		"phpinfo()",
		"Stacktrace:",
	}

	for _, pattern := range debugPatterns {
		if strings.Contains(bodyStr, pattern) {
			findings = append(findings, Finding{
				URL:         target,
				Title:       "Debug Information Exposed",
				Description: "Debug mode appears to be enabled",
				Severity:    SeverityMedium,
				Confidence:  ConfidenceMedium,
				Payload:     pattern,
				Evidence:    "Debug pattern found: " + pattern,
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

