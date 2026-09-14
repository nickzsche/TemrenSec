package scanner

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/temren/pkg/httpengine"
)

// DSNLeakScanner inspects the homepage source for embedded Sentry, Datadog or LaunchDarkly
// keys that should not be shipped to browsers without referrer/origin restrictions.
type DSNLeakScanner struct{}

func NewDSNLeakScanner() *DSNLeakScanner { return &DSNLeakScanner{} }

func (s *DSNLeakScanner) Name() string { return "Telemetry DSN / Public Key Leak" }

var dsnPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-f0-9]{32}@[\w.-]+\.ingest\.sentry\.io/\d+`),
	regexp.MustCompile(`pubKey":\s*"[\w-]{20,}"`),
	regexp.MustCompile(`DD_CLIENT_TOKEN['"]?\s*[:=]\s*['"][a-f0-9]{32}['"]`),
	regexp.MustCompile(`launchdarkly[._-]?(client|sdk)[._-]?key['"]?\s*[:=]\s*['"][\w-]{24,}['"]`),
	regexp.MustCompile(`stripe(_|-)?(publishable|public)?_?key['"]?\s*[:=]\s*['"]pk_(test|live)_[\w]{16,}['"]`),
}

func (s *DSNLeakScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	resp.Body.Close()
	var findings []Finding
	for _, re := range dsnPatterns {
		if loc := re.FindIndex(body); loc != nil {
			match := string(body[loc[0]:loc[1]])
			findings = append(findings, Finding{
				URL: target, Title: "Public Telemetry / SDK Key Leaked",
				Description: "A telemetry SDK key was embedded in the page source. Public-by-design or not, restrict via referrer / origin allowlists in the vendor console to prevent third-party abuse and quota draining.",
				Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Evidence: redact(match), Timestamp: time.Now(),
				OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.3,
			})
		}
	}
	return findings, nil
}

func redact(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:]
}
