package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// CORSPreflightScanner sends Origin-bearing OPTIONS requests to detect overly permissive CORS.
type CORSPreflightScanner struct{}

func NewCORSPreflightScanner() *CORSPreflightScanner { return &CORSPreflightScanner{} }

func (s *CORSPreflightScanner) Name() string { return "CORS Misconfiguration (Preflight)" }

func (s *CORSPreflightScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding
	origins := []string{"https://evil.example", "null", "https://attacker.com.example.com"}
	for _, origin := range origins {
		req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "DELETE")
		req.Header.Set("Access-Control-Request-Headers", "Authorization, X-Custom")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		resp.Body.Close()
		if acao == "" {
			continue
		}
		if acao == "*" && strings.EqualFold(acac, "true") {
			findings = append(findings, Finding{
				URL: target, Title: "CORS Wildcard with Credentials",
				Description: "Access-Control-Allow-Origin is * and Allow-Credentials is true — browsers will refuse, but server intent is dangerous and may have variant code paths.",
				Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5,
			})
		}
		if acao == origin && strings.EqualFold(acac, "true") {
			findings = append(findings, Finding{
				URL: target, Title: "CORS Reflects Arbitrary Origin with Credentials",
				Description: "Server echoes any Origin and sets Allow-Credentials: true. An attacker-controlled site can read authenticated responses.",
				Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Payload: "Origin: " + origin, Timestamp: time.Now(),
				OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 8.6,
			})
		}
		if origin == "null" && acao == "null" {
			findings = append(findings, Finding{
				URL: target, Title: "CORS Allows null Origin",
				Description: "Access-Control-Allow-Origin: null trusts sandboxed iframes and local files — exploitable from data: URIs and sandboxed contexts.",
				Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 6.5,
			})
		}
	}
	return findings, nil
}
