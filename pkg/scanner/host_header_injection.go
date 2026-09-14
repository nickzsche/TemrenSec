package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// HostHeaderInjectionScanner manipulates Host / X-Forwarded-Host to detect reset-poisoning and SSRF pivots.
type HostHeaderInjectionScanner struct{}

func NewHostHeaderInjectionScanner() *HostHeaderInjectionScanner { return &HostHeaderInjectionScanner{} }

func (s *HostHeaderInjectionScanner) Name() string { return "Host Header Injection" }

func (s *HostHeaderInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	evil := "temren-canary.example.com"
	probes := []func(r *http.Request){
		func(r *http.Request) { r.Host = evil },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Host", evil) },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Server", evil) },
		func(r *http.Request) { r.Header.Set("Forwarded", "host="+evil) },
	}
	var findings []Finding
	for _, mut := range probes {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		mut(req)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if strings.Contains(string(body), evil) || strings.Contains(loc, evil) {
			findings = append(findings, Finding{
				URL: target, Title: "Host Header Reflected — Password Reset Poisoning Risk",
				Description: "Manipulated Host/X-Forwarded-Host appears in the response or Location header. Attackers can poison password-reset emails and absolute-URL generation.",
				Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Payload: evil, Timestamp: time.Now(),
				OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5,
			})
			break
		}
	}
	_ = u
	return findings, nil
}
