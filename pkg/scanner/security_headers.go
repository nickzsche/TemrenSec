package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SecurityHeadersScanner audits response headers against OWASP secure-headers baseline.
type SecurityHeadersScanner struct{}

func NewSecurityHeadersScanner() *SecurityHeadersScanner { return &SecurityHeadersScanner{} }

func (s *SecurityHeadersScanner) Name() string { return "Security Headers Audit" }

type headerExpect struct {
	header string
	mustContain string
	severity Severity
	score float64
	desc string
}

var headerChecks = []headerExpect{
	{"Strict-Transport-Security", "max-age", SeverityMedium, 5.3, "HSTS missing or weak. Downgrade and SSL-strip attacks possible."},
	{"Content-Security-Policy", "default-src", SeverityMedium, 6.1, "CSP missing. XSS impact magnified — no script-source restrictions."},
	{"X-Content-Type-Options", "nosniff", SeverityLow, 3.7, "MIME-sniffing not blocked."},
	{"X-Frame-Options", "", SeverityLow, 4.3, "Clickjacking protection missing (X-Frame-Options or CSP frame-ancestors)."},
	{"Referrer-Policy", "", SeverityLow, 3.1, "Referrer-Policy missing — full URLs leak to third parties."},
	{"Permissions-Policy", "", SeverityLow, 2.7, "Permissions-Policy missing — browser features unrestricted."},
	{"Cross-Origin-Opener-Policy", "", SeverityLow, 2.7, "COOP missing — opens window references can be abused."},
	{"Cross-Origin-Resource-Policy", "", SeverityLow, 2.7, "CORP missing — same-site assets may be embedded cross-origin."},
}

func (s *SecurityHeadersScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	var findings []Finding
	for _, c := range headerChecks {
		val := resp.Header.Get(c.header)
		if val == "" || (c.mustContain != "" && !strings.Contains(strings.ToLower(val), strings.ToLower(c.mustContain))) {
			findings = append(findings, Finding{
				URL: target, Title: "Missing/Weak Header: " + c.header,
				Description: c.desc, Severity: c.severity, Confidence: ConfidenceHigh,
				Scanner: s.Name(), Timestamp: time.Now(),
				OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: c.score,
				Evidence: c.header + ": " + val,
			})
		}
	}
	// Cookies
	for _, c := range resp.Cookies() {
		miss := []string{}
		if !c.HttpOnly {
			miss = append(miss, "HttpOnly")
		}
		if !c.Secure {
			miss = append(miss, "Secure")
		}
		if c.SameSite == http.SameSiteDefaultMode {
			miss = append(miss, "SameSite")
		}
		if len(miss) > 0 {
			findings = append(findings, Finding{
				URL: target, Title: "Cookie Missing Flags: " + c.Name,
				Description: "Cookie " + c.Name + " missing: " + strings.Join(miss, ", "),
				Severity: SeverityMedium, Confidence: ConfidenceHigh,
				Scanner: s.Name(), Timestamp: time.Now(),
				OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.4,
			})
		}
	}
	return findings, nil
}
