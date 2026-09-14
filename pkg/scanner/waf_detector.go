package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// WAFDetector detects Web Application Firewalls
type WAFDetector struct{}

func NewWAFDetector() *WAFDetector {
	return &WAFDetector{}
}

func (s *WAFDetector) Name() string {
	return "WAF Detection"
}

func (s *WAFDetector) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	testPayloads := []string{
		"' OR '1'='1",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
	}

	wafSignatures := map[string]string{
		"cloudflare":   "Cloudflare",
		"__cfduid":     "Cloudflare",
		"cf-ray":       "Cloudflare",
		"akamai":       "Akamai",
		"incapsula":    "Incapsula",
		"imperva":      "Imperva",
		"mod_security": "ModSecurity",
		"bigip":        "F5 BIG-IP",
		"aws-waf":      "AWS WAF",
		"fortiweb":     "FortiWeb",
		"barracuda":    "Barracuda WAF",
		"fastly":       "Fastly",
		"sucuri":       "Sucuri",
	}

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	for _, payload := range testPayloads {
		testQuery := u.Query()
		if len(testQuery) > 0 {
			for k := range testQuery {
				testQuery.Set(k, payload)
				break
			}
			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()
			resp, err := client.Get(ctx, testURL)
			if err != nil {
				continue
			}

			headers := resp.Header
			resp.Body.Close()

			headerStr := ""
			for k, v := range headers {
				headerStr += k + ": " + strings.Join(v, ", ") + "\n"
			}

			for sig, wafName := range wafSignatures {
				if strings.Contains(strings.ToLower(headerStr), strings.ToLower(sig)) {
					findings = append(findings, Finding{
						URL:         target,
						Title:       "WAF Detected: " + wafName,
						Description: "Web Application Firewall detected",
						Severity:    SeverityInfo,
						Confidence:  ConfidenceHigh,
						Evidence:    "WAF signature: " + sig,
						Scanner:     s.Name(),
						Timestamp:   time.Now(),
					})
					return findings, nil
				}
			}

			if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
				findings = append(findings, Finding{
					URL:         target,
					Title:       "Potential WAF Blocking",
					Description: "Possible WAF intervention",
					Severity:    SeverityInfo,
					Confidence:  ConfidenceLow,
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

