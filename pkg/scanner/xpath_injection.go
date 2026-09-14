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

// XPathInjectionScanner injects XPath operators and watches for parser errors.
type XPathInjectionScanner struct{}

func NewXPathInjectionScanner() *XPathInjectionScanner { return &XPathInjectionScanner{} }

func (s *XPathInjectionScanner) Name() string { return "XPath Injection" }

var xpathPayloads = []string{
	"'or'1'='1",
	"'or'a'='a",
	"' or 1=1 or ''='",
	"x'or 1=1 or 'x'='y",
	"//user[username/text()='a' or '1'='1']",
}

func (s *XPathInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if len(q) == 0 {
		return nil, nil
	}
	var findings []Finding
	for param := range q {
		for _, p := range xpathPayloads {
			tq := url.Values{}
			for k, v := range q {
				if k == param {
					tq.Set(k, p)
				} else {
					tq.Set(k, v[0])
				}
			}
			u.RawQuery = tq.Encode()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			resp, err := client.Do(ctx, req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
			resp.Body.Close()
			low := strings.ToLower(string(body))
			if strings.Contains(low, "xpath") || strings.Contains(low, "xmldocument") || strings.Contains(low, "xpathexception") {
				findings = append(findings, Finding{
					URL:           u.String(),
					Title:         "XPath Injection",
					Description:   "XPath parser error leaked when injecting XPath syntax — authentication or data extraction may be possible.",
					Severity:      SeverityHigh,
					Confidence:    ConfidenceMedium,
					Payload:       p,
					Parameter:     param,
					Evidence:      "XPath error in response",
					Scanner:       s.Name(),
					Timestamp:     time.Now(),
					OWASPCategory: "A03:2021-Injection",
					CVSSScore:     7.5,
				})
				break
			}
		}
	}
	return findings, nil
}
