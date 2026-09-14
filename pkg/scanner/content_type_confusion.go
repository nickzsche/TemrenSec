package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// ContentTypeConfusionScanner posts XML / form-encoded bodies to JSON-only endpoints
// to detect parsers that fall back to dangerous formats (XXE via XML, parameter
// pollution via form).
type ContentTypeConfusionScanner struct{}

func NewContentTypeConfusionScanner() *ContentTypeConfusionScanner {
	return &ContentTypeConfusionScanner{}
}

func (s *ContentTypeConfusionScanner) Name() string { return "Content-Type Confusion" }

func (s *ContentTypeConfusionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	probes := []struct {
		ctype string
		body  string
		label string
	}{
		{"application/xml", `<?xml version="1.0"?><root><user>temren</user></root>`, "XML accepted"},
		{"text/xml", `<root><a/></root>`, "text/xml accepted"},
		{"application/x-www-form-urlencoded", "user=temren", "form-encoded accepted"},
		{"application/x-yaml", "user: temren", "YAML accepted"},
	}
	var findings []Finding
	for _, p := range probes {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader([]byte(p.body)))
		req.Header.Set("Content-Type", p.ctype)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		// Heuristic: a 200 that reflects "temren" suggests the alternate parser engaged.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.Contains(string(body), "temren") {
			findings = append(findings, Finding{
				URL: target, Title: "Content-Type Confusion (" + p.ctype + ")",
				Description: "Endpoint accepted body in unintended format and parsed it. XML opens XXE risk; YAML opens deserialization; form-encoded opens parameter pollution.",
				Severity: SeverityHigh, Confidence: ConfidenceLow, Scanner: s.Name(),
				Payload: p.ctype, Evidence: p.label,
				Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 6.5,
			})
		}
	}
	return findings, nil
}
