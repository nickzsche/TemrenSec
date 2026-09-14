package scanner

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SourceMapLeakScanner detects publicly accessible JavaScript source maps,
// which leak original (pre-minification) source code.
type SourceMapLeakScanner struct{}

func NewSourceMapLeakScanner() *SourceMapLeakScanner { return &SourceMapLeakScanner{} }

func (s *SourceMapLeakScanner) Name() string { return "Source Map Leak" }

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

func (s *SourceMapLeakScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	base, err := url.Parse(target)
	if err != nil {
		return nil, nil
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, nil
	}
	body, _ := readBody(resp)
	html := string(body)

	// Inline sourceMappingURL directive in the page itself.
	if strings.Contains(html, "sourceMappingURL=") {
		findings = append(findings, Finding{
			URL:           target,
			Title:         "Source Map Leak",
			Description:   "Page references an inline sourceMappingURL directive, exposing source map metadata.",
			Severity:      SeverityLow,
			Confidence:    ConfidenceHigh,
			Evidence:      "//# sourceMappingURL= directive found in HTML",
			Scanner:       s.Name(),
			Timestamp:     time.Now(),
			OWASPCategory: "A02 Security Misconfiguration",
		})
	}

	seen := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		src := m[1]
		if !strings.HasSuffix(strings.ToLower(src), ".js") {
			continue
		}
		ref, err := url.Parse(src)
		if err != nil {
			continue
		}
		mapURL := base.ResolveReference(ref).String() + ".map"
		if seen[mapURL] {
			continue
		}
		seen[mapURL] = true

		mresp, err := client.Get(ctx, mapURL)
		if err != nil {
			continue
		}
		if mresp.StatusCode != 200 {
			continue
		}
		mb, _ := readBody(mresp)
		ct := mresp.Header.Get("Content-Type")
		mstr := string(mb)

		if strings.Contains(ct, "application/json") || strings.Contains(mstr, "sourceMappingURL") || strings.Contains(mstr, `"sources":[`) {
			findings = append(findings, Finding{
				URL:           mapURL,
				Title:         "Source Map Leak",
				Description:   "JavaScript source map is publicly accessible, leaking original source code.",
				Severity:      SeverityLow,
				Confidence:    ConfidenceHigh,
				Payload:       src,
				Evidence:      "Source map served with Content-Type: " + ct,
				Scanner:       s.Name(),
				Timestamp:     time.Now(),
				OWASPCategory: "A02 Security Misconfiguration",
			})
		}
	}

	return findings, nil
}
