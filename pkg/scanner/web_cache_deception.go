package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// WebCacheDeceptionScanner detects whether dynamic endpoints are cached when the URL is suffixed with .css/.jpg etc.
type WebCacheDeceptionScanner struct{}

func NewWebCacheDeceptionScanner() *WebCacheDeceptionScanner { return &WebCacheDeceptionScanner{} }

func (s *WebCacheDeceptionScanner) Name() string { return "Web Cache Deception" }

var staticSuffixes = []string{".css", ".jpg", ".png", ".js", ".gif", ".ico", ".svg", ".woff"}

func (s *WebCacheDeceptionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding
	for _, suf := range staticSuffixes {
		probe := strings.TrimRight(target, "/") + "/nonexistent" + suf
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		cc := resp.Header.Get("Cache-Control")
		age := resp.Header.Get("Age")
		xcache := resp.Header.Get("X-Cache")
		resp.Body.Close()
		// If server returned 200 and body looks like the dynamic page (Set-Cookie, user keywords) AND response is cacheable → vuln.
		if resp.StatusCode == 200 &&
			(strings.Contains(string(body), "<html") || strings.Contains(string(body), "Set-Cookie")) &&
			(strings.Contains(strings.ToLower(cc), "public") || age != "" || strings.Contains(strings.ToLower(xcache), "hit")) {
			findings = append(findings, Finding{
				URL: probe, Title: "Web Cache Deception Possible",
				Description: "Suffixing the dynamic URL with a static-asset extension produced a cacheable 200 with HTML body. Authenticated content may be cached and served to other users.",
				Severity: SeverityHigh, Confidence: ConfidenceMedium, Scanner: s.Name(),
				Payload: suf, Evidence: "Cache-Control=" + cc + " Age=" + age,
				Timestamp: time.Now(), OWASPCategory: "A04:2021-Insecure Design", CVSSScore: 7.5,
			})
		}
	}
	return findings, nil
}
