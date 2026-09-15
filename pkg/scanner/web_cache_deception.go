package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// WebCacheDeceptionScanner detects whether dynamic endpoints are cached when the
// URL is suffixed with .css/.jpg etc.
type WebCacheDeceptionScanner struct{}

func NewWebCacheDeceptionScanner() *WebCacheDeceptionScanner { return &WebCacheDeceptionScanner{} }

func (s *WebCacheDeceptionScanner) Name() string { return "Web Cache Deception" }

var staticSuffixes = []string{".css", ".jpg", ".png", ".js", ".gif", ".ico", ".svg", ".woff"}

func (s *WebCacheDeceptionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding
	base := strings.TrimRight(target, "/")

	// Control: a nonexistent path WITHOUT a static suffix. On SPA/catch-all
	// sites every unknown path returns the same 200 HTML shell (often with a
	// public cache header), which used to be flagged as cache deception on
	// every suffix. By comparing the suffixed probe against this control we
	// only flag when the static suffix itself changes the response — the real
	// signal for cache deception.
	ctrlStatus, ctrlBody := s.fetch(ctx, client, base+"/temren-wcd-control-9271")

	for _, suf := range staticSuffixes {
		probe := base + "/temren-wcd-control-9271" + suf
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

		cacheable := strings.Contains(strings.ToLower(cc), "public") || age != "" || strings.Contains(strings.ToLower(xcache), "hit")
		looksDynamic := strings.Contains(string(body), "<html") || strings.Contains(string(body), "Set-Cookie")

		// Catch-all guard: if the suffixed probe is indistinguishable from the
		// no-suffix control (same status and near-identical body), the server
		// simply serves one shell for everything — not cache deception.
		sameAsControl := resp.StatusCode == ctrlStatus && similarLen(len(body), len(ctrlBody))

		if resp.StatusCode == 200 && looksDynamic && cacheable && !sameAsControl {
			findings = append(findings, Finding{
				URL: probe, Title: "Web Cache Deception Possible",
				Description: "Suffixing the URL with a static-asset extension produced a cacheable 200 with a dynamic body that differs from the plain catch-all response. Authenticated content may be cached and served to other users.",
				Severity:    SeverityHigh, Confidence: ConfidenceMedium, Scanner: s.Name(),
				Payload: suf, Evidence: "Cache-Control=" + cc + " Age=" + age + " X-Cache=" + xcache,
				Timestamp: time.Now(), OWASPCategory: "A04:2021-Insecure Design", CVSSScore: 7.5,
			})
		}
	}
	return findings, nil
}

// fetch returns (status, body) for a GET, or (0, nil) on error.
func (s *WebCacheDeceptionScanner) fetch(ctx context.Context, client *httpengine.Client, u string) (int, []byte) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, body
}
