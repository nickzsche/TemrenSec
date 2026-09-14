package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// WebDAVScanner probes for WebDAV verbs (PROPFIND/OPTIONS) that should never be exposed
// on a public web server.
type WebDAVScanner struct{}

func NewWebDAVScanner() *WebDAVScanner { return &WebDAVScanner{} }

func (s *WebDAVScanner) Name() string { return "WebDAV Surface" }

func (s *WebDAVScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	allow := resp.Header.Get("Allow")
	dav := resp.Header.Get("DAV")
	resp.Body.Close()
	if dav != "" || strings.Contains(strings.ToUpper(allow), "PROPFIND") {
		return []Finding{{
			URL: target, Title: "WebDAV Methods Exposed",
			Description: "Server advertises WebDAV verbs (DAV header / Allow: PROPFIND, MKCOL, COPY, etc.). Disable WebDAV unless intentionally serving a DAV client.",
			Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Evidence: "DAV=" + dav + " Allow=" + allow,
			Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5,
		}}, nil
	}
	return nil, nil
}
