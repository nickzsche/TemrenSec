package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// CachePoisoningScanner probes for unkeyed header injection that pollutes shared caches.
type CachePoisoningScanner struct{}

func NewCachePoisoningScanner() *CachePoisoningScanner { return &CachePoisoningScanner{} }

func (s *CachePoisoningScanner) Name() string { return "Web Cache Poisoning" }

func (s *CachePoisoningScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	canaries := []string{"X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL"}
	marker := "temren-canary-" + fmt.Sprintf("%d", time.Now().UnixNano())
	var findings []Finding

	for _, h := range canaries {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		req.Header.Set(h, marker+".example")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if strings.Contains(string(body), marker) {
			findings = append(findings, Finding{
				URL:           target,
				Title:         "Unkeyed Header Reflected in Body — Cache Poisoning Risk",
				Description:   fmt.Sprintf("Header %s is reflected and likely not part of the cache key. An attacker can poison the shared cache for other users.", h),
				Severity:      SeverityHigh,
				Confidence:    ConfidenceMedium,
				Payload:       fmt.Sprintf("%s: %s.example", h, marker),
				Evidence:      "marker reflected in response",
				Scanner:       s.Name(),
				Parameter:     h,
				Timestamp:     time.Now(),
				OWASPCategory: "A04:2021-Insecure Design",
				CVSSScore:     7.4,
			})
		}
	}
	return findings, nil
}
