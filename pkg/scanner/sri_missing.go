package scanner

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// SubresourceIntegrityScanner finds <script src> / <link rel="stylesheet"> tags that
// load from a different origin without an `integrity` attribute.
type SubresourceIntegrityScanner struct{}

func NewSubresourceIntegrityScanner() *SubresourceIntegrityScanner {
	return &SubresourceIntegrityScanner{}
}

func (s *SubresourceIntegrityScanner) Name() string { return "Missing Subresource Integrity (SRI)" }

var scriptTagRE = regexp.MustCompile(`<(?:script|link)[^>]+(?:src|href)\s*=\s*"([^"]+)"[^>]*>`)
var integrityRE = regexp.MustCompile(`integrity\s*=\s*"`)

func (s *SubresourceIntegrityScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	resp.Body.Close()
	str := string(body)
	matches := scriptTagRE.FindAllStringSubmatchIndex(str, -1)
	var findings []Finding
	for _, m := range matches {
		tag := str[m[0]:m[1]]
		ref := str[m[2]:m[3]]
		if !strings.HasPrefix(ref, "http") && !strings.HasPrefix(ref, "//") {
			continue
		}
		if integrityRE.MatchString(tag) {
			continue
		}
		findings = append(findings, Finding{
			URL: target, Title: "External resource without SRI: " + ref,
			Description: "Cross-origin asset loaded without an integrity= hash. A breach of the CDN can silently substitute hostile code.",
			Severity: SeverityMedium, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Evidence: tag, Timestamp: time.Now(),
			OWASPCategory: "A08:2021-Software and Data Integrity Failures", CVSSScore: 6.5,
		})
	}
	return findings, nil
}
