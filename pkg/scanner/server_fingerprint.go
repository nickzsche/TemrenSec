package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// ServerFingerprintScanner reports verbose Server / X-Powered-By / X-AspNet-Version
// banners that help attackers find applicable CVEs.
type ServerFingerprintScanner struct{}

func NewServerFingerprintScanner() *ServerFingerprintScanner {
	return &ServerFingerprintScanner{}
}

func (s *ServerFingerprintScanner) Name() string { return "Server Banner / Version Disclosure" }

var bannerHeaders = []string{
	"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator",
	"X-Drupal-Cache", "X-Drupal-Dynamic-Cache", "X-Backend-Server", "X-Served-By",
}

func (s *ServerFingerprintScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	resp.Body.Close()
	var leaks []string
	for _, h := range bannerHeaders {
		if v := resp.Header.Get(h); v != "" && containsDigit(v) {
			leaks = append(leaks, h+": "+v)
		}
	}
	if len(leaks) == 0 {
		return nil, nil
	}
	return []Finding{{
		URL: target, Title: "Server Banners Disclose Versions",
		Description: "Strip these headers at the reverse-proxy or app server. Attackers use them to map known CVEs onto your infrastructure.",
		Severity: SeverityLow, Confidence: ConfidenceHigh, Scanner: s.Name(),
		Evidence: strings.Join(leaks, " | "),
		Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 3.7,
	}}, nil
}

func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}
