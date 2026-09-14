package scanner

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// ETagLeakScanner flags weak ETags that embed inode numbers (Apache mod_etag default),
// which leak server-local filesystem identity.
type ETagLeakScanner struct{}

func NewETagLeakScanner() *ETagLeakScanner { return &ETagLeakScanner{} }

func (s *ETagLeakScanner) Name() string { return "ETag Inode Leak" }

func (s *ETagLeakScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	etag := resp.Header.Get("ETag")
	resp.Body.Close()
	if etag == "" {
		return nil, nil
	}
	// Apache default looks like "12345-67890-abcd1234" (inode-size-mtime)
	parts := strings.Split(strings.Trim(etag, "\""), "-")
	if len(parts) >= 3 && allDigits(parts[0]) && allDigits(parts[1]) {
		return []Finding{{
			URL: target, Title: "ETag Leaks Server Inode",
			Description: "Default Apache ETag format embeds the file inode and size. Useful to attackers in clustered or NFS environments to fingerprint storage layout.",
			Severity: SeverityLow, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Evidence: etag, Timestamp: time.Now(),
			OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 3.7,
		}}, nil
	}
	return nil, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
