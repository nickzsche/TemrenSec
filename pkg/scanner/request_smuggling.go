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

// RequestSmugglingScanner detects HTTP Request Smuggling (CL.TE / TE.CL / TE.TE) susceptibility.
type RequestSmugglingScanner struct{}

func NewRequestSmugglingScanner() *RequestSmugglingScanner { return &RequestSmugglingScanner{} }

func (s *RequestSmugglingScanner) Name() string { return "HTTP Request Smuggling" }

func (s *RequestSmugglingScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	probes := []struct {
		label   string
		headers map[string]string
	}{
		{"CL.TE", map[string]string{"Content-Length": "6", "Transfer-Encoding": "chunked"}},
		{"TE.CL", map[string]string{"Transfer-Encoding": "chunked", "Content-Length": "4"}},
		{"TE.TE-obf", map[string]string{"Transfer-Encoding": "chunked", "Transfer-Encoding ": "x"}},
	}

	for _, p := range probes {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("0\r\n\r\nX"))
		if err != nil {
			continue
		}
		for k, v := range p.headers {
			req.Header.Set(k, v)
		}
		start := time.Now()
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		elapsed := time.Since(start)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Heuristics: timeout >5s or 400/408 only on smuggling probe suggests divergent parsing.
		if elapsed > 5*time.Second || resp.StatusCode == 408 || resp.StatusCode == 400 {
			findings = append(findings, Finding{
				URL:           target,
				Title:         fmt.Sprintf("Possible HTTP Request Smuggling (%s)", p.label),
				Description:   "Frontend and backend disagreed about request boundary. This can lead to cache poisoning, session hijacking or auth bypass.",
				Severity:      SeverityHigh,
				Confidence:    ConfidenceLow,
				Payload:       fmt.Sprintf("%v", p.headers),
				Evidence:      fmt.Sprintf("status=%d elapsed=%s", resp.StatusCode, elapsed),
				Scanner:       s.Name(),
				Timestamp:     time.Now(),
				OWASPCategory: "A10:2021-SSRF (boundary parsing)",
				CVSSScore:     7.5,
			})
		}
	}

	return findings, nil
}
