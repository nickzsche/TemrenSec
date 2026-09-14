package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// ServerSidePrototypePollutionScanner pollutes Object.prototype via JSON merge endpoints
// and looks for canary-key reflection.
type ServerSidePrototypePollutionScanner struct{}

func NewServerSidePrototypePollutionScanner() *ServerSidePrototypePollutionScanner {
	return &ServerSidePrototypePollutionScanner{}
}

func (s *ServerSidePrototypePollutionScanner) Name() string { return "Server-Side Prototype Pollution" }

func (s *ServerSidePrototypePollutionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	canary := "temren_canary_" + time.Now().UTC().Format("150405")
	payloads := []map[string]any{
		{"__proto__": map[string]string{canary: "1"}},
		{"constructor": map[string]any{"prototype": map[string]string{canary: "1"}}},
		{"__proto__.toString": canary},
	}
	var findings []Finding
	for _, p := range payloads {
		buf, _ := json.Marshal(p)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if strings.Contains(string(body), canary) {
			findings = append(findings, Finding{
				URL: target, Title: "Server-Side Prototype Pollution",
				Description: "Endpoint merged untrusted JSON into a shared object; injected property leaked into the response. Attackers can shape downstream object lookups and frequently chain this to RCE in Node.js.",
				Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Payload: string(buf), Evidence: "canary echoed",
				Timestamp: time.Now(), OWASPCategory: "A08:2021-Software and Data Integrity Failures", CVSSScore: 8.1,
			})
			return findings, nil
		}
	}
	return findings, nil
}
