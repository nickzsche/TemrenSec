package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// MassAssignmentScanner probes JSON endpoints with privileged extra fields.
// It only fires for paths that look like JSON APIs (/api/, /v1/, /rest/...)
// and where the server actually returns JSON. The previous version posted
// to arbitrary HTML pages and substring-matched the HTML body for words
// like "role" or "admin", producing one finding per crawled URL.
type MassAssignmentScanner struct{}

func NewMassAssignmentScanner() *MassAssignmentScanner { return &MassAssignmentScanner{} }

func (s *MassAssignmentScanner) Name() string { return "Mass Assignment / BOLA" }

var massAssignProbes = []map[string]any{
	{"is_admin": true},
	{"role": "admin"},
	{"isAdmin": true},
	{"admin": 1},
	{"verified": true},
	{"approved": true},
	{"balance": 999999},
	{"credits": 999999},
	{"price": 0},
	{"discount": 100},
}

// apiPathPrefixes — path segments that mark a URL as a likely JSON API.
var apiPathPrefixes = []string{
	"/api/", "/api.", "/v1/", "/v2/", "/v3/",
	"/rest/", "/graphql", "/jsonrpc",
}

func looksLikeAPIPath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, prefix := range apiPathPrefixes {
		if strings.Contains(p, prefix) {
			return true
		}
	}
	return false
}

func (s *MassAssignmentScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	// Heuristic gate: only probe paths that smell like an API. Posting
	// JSON to HTML routes burns the budget and trips false positives.
	if !looksLikeAPIPath(target) {
		return nil, nil
	}

	var findings []Finding
	for _, extra := range massAssignProbes {
		buf, _ := json.Marshal(extra)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		// Response must look like JSON. HTML routes that 200-OK any POST
		// (which happens with many SPA frameworks) don't count.
		if !strings.Contains(strings.ToLower(ct), "json") {
			continue
		}
		for k := range extra {
			// Field must appear AS A JSON KEY in the response, not just
			// the literal word. `"role":` is meaningful; "role" in prose
			// is noise.
			needle := `"` + strings.ToLower(k) + `"`
			lowerBody := strings.ToLower(string(body))
			if !strings.Contains(lowerBody, needle+":") {
				continue
			}
			findings = append(findings, Finding{
				URL:           target,
				Title:         "Possible Mass Assignment (" + k + ")",
				Description:   "Endpoint accepted privileged field " + k + " in request body and echoed it back as a JSON key in the response. Manually verify whether the server persisted the field to the entity.",
				Severity:      SeverityHigh,
				Confidence:    ConfidenceLow,
				Payload:       string(buf),
				Evidence:      "field accepted & echoed as JSON key",
				Scanner:       s.Name(),
				Parameter:     k,
				Timestamp:     time.Now(),
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				CVSSScore:     7.5,
			})
		}
	}
	return findings, nil
}
