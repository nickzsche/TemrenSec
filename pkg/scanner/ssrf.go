package scanner

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// SSRFScanner detects Server-Side Request Forgery. It uses indicator-based
// detection (internal file/metadata content echoed back) plus a blind
// response-diff heuristic: if the application responds differently when asked
// to fetch a reachable internal endpoint versus an unreachable one, it is
// almost certainly performing the fetch server-side.
type SSRFScanner struct{}

func NewSSRFScanner() *SSRFScanner {
	return &SSRFScanner{}
}

func (s *SSRFScanner) Name() string {
	return "Server-Side Request Forgery (SSRF)"
}

// Scan tests for SSRF.
func (s *SSRFScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	for param := range query {
		orig := query.Get(param)

		if f, ok := s.testIndicatorBased(ctx, client, u, query, param); ok {
			findings = append(findings, f)
			query.Set(param, orig)
			continue
		}

		if f, ok := s.testResponseDiff(ctx, client, u, query, param); ok {
			findings = append(findings, f)
		}

		query.Set(param, orig)
	}

	return findings, nil
}

// testIndicatorBased is the original technique: look for internal resource
// content (passwd, cloud metadata) in the response.
func (s *SSRFScanner) testIndicatorBased(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param string) (Finding, bool) {
	for _, payload := range payloads.SSRF {
		testURL := buildURL(u, query, param, payload)
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		body, _ := readBody(resp)
		resp.Body.Close()

		if s.detectSSRFResponse(string(body), payload) {
			return Finding{
				URL:           testURL,
				Title:         "Server-Side Request Forgery (indicator-based)",
				Description:   "SSRF in parameter '" + param + "': the response contained content from an internal resource.",
				Severity:      SeverityHigh,
				Confidence:    ConfidenceHigh,
				Payload:       payload,
				Evidence:      "Response indicates internal resource access",
				Scanner:       s.Name(),
				Parameter:     param,
				OWASPCategory: "A10:2021-SSRF",
				Timestamp:     time.Now(),
			}, true
		}
	}
	return Finding{}, false
}

// diffPair is a reachable/unreachable internal target used for response-diff.
type diffPair struct {
	reachable   string
	unreachable string
	label       string
}

func ssrfDiffPairs() []diffPair {
	return []diffPair{
		{reachable: "http://127.0.0.1:80/", unreachable: "http://127.0.0.1:1/", label: "loopback:80 vs closed port"},
		{reachable: "http://169.254.169.254/latest/meta-data/", unreachable: "http://240.0.0.1/", label: "cloud metadata vs unroutable"},
	}
}

// testResponseDiff flags blind SSRF when the app answers differently for a
// reachable internal target than for an unreachable one — evidence that the
// fetch happens server-side. A pure reflector (no server-side fetch) returns
// identical responses for both, so this stays quiet on non-vulnerable apps.
func (s *SSRFScanner) testResponseDiff(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param string) (Finding, bool) {
	for _, dp := range ssrfDiffPairs() {
		rLen, rCode, ok1 := fetchLen(ctx, client, buildURL(u, query, param, dp.reachable))
		uLen, uCode, ok2 := fetchLen(ctx, client, buildURL(u, query, param, dp.unreachable))
		if !ok1 || !ok2 {
			continue
		}

		// A meaningful difference in status or body length between reachable
		// and unreachable internal targets indicates server-side fetching.
		if rCode != uCode || !similarLen(rLen, uLen) {
			return Finding{
				URL:           buildURL(u, query, param, dp.reachable),
				Title:         "Server-Side Request Forgery (blind, response-diff)",
				Description:   "Probable blind SSRF in parameter '" + param + "': the application responds differently for a reachable internal target than for an unreachable one (" + dp.label + "), indicating a server-side fetch.",
				Severity:      SeverityHigh,
				Confidence:    ConfidenceMedium,
				Payload:       dp.reachable,
				Evidence:      "reachable → status " + itoa(rCode) + " len " + itoa(rLen) + "; unreachable → status " + itoa(uCode) + " len " + itoa(uLen),
				Scanner:       s.Name(),
				Parameter:     param,
				OWASPCategory: "A10:2021-SSRF",
				Timestamp:     time.Now(),
			}, true
		}
	}
	return Finding{}, false
}

// detectSSRFResponse checks for SSRF indicators.
func (s *SSRFScanner) detectSSRFResponse(body, payload string) bool {
	indicators := []string{
		"root:",
		"/bin/bash",
		"[fonts]",
		"[extensions]",
		"ami-id",
		"instance-id",
		"local-hostname",
		"local-ipv4",
		"computeMetadata",
		"metadata.google",
	}

	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}

	// Note: a blanket "file:// payload + any body = SSRF" rule was removed
	// because it fired on every response and produced false positives. A
	// genuine file read is caught by the content indicators above (e.g.
	// "root:" from /etc/passwd); anything weaker is left to the blind
	// response-diff heuristic.
	_ = payload
	return false
}
