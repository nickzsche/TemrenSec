package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// XSSScanner detects reflected Cross-Site Scripting.
//
// Detection is nonce-based: each payload carries a random marker, and a finding
// is only reported when that exact marker comes back unencoded, inside markup
// the browser would execute. Two earlier behaviours are deliberately gone:
//
//   - matching a fixed list of indicators ("<script>alert", "onerror=alert")
//     anywhere in the body, regardless of whether the payload caused them. Any
//     page that merely contained such text — a WAF block page echoing the
//     attack, a security tutorial, a JS bundle — produced a finding for every
//     parameter tested;
//   - treating plain reflection as proof. Reflected text that comes back
//     HTML-encoded is the server behaving correctly, not a vulnerability.
type XSSScanner struct{}

func NewXSSScanner() *XSSScanner {
	return &XSSScanner{}
}

func (s *XSSScanner) Name() string {
	return "Cross-Site Scripting (XSS)"
}

func (s *XSSScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		if f, ok := s.testParam(ctx, client, u, query, param); ok {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func (s *XSSScanner) testParam(
	ctx context.Context,
	client *httpengine.Client,
	u *url.URL,
	query url.Values,
	param string,
) (Finding, bool) {
	for _, template := range payloads.XSS {
		nonce := newNonce()
		payload := markPayload(template, nonce)

		testURL := buildTestURL(u, query, param, payload)

		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		body, _ := readBody(resp)
		resp.Body.Close()

		where, ok := s.executableReflection(payload, nonce, string(body))
		if !ok {
			continue
		}

		return Finding{
			URL:         testURL,
			Title:       "Reflected XSS",
			Description: "Parameter " + param + " is reflected into the response without encoding",
			Severity:    SeverityHigh,
			Confidence:  ConfidenceHigh,
			Payload:     payload,
			Evidence: "The injected marker " + quote(nonce) + " was returned unencoded " + where +
				". Only this request's marker is matched, so the reflection is attributable to the payload.",
			Scanner:   s.Name(),
			Timestamp: time.Now(),
		}, true
	}
	return Finding{}, false
}

// executableReflection reports whether the payload came back in a form a
// browser would act on, and describes where.
func (s *XSSScanner) executableReflection(payload, nonce, body string) (string, bool) {
	// The marker must be present at all — if the server dropped or encoded it,
	// there is nothing to report.
	if !strings.Contains(body, nonce) {
		return "", false
	}

	// The full payload surviving verbatim means no encoding was applied.
	if strings.Contains(body, payload) {
		return "as part of the complete injected payload", true
	}

	// Otherwise the marker survived but the payload was altered. Only treat it
	// as executable if the characters that make markup dangerous also survived
	// next to the marker.
	idx := strings.Index(body, nonce)
	window := body[max(0, idx-120):min(len(body), idx+len(nonce)+120)]

	switch {
	case strings.Contains(window, "<script") && !isEncoded(window):
		return "inside a <script> element", true
	case containsEventHandler(window) && !isEncoded(window):
		return "inside an event-handler attribute", true
	case strings.Contains(window, "javascript:") && !isEncoded(window):
		return "inside a javascript: URL", true
	}

	return "", false
}

// isEncoded reports whether the surrounding markup shows the angle brackets and
// quotes were escaped — the sign that the server is encoding output correctly.
func isEncoded(window string) bool {
	return strings.Contains(window, "&lt;") ||
		strings.Contains(window, "&gt;") ||
		strings.Contains(window, "&quot;") ||
		strings.Contains(window, "&#x27;") ||
		strings.Contains(window, "&#39;")
}

func containsEventHandler(window string) bool {
	lower := strings.ToLower(window)
	for _, h := range []string{
		"onerror=", "onload=", "onfocus=", "onmouseover=", "onclick=",
		"onanimationstart=", "ontoggle=", "onstart=",
	} {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// markPayload injects the nonce into a payload template so the reflection can be
// attributed to this specific request.
func markPayload(template, nonce string) string {
	switch {
	case strings.Contains(template, "alert(1)"):
		return strings.Replace(template, "alert(1)", "alert('"+nonce+"')", 1)
	case strings.Contains(template, "alert('XSS')"):
		return strings.Replace(template, "alert('XSS')", "alert('"+nonce+"')", 1)
	default:
		return template + nonce
	}
}

func newNonce() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "tmrn0000nonce"
	}
	return "tmrn" + hex.EncodeToString(b)
}

// isPayloadReflected reports whether a payload was reflected in a way a browser
// would execute. Retained for callers without a per-request nonce; it derives
// one from the payload itself.
func (s *XSSScanner) isPayloadReflected(payload, body string) bool {
	_, ok := s.executableReflection(payload, payload, body)
	return ok
}
