package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// VerificationResult holds the outcome of proof-based verification
type VerificationResult struct {
	Finding    Finding
	Verified   bool
	Proof      string
	Confidence Confidence
	RiskLevel  string
}

// ProofVerifier validates findings by attempting safe exploitation proof
type ProofVerifier struct {
	client  *httpengine.Client
	enabled bool
}

func NewProofVerifier(client *httpengine.Client) *ProofVerifier {
	return &ProofVerifier{
		client:  client,
		enabled: true,
	}
}

// Verify processes all findings and attempts to verify each one
func (pv *ProofVerifier) Verify(ctx context.Context, findings []Finding) []VerificationResult {
	results := make([]VerificationResult, 0, len(findings))

	for _, f := range findings {
		var result VerificationResult

		switch {
		case strings.Contains(strings.ToLower(f.Title), "sql injection") || strings.Contains(strings.ToLower(f.Title), "sqli"):
			result = pv.verifySQLi(ctx, f)
		case strings.Contains(strings.ToLower(f.Title), "xss") || strings.Contains(strings.ToLower(f.Title), "cross-site scripting"):
			result = pv.verifyXSS(ctx, f)
		case strings.Contains(strings.ToLower(f.Title), "ssrf"):
			result = pv.verifySSRF(ctx, f)
		case strings.Contains(strings.ToLower(f.Title), "path traversal") || strings.Contains(strings.ToLower(f.Title), "directory traversal"):
			result = pv.verifyPathTraversal(ctx, f)
		case strings.Contains(strings.ToLower(f.Title), "open redirect"):
			result = pv.verifyOpenRedirect(ctx, f)
		case strings.Contains(strings.ToLower(f.Title), "command injection") || strings.Contains(strings.ToLower(f.Title), "rce"):
			result = pv.verifyCommandInjection(ctx, f)
		default:
			result = VerificationResult{
				Finding:    f,
				Verified:   false,
				Proof:      "No verification strategy available for this finding type",
				Confidence: f.Confidence,
				RiskLevel:  "unverified",
			}
		}

		// Stamp the outcome back onto the embedded finding so a caller that
		// only looks at result.Finding still sees the verification verdict.
		result.Finding.Verified = result.Verified
		result.Finding.Proof = result.Proof
		result.Finding.Confidence = result.Confidence

		results = append(results, result)
	}

	return results
}

// ApplyVerification runs deterministic proof verification against every
// Critical and High severity finding and returns the findings with their
// Verified flag, Proof text and Confidence adjusted:
//
//   - Reproduced with a second request  -> Verified=true, Confidence=HIGH.
//   - A proof strategy exists but failed -> Verified=false, Confidence=LOW
//     (an unproven Critical/High is treated as low confidence, i.e. a likely
//     false positive that a human should review before acting on).
//   - No proof strategy for this type    -> left untouched (these findings are
//     already proven by their own detector, e.g. an exposed secret).
//
// Medium/Low findings are returned unchanged. No LLM is involved; this is
// purely HTTP-level re-testing.
func (pv *ProofVerifier) ApplyVerification(ctx context.Context, findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity != SeverityCritical && f.Severity != SeverityHigh {
			out = append(out, f)
			continue
		}

		res := pv.Verify(ctx, []Finding{f})
		if len(res) == 0 {
			out = append(out, f)
			continue
		}
		r := res[0]

		switch r.RiskLevel {
		case "confirmed":
			f.Verified = true
			f.Proof = r.Proof
			f.Confidence = ConfidenceHigh
		case "likely_false_positive":
			f.Verified = false
			f.Proof = r.Proof
			f.Confidence = ConfidenceLow
		default: // "unverified" — no strategy for this type; leave as-is
			f.Proof = r.Proof
		}
		out = append(out, f)
	}
	return out
}

// verifySQLi confirms SQL injection using time-based and error-based verification
func (pv *ProofVerifier) verifySQLi(ctx context.Context, f Finding) VerificationResult {
	u, err := url.Parse(f.URL)
	if err != nil {
		return unverifiableResult(f, "invalid URL")
	}

	query := u.Query()
	if len(query) == 0 {
		return unverifiableResult(f, "no query parameters")
	}

	sleepPayloads := []string{
		"' OR SLEEP(3)--",
		"'; WAITFOR DELAY '0:0:3'--",
		"' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
	}

	for param := range query {
		for _, payload := range sleepPayloads {
			testQuery := url.Values{}
			for k, v := range query {
				testQuery.Set(k, v[0])
			}
			testQuery.Set(param, payload)

			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			start := time.Now()
			resp, err := pv.client.Get(ctx, testURL)
			elapsed := time.Since(start)

			if err != nil {
				continue
			}
			resp.Body.Close()

			if elapsed >= 3*time.Second {
				return VerificationResult{
					Finding:    f,
					Verified:   true,
					Proof:      fmt.Sprintf("Time-based SQLi confirmed: response delayed %v with SLEEP payload on param '%s'", elapsed.Round(time.Millisecond), param),
					Confidence: ConfidenceHigh,
					RiskLevel:  "confirmed",
				}
			}
		}
	}

	// Active error-based re-test: inject an unbalanced quote and look for a
	// fresh SQL error in the response. This confirms error-based findings that
	// the time-based probe above can't reproduce.
	errSc := &SQLiScanner{}
	for param := range query {
		for _, payload := range []string{"'", "\"", "')", "1'\""} {
			testQuery := url.Values{}
			for k, v := range query {
				testQuery.Set(k, v[0])
			}
			testQuery.Set(param, payload)
			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			resp, err := pv.client.Get(ctx, testURL)
			if err != nil {
				continue
			}
			body, _ := readBody(resp)
			resp.Body.Close()
			if errSc.detectSQLError(string(body)) {
				return VerificationResult{
					Finding:    f,
					Verified:   true,
					Proof:      fmt.Sprintf("Error-based SQLi confirmed: database error reproduced with payload %q on param '%s'", payload, param),
					Confidence: ConfidenceHigh,
					RiskLevel:  "confirmed",
				}
			}
		}
	}

	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "Time-based and error-based verification did not confirm SQLi",
		Confidence: ConfidenceLow,
		RiskLevel:  "likely_false_positive",
	}
}

// verifyXSS confirms XSS by checking if a unique marker is reflected unencoded
func (pv *ProofVerifier) verifyXSS(ctx context.Context, f Finding) VerificationResult {
	u, err := url.Parse(f.URL)
	if err != nil {
		return unverifiableResult(f, "invalid URL")
	}

	query := u.Query()
	if len(query) == 0 {
		return unverifiableResult(f, "no query parameters")
	}

	marker := fmt.Sprintf("temren-verify-%08x", rand.Int31())

	for param := range query {
		testQuery := url.Values{}
		for k, v := range query {
			testQuery.Set(k, v[0])
		}
		testQuery.Set(param, marker)

		testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

		resp, err := pv.client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		body, _ := readBody(resp)
		resp.Body.Close()

		bodyStr := string(body)
		if strings.Contains(bodyStr, marker) {
			encoded := strings.Contains(bodyStr, "&lt;"+marker) ||
				strings.Contains(bodyStr, "u003c"+marker) ||
				strings.Contains(bodyStr, "%3C"+marker)

			if !encoded {
				return VerificationResult{
					Finding:    f,
					Verified:   true,
					Proof:      fmt.Sprintf("XSS confirmed: unique marker reflected unencoded in param '%s'", param),
					Confidence: ConfidenceHigh,
					RiskLevel:  "confirmed",
				}
			}
		}
	}

	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "XSS marker was not reflected or was properly encoded",
		Confidence: ConfidenceLow,
		RiskLevel:  "likely_false_positive",
	}
}

// verifySSRF confirms SSRF by checking for internal resource content indicators
func (pv *ProofVerifier) verifySSRF(ctx context.Context, f Finding) VerificationResult {
	u, err := url.Parse(f.URL)
	if err != nil {
		return unverifiableResult(f, "invalid URL")
	}

	query := u.Query()
	if len(query) == 0 {
		return unverifiableResult(f, "no query parameters")
	}

	internalIndicators := []string{
		"127.0.0.1",
		"localhost",
		"169.254.169.254",
		"metadata.google.internal",
	}

	for param := range query {
		for _, indicator := range internalIndicators {
			testQuery := url.Values{}
			for k, v := range query {
				testQuery.Set(k, v[0])
			}
			testQuery.Set(param, indicator)

			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			resp, err := pv.client.Get(ctx, testURL)
			if err != nil {
				continue
			}
			body, _ := readBody(resp)
			resp.Body.Close()

			bodyStr := string(body)
			metadataIndicators := []string{
				"ami-id", "instance-id", "hostname",
				"iam", "security-credentials",
				"meta-data", "user-data",
			}

			for _, md := range metadataIndicators {
				if strings.Contains(strings.ToLower(bodyStr), md) {
					return VerificationResult{
						Finding:    f,
						Verified:   true,
						Proof:      fmt.Sprintf("SSRF confirmed: internal resource content indicator '%s' found when probing param '%s'", md, param),
						Confidence: ConfidenceHigh,
						RiskLevel:  "confirmed",
					}
				}
			}
		}
	}

	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "SSRF verification did not confirm internal resource access",
		Confidence: ConfidenceLow,
		RiskLevel:  "likely_false_positive",
	}
}

// verifyPathTraversal confirms path traversal by checking for known file content
func (pv *ProofVerifier) verifyPathTraversal(ctx context.Context, f Finding) VerificationResult {
	u, err := url.Parse(f.URL)
	if err != nil {
		return unverifiableResult(f, "invalid URL")
	}

	query := u.Query()
	if len(query) == 0 {
		return unverifiableResult(f, "no query parameters")
	}

	traversalPayloads := map[string][]string{
		"../../etc/passwd":              {"root:", "/bin/bash", "/bin/sh"},
		"..\\" + "..\\windows\\win.ini": {"[fonts]", "[extensions]", "[files]"},
		"....//....//etc/passwd":        {"root:", "/bin/bash"},
	}

	for param := range query {
		for payload, indicators := range traversalPayloads {
			testQuery := url.Values{}
			for k, v := range query {
				testQuery.Set(k, v[0])
			}
			testQuery.Set(param, payload)

			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			resp, err := pv.client.Get(ctx, testURL)
			if err != nil {
				continue
			}
			body, _ := readBody(resp)
			resp.Body.Close()

			bodyStr := string(body)
			for _, indicator := range indicators {
				if strings.Contains(bodyStr, indicator) {
					maskedContent := maskFileContent(bodyStr)
					return VerificationResult{
						Finding:    f,
						Verified:   true,
						Proof:      fmt.Sprintf("Path traversal confirmed: file content indicator '%s' found via param '%s'. Content: %s", indicator, param, maskedContent),
						Confidence: ConfidenceHigh,
						RiskLevel:  "confirmed",
					}
				}
			}
		}
	}

	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "Path traversal verification did not confirm file access",
		Confidence: ConfidenceLow,
		RiskLevel:  "likely_false_positive",
	}
}

// verifyOpenRedirect confirms open redirect by checking actual redirect behavior
func (pv *ProofVerifier) verifyOpenRedirect(ctx context.Context, f Finding) VerificationResult {
	u, err := url.Parse(f.URL)
	if err != nil {
		return unverifiableResult(f, "invalid URL")
	}

	query := u.Query()
	if len(query) == 0 {
		return unverifiableResult(f, "no query parameters")
	}

	testDomain := "https://temren-verify-test.example.com"

	for param := range query {
		testQuery := url.Values{}
		for k, v := range query {
			testQuery.Set(k, v[0])
		}
		testQuery.Set(param, testDomain)

		testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}

		resp, err := pv.client.Do(ctx, req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if strings.HasPrefix(location, testDomain) {
				return VerificationResult{
					Finding:    f,
					Verified:   true,
					Proof:      fmt.Sprintf("Open redirect confirmed: redirect to test domain via param '%s' (Location: %s)", param, maskURL(location)),
					Confidence: ConfidenceHigh,
					RiskLevel:  "confirmed",
				}
			}
		}
	}

	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "Open redirect verification did not confirm redirect to external domain",
		Confidence: ConfidenceLow,
		RiskLevel:  "likely_false_positive",
	}
}

// verifyCommandInjection confirms command injection using time-based verification
func (pv *ProofVerifier) verifyCommandInjection(ctx context.Context, f Finding) VerificationResult {
	u, err := url.Parse(f.URL)
	if err != nil {
		return unverifiableResult(f, "invalid URL")
	}

	query := u.Query()
	if len(query) == 0 {
		return unverifiableResult(f, "no query parameters")
	}

	timePayloads := []string{
		"; sleep 3",
		"| sleep 3",
		"`sleep 3`",
		"& timeout 3",
	}

	for param := range query {
		for _, payload := range timePayloads {
			testQuery := url.Values{}
			for k, v := range query {
				testQuery.Set(k, v[0])
			}
			testQuery.Set(param, payload)

			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			start := time.Now()
			resp, err := pv.client.Get(ctx, testURL)
			elapsed := time.Since(start)

			if err != nil {
				continue
			}
			resp.Body.Close()

			if elapsed >= 3*time.Second {
				return VerificationResult{
					Finding:    f,
					Verified:   true,
					Proof:      fmt.Sprintf("Command injection confirmed: response delayed %v with sleep payload on param '%s'", elapsed.Round(time.Millisecond), param),
					Confidence: ConfidenceHigh,
					RiskLevel:  "confirmed",
				}
			}
		}
	}

	// Output-based re-test: inject a command whose output is recognizable and
	// confirm it appears in the response. Covers output-based findings the
	// time-based probe can't reproduce.
	cmdSc := &CommandInjectionScanner{}
	for param := range query {
		for _, payload := range []string{"; id", "| id", "& whoami", "`id`", "$(id)"} {
			testQuery := url.Values{}
			for k, v := range query {
				testQuery.Set(k, v[0])
			}
			testQuery.Set(param, payload)
			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			resp, err := pv.client.Get(ctx, testURL)
			if err != nil {
				continue
			}
			body, _ := readBody(resp)
			resp.Body.Close()
			if cmdSc.detectCommandOutput(string(body)) {
				return VerificationResult{
					Finding:    f,
					Verified:   true,
					Proof:      fmt.Sprintf("Command injection confirmed: command output reproduced with payload %q on param '%s'", payload, param),
					Confidence: ConfidenceHigh,
					RiskLevel:  "confirmed",
				}
			}
		}
	}

	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "Command injection verification did not confirm execution",
		Confidence: ConfidenceLow,
		RiskLevel:  "likely_false_positive",
	}
}

// unverifiableResult creates a result for findings that cannot be verified
func unverifiableResult(f Finding, reason string) VerificationResult {
	return VerificationResult{
		Finding:    f,
		Verified:   false,
		Proof:      "Cannot verify: " + reason,
		Confidence: f.Confidence,
		RiskLevel:  "unverified",
	}
}

// maskFileContent masks sensitive content from file reads (e.g., /etc/passwd)
func maskFileContent(content string) string {
	lines := strings.Split(content, "\n")
	masked := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 2 {
				masked = append(masked, parts[0]+":***:"+strings.Repeat("*", len(parts[1])))
			} else {
				masked = append(masked, "***")
			}
		} else {
			if len(line) > 20 {
				masked = append(masked, line[:10]+"***"+line[len(line)-5:])
			} else {
				masked = append(masked, "***")
			}
		}
	}
	return strings.Join(masked, "\n")
}

// maskURL masks sensitive parts of URLs in proof output
func maskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	result := u.String()
	result = strings.ReplaceAll(result, "%2A%2A%2A", "***")
	return result
}
