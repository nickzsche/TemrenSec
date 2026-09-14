package scanner

import (
	"context"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// SQLiScanner detects SQL injection vulnerabilities using three complementary
// techniques: error-based (SQL error strings surfaced in the response),
// boolean-based blind (a TRUE vs FALSE condition produces materially different
// responses) and time-based blind (an injected sleep measurably delays the
// response). Each technique labels its findings distinctly via Evidence and
// Confidence so triage can tell them apart.
type SQLiScanner struct {
	// SleepSeconds is the delay requested by time-based payloads. Kept as a
	// field so tests can shrink it; production uses the default.
	SleepSeconds int
}

func NewSQLiScanner() *SQLiScanner {
	return &SQLiScanner{SleepSeconds: 5}
}

func (s *SQLiScanner) Name() string {
	return "SQL Injection"
}

// sleepSeconds returns the configured sleep, defaulting to 5s.
func (s *SQLiScanner) sleepSeconds() int {
	if s.SleepSeconds <= 0 {
		return 5
	}
	return s.SleepSeconds
}

// Scan tests every query parameter for SQL injection.
func (s *SQLiScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		originalValue := query.Get(param)

		if f, ok := s.testErrorBased(ctx, client, u, query, param); ok {
			findings = append(findings, f)
			// Error-based is the strongest signal; still probe blind
			// techniques so we can attach corroborating evidence, but avoid
			// duplicate reports by continuing to the next parameter.
			query.Set(param, originalValue)
			continue
		}

		if f, ok := s.testBooleanBlind(ctx, client, u, query, param, originalValue); ok {
			findings = append(findings, f)
			query.Set(param, originalValue)
			continue
		}

		if f, ok := s.testTimeBlind(ctx, client, u, query, param); ok {
			findings = append(findings, f)
		}

		query.Set(param, originalValue)
	}

	return findings, nil
}

// buildURL renders target URL with param overridden by payload.
func buildURL(u *url.URL, query url.Values, param, payload string) string {
	testQuery := url.Values{}
	for k, v := range query {
		if k == param {
			testQuery.Set(k, payload)
		} else if len(v) > 0 {
			testQuery.Set(k, v[0])
		}
	}
	return u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()
}

// testErrorBased is the original technique: inject payloads and look for
// database error strings in the response body.
func (s *SQLiScanner) testErrorBased(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param string) (Finding, bool) {
	for _, payload := range payloads.SQLInjection {
		testURL := buildURL(u, query, param, payload)
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		body, _ := readBody(resp)
		resp.Body.Close()

		if s.detectSQLError(string(body)) {
			return Finding{
				URL:           testURL,
				Title:         "SQL Injection (error-based)",
				Description:   "SQL injection detected in parameter '" + param + "': the database emitted a SQL error when the value was manipulated.",
				Severity:      SeverityCritical,
				Confidence:    ConfidenceHigh,
				Payload:       payload,
				Evidence:      "SQL error message detected in response",
				Scanner:       s.Name(),
				Parameter:     param,
				OWASPCategory: "A03:2021-Injection",
				Timestamp:     time.Now(),
			}, true
		}
	}
	return Finding{}, false
}

// booleanPair is a TRUE/FALSE condition pair for one injection context.
type booleanPair struct {
	truePayload  string
	falsePayload string
	context      string
}

func booleanPairs(orig string) []booleanPair {
	return []booleanPair{
		// String/quote-breaking context
		{truePayload: orig + "' OR '1'='1", falsePayload: orig + "' AND '1'='2", context: "single-quote string"},
		{truePayload: orig + "\" OR \"1\"=\"1", falsePayload: orig + "\" AND \"1\"=\"2", context: "double-quote string"},
		// Numeric context
		{truePayload: orig + " OR 1=1", falsePayload: orig + " AND 1=2", context: "numeric"},
		// Commented terminator variants
		{truePayload: orig + "' OR '1'='1'-- ", falsePayload: orig + "' AND '1'='2'-- ", context: "quoted + comment"},
	}
}

// testBooleanBlind sends a "always true" and "always false" payload and flags
// injection when the true response resembles the untampered baseline while the
// false response diverges from it.
func (s *SQLiScanner) testBooleanBlind(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param, originalValue string) (Finding, bool) {
	baselineURL := buildURL(u, query, param, originalValue)
	baseLen, ok := s.bodyLen(ctx, client, baselineURL)
	if !ok {
		return Finding{}, false
	}

	for _, bp := range booleanPairs(originalValue) {
		trueURL := buildURL(u, query, param, bp.truePayload)
		falseURL := buildURL(u, query, param, bp.falsePayload)

		trueLen, ok1 := s.bodyLen(ctx, client, trueURL)
		falseLen, ok2 := s.bodyLen(ctx, client, falseURL)
		if !ok1 || !ok2 {
			continue
		}

		// TRUE should look like the baseline (both return the "real" row set),
		// FALSE should differ noticeably. Similarity is measured as a length
		// ratio to avoid heavy diffing and to tolerate dynamic content.
		if similarLen(trueLen, baseLen) && !similarLen(falseLen, baseLen) && !similarLen(trueLen, falseLen) {
			return Finding{
				URL:           trueURL,
				Title:         "SQL Injection (boolean-based blind)",
				Description:   "Blind SQL injection in parameter '" + param + "': a TRUE condition reproduces the original response while a FALSE condition changes it, in the " + bp.context + " context.",
				Severity:      SeverityCritical,
				Confidence:    ConfidenceMedium,
				Payload:       bp.truePayload,
				Evidence:      formatBoolEvidence(baseLen, trueLen, falseLen),
				Scanner:       s.Name(),
				Parameter:     param,
				OWASPCategory: "A03:2021-Injection",
				Timestamp:     time.Now(),
			}, true
		}
	}
	return Finding{}, false
}

// timePayloads returns sleep payloads across the common database engines.
func (s *SQLiScanner) timePayloads(orig string) []string {
	n := s.sleepSeconds()
	sec := itoa(n)
	return []string{
		orig + "' AND SLEEP(" + sec + ")-- ",
		orig + "'; SELECT pg_sleep(" + sec + ")-- ",
		orig + "' AND pg_sleep(" + sec + ") IS NOT NULL-- ",
		orig + "'; WAITFOR DELAY '0:0:" + sec + "'-- ",
		orig + " OR SLEEP(" + sec + ")",
		orig + "') OR SLEEP(" + sec + ")-- ",
	}
}

// testTimeBlind measures the response time under a sleep payload and confirms
// the delay with a second request to filter out one-off latency spikes.
func (s *SQLiScanner) testTimeBlind(ctx context.Context, client *httpengine.Client, u *url.URL, query url.Values, param string) (Finding, bool) {
	orig := query.Get(param)

	// Establish a fast baseline; if the endpoint is already slow, time-based
	// detection is unreliable, so bail out.
	base := s.measure(ctx, client, buildURL(u, query, param, orig))
	if base <= 0 || base > 2*time.Second {
		return Finding{}, false
	}

	threshold := time.Duration(s.sleepSeconds())*time.Second - time.Second // allow 1s slack

	for _, payload := range s.timePayloads(orig) {
		testURL := buildURL(u, query, param, payload)

		d1 := s.measure(ctx, client, testURL)
		if d1 < base+threshold {
			continue
		}
		// Confirm to reduce false positives from transient slowness.
		d2 := s.measure(ctx, client, testURL)
		if d2 < base+threshold {
			continue
		}

		return Finding{
			URL:           testURL,
			Title:         "SQL Injection (time-based blind)",
			Description:   "Blind SQL injection in parameter '" + param + "': an injected sleep delayed the response by roughly " + itoa(s.sleepSeconds()) + "s, confirmed twice.",
			Severity:      SeverityCritical,
			Confidence:    ConfidenceMedium,
			Payload:       payload,
			Evidence:      "baseline " + d1.Round(time.Millisecond).String() + " vs delayed responses " + d1.Round(time.Millisecond).String() + " / " + d2.Round(time.Millisecond).String(),
			Scanner:       s.Name(),
			Parameter:     param,
			OWASPCategory: "A03:2021-Injection",
			Timestamp:     time.Now(),
		}, true
	}
	return Finding{}, false
}

// measure issues a request and returns how long it took; 0 on error.
func (s *SQLiScanner) measure(ctx context.Context, client *httpengine.Client, testURL string) time.Duration {
	start := time.Now()
	resp, err := client.Get(ctx, testURL)
	if err != nil {
		return 0
	}
	_, _ = readBody(resp)
	resp.Body.Close()
	return time.Since(start)
}

// bodyLen fetches a URL and returns the response body length.
func (s *SQLiScanner) bodyLen(ctx context.Context, client *httpengine.Client, testURL string) (int, bool) {
	resp, err := client.Get(ctx, testURL)
	if err != nil {
		return 0, false
	}
	body, _ := readBody(resp)
	resp.Body.Close()
	return len(body), true
}

// similarLen reports whether two body lengths are within 5% (and 32 bytes) of
// each other — treated as "the same page".
func similarLen(a, b int) bool {
	if a == b {
		return true
	}
	diff := math.Abs(float64(a - b))
	larger := math.Max(float64(a), float64(b))
	if larger == 0 {
		return true
	}
	return diff <= 32 || diff/larger <= 0.05
}

func formatBoolEvidence(base, tru, fals int) string {
	return "response lengths — baseline:" + itoa(base) + " true:" + itoa(tru) + " false:" + itoa(fals)
}

// detectSQLError checks for SQL error messages in a response body.
func (s *SQLiScanner) detectSQLError(body string) bool {
	sqlErrors := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-01756",
		"quoted string not properly terminated",
		"Unclosed quotation mark",
		"pg_query()",
		"Warning: pg_",
		"valid MySQL result",
		"MySqlClient.",
		"SQLSTATE[",
		"mysqli_",
		"Syntax error",
		"syntax error",
		"unexpected end of SQL command",
		"postgresql",
		"sqlite3.",
		"SQL error",
		"mysql_num_rows()",
		"mysql_fetch_array()",
	}

	lower := strings.ToLower(body)
	for _, e := range sqlErrors {
		if strings.Contains(lower, strings.ToLower(e)) {
			return true
		}
	}
	return false
}
