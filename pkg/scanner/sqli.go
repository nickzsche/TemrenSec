package scanner

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// SQLiScanner detects SQL injection vulnerabilities.
//
// Two independent signals, both compared against the parameter's unmodified
// response rather than judged in isolation:
//
//   - error-based: a database error signature that appears only after the
//     payload is injected;
//   - time-based: a response that is reliably slower with a sleep payload, and
//     is not slow without one.
//
// The baseline comparison is the important part. Matching signatures anywhere
// in the body meant any page that merely mentioned a database — docs, a stack
// listing, a "powered by" footer — was reported as a critical finding at high
// confidence.
type SQLiScanner struct{}

func NewSQLiScanner() *SQLiScanner {
	return &SQLiScanner{}
}

func (s *SQLiScanner) Name() string {
	return "SQL Injection"
}

// sleepSeconds is what the time-based payloads below ask the database to wait.
const sleepSeconds = 5

// timeBasedPayloads are kept separate from the error-based set: they are judged
// by latency, not by body content.
var timeBasedPayloads = []string{
	"' AND SLEEP(5)--",
	"1 AND SLEEP(5)--",
	"'; WAITFOR DELAY '0:0:5'--",
	"' AND pg_sleep(5)--",
}

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

	// One baseline fetch for the whole URL: what this endpoint looks like when
	// nothing is injected.
	baselineBody, baselineLatency, err := s.probe(ctx, client, target)
	if err != nil {
		// Without a baseline every comparison below is guesswork, so stop
		// rather than fall back to matching raw strings.
		return findings, nil
	}
	baselineErrors := detectSQLErrors(baselineBody)

	for param := range query {
		if f, ok := s.testErrorBased(ctx, client, u, query, param, baselineErrors); ok {
			findings = append(findings, f)
			continue
		}
		if f, ok := s.testTimeBased(ctx, client, u, query, param, baselineLatency); ok {
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func (s *SQLiScanner) testErrorBased(
	ctx context.Context,
	client *httpengine.Client,
	u *url.URL,
	query url.Values,
	param string,
	baselineErrors map[string]bool,
) (Finding, bool) {
	for _, payload := range payloads.SQLInjection {
		if isTimeBasedPayload(payload) {
			continue // judged by latency, not body content
		}

		testURL := buildTestURL(u, query, param, payload)
		body, _, err := s.probe(ctx, client, testURL)
		if err != nil {
			continue
		}

		// Only signatures the baseline did not already contain count.
		for _, sig := range detectSQLErrorList(body) {
			if baselineErrors[sig] {
				continue
			}
			return Finding{
				URL:         testURL,
				Title:       "SQL Injection",
				Description: "Database error disclosed after injecting into parameter: " + param,
				Severity:    SeverityCritical,
				Confidence:  ConfidenceHigh,
				Payload:     payload,
				Evidence: "Response contains the database error signature " + quote(sig) +
					", which is absent from the unmodified response for the same URL.",
				Scanner:   s.Name(),
				Timestamp: time.Now(),
			}, true
		}
	}
	return Finding{}, false
}

// testTimeBased confirms a delay is caused by the payload and is reproducible.
//
// A single slow response proves nothing — servers are occasionally slow. This
// requires the injected request to exceed the baseline by most of the requested
// sleep, then repeats the measurement before reporting.
func (s *SQLiScanner) testTimeBased(
	ctx context.Context,
	client *httpengine.Client,
	u *url.URL,
	query url.Values,
	param string,
	baselineLatency time.Duration,
) (Finding, bool) {
	// Require most of the requested sleep, leaving room for a database that
	// rounds down or a payload that only partially executes.
	threshold := sleepSeconds * time.Second * 7 / 10

	for _, payload := range timeBasedPayloads {
		testURL := buildTestURL(u, query, param, payload)

		if _, elapsed, err := s.probe(ctx, client, testURL); err != nil || elapsed-baselineLatency < threshold {
			continue
		}

		// Re-measure the baseline and the payload; a one-off spike must not be
		// enough to report a critical finding.
		_, baseAgain, err := s.probe(ctx, client, u.String())
		if err != nil {
			continue
		}
		_, elapsedAgain, err := s.probe(ctx, client, testURL)
		if err != nil || elapsedAgain-baseAgain < threshold {
			continue
		}

		return Finding{
			URL:         testURL,
			Title:       "SQL Injection (time-based blind)",
			Description: "Injecting a sleep into parameter " + param + " reproducibly delays the response",
			Severity:    SeverityCritical,
			Confidence:  ConfidenceMedium,
			Payload:     payload,
			Evidence: "Baseline responded in " + baseAgain.Round(time.Millisecond).String() +
				"; with the payload it took " + elapsedAgain.Round(time.Millisecond).String() +
				" across two independent measurements.",
			Scanner:   s.Name(),
			Timestamp: time.Now(),
		}, true
	}
	return Finding{}, false
}

// probe fetches a URL and reports its body and wall-clock latency.
func (s *SQLiScanner) probe(ctx context.Context, client *httpengine.Client, target string) ([]byte, time.Duration, error) {
	start := time.Now()
	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, 0, err
	}
	body, _ := readBody(resp)
	elapsed := time.Since(start)
	resp.Body.Close()
	return body, elapsed, nil
}

func buildTestURL(u *url.URL, query url.Values, param, payload string) string {
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

func isTimeBasedPayload(payload string) bool {
	lower := strings.ToLower(payload)
	return strings.Contains(lower, "sleep") ||
		strings.Contains(lower, "waitfor") ||
		strings.Contains(lower, "benchmark") ||
		strings.Contains(lower, "pg_sleep")
}

// sqlErrorSignatures are strings that only a database error page produces.
//
// Deliberately excluded: bare product names ("postgresql", "mysql"), and
// generic phrases such as "syntax error" or "SQL error". Those appear on
// ordinary pages — documentation, blog posts, JavaScript error output — and
// were the single largest source of false positives.
var sqlErrorSignatures = []string{
	"you have an error in your sql syntax",
	"warning: mysql_",
	"mysql_fetch_array()",
	"mysql_fetch_assoc()",
	"mysql_num_rows()",
	"valid mysql result",
	"mysqli_fetch",
	"mysqlclient.",
	"com.mysql.jdbc.exceptions",
	"unclosed quotation mark after the character string",
	"incorrect syntax near",
	"microsoft ole db provider for sql server",
	"unterminated quoted string at or near",
	"pg_query()",
	"pg_exec()",
	"warning: pg_",
	"org.postgresql.util.psqlexception",
	"quoted string not properly terminated",
	"ora-00933",
	"ora-01756",
	"ora-00921",
	"oracle error",
	"sqlite3.operationalerror",
	"sqlite_error",
	"sqlite3::",
	"sqlstate[",
	"java.sql.sqlexception",
	"system.data.sqlclient.sqlexception",
	"psycopg2.errors",
	"sqlalchemy.exc",
}

func detectSQLErrorList(body []byte) []string {
	lower := strings.ToLower(string(body))
	var hits []string
	for _, sig := range sqlErrorSignatures {
		if strings.Contains(lower, sig) {
			hits = append(hits, sig)
		}
	}
	sort.Strings(hits)
	return hits
}

func detectSQLErrors(body []byte) map[string]bool {
	out := map[string]bool{}
	for _, sig := range detectSQLErrorList(body) {
		out[sig] = true
	}
	return out
}

// detectSQLError reports whether the body contains any database error
// signature. Retained for callers that have no baseline to compare against.
func (s *SQLiScanner) detectSQLError(body string) bool {
	return len(detectSQLErrorList([]byte(body))) > 0
}

func quote(s string) string { return "\"" + s + "\"" }
