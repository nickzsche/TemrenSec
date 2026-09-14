package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// ExposedEndpointsScanner probes for common admin/debug/source-control surface that should never be public.
type ExposedEndpointsScanner struct{}

func NewExposedEndpointsScanner() *ExposedEndpointsScanner { return &ExposedEndpointsScanner{} }

func (s *ExposedEndpointsScanner) Name() string { return "Exposed Sensitive Endpoints" }

type endpointProbe struct {
	path     string
	contains string
	title    string
	sev      Severity
	score    float64
	owasp    string
	desc     string
}

var exposedEndpoints = []endpointProbe{
	{"/.git/HEAD", "ref:", "Exposed .git directory", SeverityCritical, 9.8, "A05:2021-Security Misconfiguration", "Source code reconstructable via git-dumper."},
	{"/.env", "=", "Exposed .env file", SeverityCritical, 9.8, "A02:2021-Cryptographic Failures", "Environment file likely contains credentials."},
	{"/.svn/entries", "", "Exposed .svn directory", SeverityHigh, 8.6, "A05:2021-Security Misconfiguration", "Subversion metadata exposes source tree."},
	{"/.DS_Store", "Bud1", "Exposed .DS_Store", SeverityLow, 3.7, "A05:2021-Security Misconfiguration", "macOS metadata leaks file/directory names."},
	{"/server-status", "Apache Server Status", "Apache mod_status exposed", SeverityHigh, 7.5, "A05:2021-Security Misconfiguration", "Reveals all active requests and clients."},
	{"/server-info", "Apache Server Information", "Apache mod_info exposed", SeverityMedium, 6.5, "A05:2021-Security Misconfiguration", "Full server configuration leaked."},
	{"/phpinfo.php", "phpinfo()", "phpinfo() exposed", SeverityHigh, 7.5, "A05:2021-Security Misconfiguration", "Full PHP environment, paths, modules leaked."},
	{"/wp-config.php.bak", "DB_PASSWORD", "WordPress config backup", SeverityCritical, 9.8, "A02:2021-Cryptographic Failures", "Database credentials in backup."},
	{"/actuator", "_links", "Spring Boot Actuator exposed", SeverityCritical, 9.1, "A05:2021-Security Misconfiguration", "Actuator endpoints can leak env, dump heap, even achieve RCE via jolokia/env."},
	{"/actuator/env", "spring.application", "Actuator /env exposed", SeverityCritical, 9.1, "A05:2021-Security Misconfiguration", "Environment includes secrets."},
	{"/actuator/heapdump", "JFIF", "Actuator /heapdump exposed", SeverityCritical, 9.8, "A05:2021-Security Misconfiguration", "Heap may contain credentials and session tokens."},
	{"/debug/pprof/", "/debug/pprof/", "Go pprof exposed", SeverityMedium, 6.5, "A05:2021-Security Misconfiguration", "pprof exposes runtime details — useful for DoS and reverse engineering."},
	{"/metrics", "# HELP", "Prometheus /metrics exposed", SeverityLow, 4.3, "A09:2021-Security Logging Failures", "Internal metrics are public. Consider authentication."},
	{"/swagger.json", "swagger", "Swagger spec exposed", SeverityLow, 3.7, "A09:2021-Security Logging Failures", "API surface is documented — consider whether intended."},
	{"/api-docs", "swagger", "API docs exposed", SeverityLow, 3.7, "A09:2021-Security Logging Failures", ""},
	{"/.well-known/security.txt", "Contact:", "security.txt present (informational)", SeverityInfo, 0, "informational", ""},
	{"/robots.txt", "Disallow", "robots.txt present (informational)", SeverityInfo, 0, "informational", ""},
}

// envLine matches a typical .env line: KEY=value, key in upper snake case.
// We require a line-anchored match so SPA HTML responses that happen to
// contain `="..."` attributes don't trigger a false positive.
var envLineRe = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{1,}=`)

func (s *ExposedEndpointsScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	var findings []Finding
	for _, e := range exposedEndpoints {
		full := target + e.path
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		// SPA/CDN wildcard guard: real .env / .git / actuator / pprof
		// endpoints never serve text/html. If the framework's catch-all
		// route returns the SPA shell, drop the finding.
		if isHTMLResponse(ct, body) {
			continue
		}
		if !matchesProbeShape(e, body) {
			continue
		}
		findings = append(findings, Finding{
			URL: full, Title: e.title, Description: e.desc,
			Severity: e.sev, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Timestamp: time.Now(), OWASPCategory: e.owasp, CVSSScore: e.score,
		})
	}
	return findings, nil
}

func isHTMLResponse(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if ct == "text/html" || ct == "application/xhtml+xml" {
		return true
	}
	// Some misconfigured catch-all routes return text/plain or no
	// Content-Type at all but a full HTML body. Sniff the first bytes.
	head := bytes.TrimLeft(body, " \t\r\n")
	if len(head) > 14 && (bytes.HasPrefix(bytes.ToLower(head[:14]), []byte("<!doctype html")) ||
		bytes.HasPrefix(head, []byte("<html")) ||
		bytes.HasPrefix(head, []byte("<HTML"))) {
		return true
	}
	return false
}

// matchesProbeShape tightens the contains match for probes whose marker
// (e.g. "=" for .env, "ref:" for .git/HEAD) is too generic on its own.
func matchesProbeShape(e endpointProbe, body []byte) bool {
	switch e.path {
	case "/.env":
		return envLineRe.Match(body)
	case "/.git/HEAD":
		// real HEAD is either "ref: refs/heads/<name>\n" or a 40-char hex sha
		return bytes.HasPrefix(body, []byte("ref: refs/")) ||
			(len(bytes.TrimSpace(body)) == 40 && isHex(bytes.TrimSpace(body)))
	}
	if e.contains == "" {
		return true
	}
	return bytes.Contains(body, []byte(e.contains))
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
