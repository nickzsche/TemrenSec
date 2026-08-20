package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hibiken/asynq"
	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/metrics"
	"github.com/temren/internal/model"
	"github.com/temren/internal/safeurl"
	"github.com/temren/pkg/analyzer"
	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/plugin"
	"github.com/temren/pkg/scanner"
	"github.com/temren/pkg/spider"
)

type Worker struct {
	server *asynq.ServeMux
}

func NewWorker() *Worker {
	mux := asynq.NewServeMux()
	w := &Worker{server: mux}
	mux.HandleFunc(TypeScan, w.handleScan)
	return w
}

func (w *Worker) Run() error {
	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: redisAddr()},
		asynq.Config{
			Concurrency: config.AppConfig.WorkerConcurrency,
			Queues: map[string]int{
				"scans":   10,
				"default": 1,
			},
			RetryDelayFunc: func(n int, err error, task *asynq.Task) time.Duration {
				return time.Duration(n) * time.Minute
			},
		},
	)

	log.Println("[worker] starting scan worker...")
	return srv.Run(w.server)
}

func (w *Worker) handleScan(ctx context.Context, t *asynq.Task) error {
	var payload ScanPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	log.Printf("[worker] starting scan %s for %s", payload.ScanID, payload.URL)

	scanDB := database.NewScanRepo()
	vulnDB := database.NewVulnerabilityRepo()
	targetDB := database.NewTargetRepo()

	if err := scanDB.StartScan(ctx, payload.ScanID); err != nil {
		log.Printf("[worker] failed to start scan %s: %v", payload.ScanID, err)
		metrics.ScansTotal.WithLabelValues("failed").Inc()
		return err
	}

	// The scan counters and duration histogram are published on /metrics but
	// nothing on this path ever moved them, so every dashboard built on them
	// read zero.
	scanStarted := time.Now()
	metrics.ScansTotal.WithLabelValues("started").Inc()
	metrics.ScansInProgress.Inc()
	defer metrics.ScansInProgress.Dec()

	var scanConfig struct {
		Depth       int  `json:"depth"`
		MaxPages    int  `json:"max_pages"`
		Concurrency int  `json:"concurrency"`
		RateLimit   int  `json:"rate_limit"`
		Active      bool `json:"active"`
		Passive     bool `json:"passive"`
	}
	_ = json.Unmarshal([]byte(payload.Config), &scanConfig)

	if scanConfig.Depth == 0 {
		scanConfig.Depth = 2
	}
	if scanConfig.MaxPages == 0 {
		scanConfig.MaxPages = 50
	}
	if scanConfig.Concurrency == 0 {
		scanConfig.Concurrency = 5
	}
	if scanConfig.RateLimit == 0 {
		scanConfig.RateLimit = 10
	}

	targetURL := payload.URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	// Re-validate the stored target: it passed safeurl.Validate when it was
	// created, but DNS answers change, and a target predating that check may
	// still be in the database.
	if err := safeurl.Validate(targetURL); err != nil {
		log.Printf("[worker] refusing scan %s: %v", payload.ScanID, err)
		if ferr := scanDB.FailScan(ctx, payload.ScanID, err.Error()); ferr != nil {
			log.Printf("[worker] failed to mark scan %s failed: %v", payload.ScanID, ferr)
		}
		metrics.ScansTotal.WithLabelValues("refused").Inc()
		metrics.ScanDuration.WithLabelValues("refused").Observe(time.Since(scanStarted).Seconds())
		return nil
	}

	httpCfg := &httpengine.Config{
		Timeout:         time.Duration(config.AppConfig.ScanTimeout) * time.Second,
		RateLimit:       scanConfig.RateLimit,
		MaxRedirects:    10,
		FollowRedirects: true,
		UserAgent:       "TemrenSec/1.0 (Security Scanner)",
		// Enforce the destination policy at connect time too, so DNS rebinding
		// and redirects into the internal network are blocked on every hop.
		DialControl: safeurl.DialControl,
	}
	client := httpengine.NewClient(httpCfg)

	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	var allFindings []scanner.Finding
	var findingsMu sync.Mutex

	urlsToScan := []string{targetURL}

	if scanConfig.Passive || scanConfig.Active {
		spiderCfg := &spider.Config{
			MaxDepth:    scanConfig.Depth,
			MaxPages:    scanConfig.MaxPages,
			Concurrency: scanConfig.Concurrency,
			SameDomain:  true,
			Delay:       time.Second / time.Duration(scanConfig.RateLimit),
		}

		s := spider.New(client, spiderCfg)
		results := s.Crawl(scanCtx, targetURL)

		for result := range results {
			if result.Error != nil {
				continue
			}
			urlsToScan = append(urlsToScan, result.URL)

			if scanConfig.Passive {
				passiveFindings := runPassiveAnalysis(scanCtx, result.URL, result.Response)
				findingsMu.Lock()
				allFindings = append(allFindings, passiveFindings...)
				findingsMu.Unlock()
			}
		}
	}

	if scanConfig.Active {
		// Use the shared registry rather than a hand-maintained list. The local
		// copy had drifted to 22 scanners while the CLI ran all of them, so the
		// dashboard silently reported a fraction of the coverage.
		scanners := scanner.AllScanners()
		scanEngine := scanner.NewScanEngine(client, scanners, scanConfig.Concurrency)

		activeFindings, err := scanEngine.RunAll(scanCtx, urlsToScan)
		if err != nil {
			log.Printf("[worker] active scan for %s reported an error: %v", targetURL, err)
		}
		allFindings = append(allFindings, activeFindings...)

		scanEngine.ClearCache()
	}

	// Verify findings before they reach the dashboard. The CLI already did this;
	// the queue path did not, so web users saw unfiltered false positives.
	if scanConfig.Active && len(allFindings) > 0 {
		verifier := scanner.NewProofVerifier(client)
		verified := make([]scanner.Finding, 0, len(allFindings))
		dropped := 0
		for _, vr := range verifier.Verify(scanCtx, allFindings) {
			if vr.RiskLevel == "likely_false_positive" {
				dropped++
				continue
			}
			f := vr.Finding
			f.Confidence = vr.Confidence
			verified = append(verified, f)
		}
		if dropped > 0 {
			log.Printf("[worker] verification dropped %d likely false positive(s) of %d",
				dropped, len(allFindings))
		}
		allFindings = verified
	}

	// Run plugins from default directory
	pluginEngine := plugin.NewPluginEngine()
	home, _ := os.UserHomeDir()
	if home != "" {
		pluginsPath := filepath.Join(home, ".temren", "plugins")
		if err := pluginEngine.Load(pluginsPath); err != nil {
			log.Printf("[worker] plugin loading error: %v", err)
		}
	}

	if pluginEngine.Count() > 0 {
		log.Printf("[worker] running %d plugin(s)", pluginEngine.Count())
		for _, u := range urlsToScan {
			headers := make(map[string]string)
			baseline, baseErr := client.Get(scanCtx, u)
			if baseErr != nil {
				continue
			}
			for k, v := range baseline.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			bodyBytes, _ := readWorkerBody(baseline)
			baseline.Body.Close()

			pluginFindings := pluginEngine.RunAll(scanCtx, u, string(bodyBytes), headers)
			for _, pf := range pluginFindings {
				allFindings = append(allFindings, pf.ToScannerFinding("plugin"))
			}
		}
		pluginEngine.Close()
	}

	scanResult := &model.Scan{
		ID:            payload.ScanID,
		PagesCrawled:  len(urlsToScan),
		TotalFindings: len(allFindings),
	}

	for _, f := range allFindings {
		vuln := &model.Vulnerability{
			ScanID:            payload.ScanID,
			TargetID:          payload.TargetID,
			Title:             f.Title,
			Severity:          string(f.Severity),
			Description:       f.Description,
			URL:               f.URL,
			Payload:           f.Payload,
			Evidence:          f.Evidence,
			OWASPCategory:     mapScannerToOWASP(f.Scanner),
			FixRecommendation: getFixRecommendation(f.Title, string(f.Severity)),
			Proof:             f.Request + "\n\n" + f.Response,
			Status:            "open",
		}

		switch f.Severity {
		case scanner.SeverityCritical:
			scanResult.CriticalCount++
		case scanner.SeverityHigh:
			scanResult.HighCount++
		case scanner.SeverityMedium:
			scanResult.MediumCount++
		case scanner.SeverityLow:
			scanResult.LowCount++
		case scanner.SeverityInfo:
			scanResult.InfoCount++
		}

		if err := vulnDB.Create(ctx, vuln); err != nil {
			log.Printf("[worker] failed to save vulnerability: %v", err)
			continue
		}
		metrics.VulnerabilitiesFound.WithLabelValues(string(f.Severity), f.Scanner).Inc()
	}

	if err := scanDB.CompleteScan(ctx, scanResult); err != nil {
		log.Printf("[worker] failed to complete scan %s: %v", payload.ScanID, err)
		metrics.ScansTotal.WithLabelValues("failed").Inc()
		metrics.ScanDuration.WithLabelValues("failed").Observe(time.Since(scanStarted).Seconds())
		return err
	}

	metrics.ScansTotal.WithLabelValues("completed").Inc()
	metrics.ScanDuration.WithLabelValues("completed").Observe(time.Since(scanStarted).Seconds())

	securityScore := calculateSecurityScore(scanResult)
	_ = targetDB.UpdateSecurityScore(ctx, payload.TargetID, securityScore)

	log.Printf("[worker] scan %s completed: %d findings (score: %d)", payload.ScanID, len(allFindings), securityScore)

	return nil
}

func runPassiveAnalysis(ctx context.Context, target string, resp *httpengine.Response) []scanner.Finding {
	var findings []scanner.Finding

	analyzers := []analyzer.Analyzer{
		analyzer.NewSecurityHeadersAnalyzer(),
		analyzer.NewSSLAnalyzer(),
		analyzer.NewSensitiveDataAnalyzer(),
		analyzer.NewCORSAnalyzer(),
	}

	for _, a := range analyzers {
		results, err := a.Analyze(ctx, target, resp)
		if err != nil {
			continue
		}
		findings = append(findings, results...)
	}

	return findings
}

// mapScannerToOWASP resolves a scanner's reported name to an OWASP Top 10 (2021)
// category.
//
// This table is keyed on the exact string Scanner.Name() returns. The previous
// version was keyed on informal short names ("XSS", "IDOR", "JWT"), 15 of which
// matched no scanner at all, so those findings all fell through to a category
// that does not exist. It also filed injection under A06. owasp_test.go walks
// the registry and fails if any scanner is unmapped, so new scanners cannot
// silently regress this.
func mapScannerToOWASP(scannerName string) string {
	if cat, ok := owaspByScannerName[scannerName]; ok {
		return cat
	}
	// Fall back to keyword matching so a renamed or newly added scanner still
	// lands in a plausible category rather than an unknown one.
	lower := strings.ToLower(scannerName)
	for _, rule := range owaspKeywordRules {
		if strings.Contains(lower, rule.keyword) {
			return rule.category
		}
	}
	return owaspUncategorized
}

// owaspUncategorized is used when nothing matches. A05 (Security
// Misconfiguration) is the broadest real category; the old code returned
// "A00:2021", which is not an OWASP category at all.
const owaspUncategorized = "A05:2021"

var owaspKeywordRules = []struct {
	keyword  string
	category string
}{
	{"injection", "A03:2021"},
	{"xss", "A03:2021"},
	{"cross-site scripting", "A03:2021"},
	{"traversal", "A01:2021"},
	{"ssrf", "A10:2021"},
	{"jwt", "A07:2021"},
	{"oauth", "A07:2021"},
	{"saml", "A07:2021"},
	{"auth", "A07:2021"},
	{"deserialization", "A08:2021"},
	{"supply chain", "A08:2021"},
	{"dependency", "A06:2021"},
	{"component", "A06:2021"},
	{"outdated", "A06:2021"},
	{"tls", "A02:2021"},
	{"ssl", "A02:2021"},
	{"crypto", "A02:2021"},
	{"secret", "A02:2021"},
	{"leak", "A01:2021"},
	{"logging", "A09:2021"},
	{"monitoring", "A09:2021"},
	{"design", "A04:2021"},
	{"race condition", "A04:2021"},
	{"redirect", "A01:2021"},
	{"cors", "A05:2021"},
	{"header", "A05:2021"},
	{"exposed", "A05:2021"},
}

// owaspByScannerName maps Scanner.Name() to its OWASP 2021 category.
//
//	A01 Broken Access Control          A06 Vulnerable and Outdated Components
//	A02 Cryptographic Failures         A07 Identification and Authentication Failures
//	A03 Injection                      A08 Software and Data Integrity Failures
//	A04 Insecure Design                A09 Security Logging and Monitoring Failures
//	A05 Security Misconfiguration      A10 Server-Side Request Forgery
var owaspByScannerName = map[string]string{
	// A03 — Injection
	"SQL Injection":                       "A03:2021",
	"NoSQL Injection":                     "A03:2021",
	"Cross-Site Scripting (XSS)":          "A03:2021",
	"Command Injection":                   "A03:2021",
	"LDAP Injection":                      "A03:2021",
	"XPath Injection":                     "A03:2021",
	"Email/SMTP Header Injection":         "A03:2021",
	"Host Header Injection":               "A03:2021",
	"SSTI — Engine Fingerprint":           "A03:2021",
	"Server-Side Include (SSI) Injection": "A03:2021",
	"Form Parameter Testing":              "A03:2021",

	// A01 — Broken Access Control
	"Insecure Direct Object Reference (IDOR)": "A01:2021",
	"Path Traversal":                      "A01:2021",
	"Nginx Alias Traversal":               "A01:2021",
	"Open Redirect":                       "A01:2021",
	"Open Redirect (Path)":                "A01:2021",
	"Directory Brute Force":               "A01:2021",
	"Exposed Sensitive Endpoints":         "A01:2021",
	".well-known Inventory":               "A01:2021",
	"Cloud Leak Detection":                "A01:2021",
	"HTTP Method Override Bypass":         "A01:2021",
	"Mass Assignment / BOLA":              "A01:2021",
	"SCIM Endpoint Enumeration":           "A01:2021",
	"Dev-tool Exposure (Storybook / MSW)": "A01:2021",

	// A02 — Cryptographic Failures
	"Padding Oracle Probe": "A02:2021",
	"ETag Inode Leak":      "A02:2021",

	// A04 — Insecure Design
	"Insecure Design":                      "A04:2021",
	"Race Condition":                       "A04:2021",
	"Account Enumeration (Password Reset)": "A04:2021",
	"Honeypot Detection":                   "A04:2021",

	// A05 — Security Misconfiguration
	"CORS Misconfiguration":                 "A05:2021",
	"CORS Misconfiguration (Preflight)":     "A05:2021",
	"Clickjacking Protection":               "A05:2021",
	"CSP Bypass Surface":                    "A05:2021",
	"HSTS Preload Eligibility":              "A05:2021",
	"Content-Type Confusion":                "A05:2021",
	"Mishandling of Exceptional Conditions": "A05:2021",
	"Backup File Scanner":                   "A05:2021",
	"GraphQL Security":                      "A05:2021",
	"GraphQL Batching Attack":               "A05:2021",
	"GraphQL Field Suggestion Leak":         "A05:2021",
	"GraphQL CSRF (no preflight)":           "A05:2021",
	"JSONP Callback Abuse":                  "A05:2021",
	"HTTP Parameter Pollution":              "A05:2021",
	"HTTP Request Smuggling":                "A05:2021",
	"File Upload Validation Bypass":         "A05:2021",
	"API Security":                          "A05:2021",
	"API Autodiscovery":                     "A05:2021",
	"Parameter Mining":                      "A05:2021",
	"LLM/API Security Scanner":              "A05:2021",

	// A06 — Vulnerable and Outdated Components
	"Missing Subresource Integrity (SRI)": "A06:2021",

	// A07 — Identification and Authentication Failures
	"Authentication Failures":                  "A07:2021",
	"JWT Analysis":                             "A07:2021",
	"JWT Algorithm Confusion / JWKS injection": "A07:2021",
	"JWT JKU Header Injection":                 "A07:2021",
	"OAuth/OIDC Misconfiguration":              "A07:2021",
	"SAML XSW Surface":                         "A07:2021",

	// A08 — Software and Data Integrity Failures
	"Insecure Deserialization": "A08:2021",
	"Prototype Pollution":      "A08:2021",

	// A10 — Server-Side Request Forgery
	"SSRF — Cloud Metadata": "A10:2021",
}

func getFixRecommendation(title, severity string) string {
	if strings.Contains(strings.ToLower(title), "sql") {
		return "Use parameterized queries/prepared statements. Validate and sanitize all user inputs."
	}
	if strings.Contains(strings.ToLower(title), "xss") {
		return "Implement Content-Security-Policy headers. Escape all user-controlled data in output."
	}
	if strings.Contains(strings.ToLower(title), "header") {
		return "Configure proper security headers in your web server configuration."
	}
	if strings.Contains(strings.ToLower(title), "tls") || strings.Contains(strings.ToLower(title), "ssl") {
		return "Use TLS 1.2+ with strong cipher suites. Obtain certificates from trusted CAs."
	}
	return "Review and remediate based on OWASP guidelines for this vulnerability category."
}

func calculateSecurityScore(scan *model.Scan) int {
	score := 100
	score -= scan.CriticalCount * 25
	score -= scan.HighCount * 15
	score -= scan.MediumCount * 5
	score -= scan.LowCount * 2
	score -= scan.InfoCount

	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func readWorkerBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	buf := make([]byte, 1024*1024)
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}
	return buf[:n], nil
}
