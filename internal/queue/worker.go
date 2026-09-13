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

	"github.com/temren/internal/config"
	"github.com/temren/internal/database"
	"github.com/temren/internal/model"
	"github.com/temren/internal/websocket"
	"github.com/temren/pkg/analyzer"
	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/plugin"
	"github.com/temren/pkg/remediation"
	"github.com/temren/pkg/scanner"
	"github.com/temren/pkg/spider"
	"github.com/hibiken/asynq"
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
		return err
	}

	// Live progress → WebSocket (via Redis bridge to the API replicas).
	hub := websocket.GetHub()
	hub.PublishScanStarted(payload.ScanID, payload.TargetID)

	var scanConfig struct {
		Depth       int      `json:"depth"`
		MaxPages    int      `json:"max_pages"`
		Concurrency int      `json:"concurrency"`
		RateLimit   int      `json:"rate_limit"`
		Active      bool     `json:"active"`
		Passive     bool     `json:"passive"`
		Scanners    []string `json:"scanners"` // optional subset; empty = every registered scanner
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

	httpCfg := &httpengine.Config{
		Timeout:         time.Duration(config.AppConfig.ScanTimeout) * time.Second,
		RateLimit:       scanConfig.RateLimit,
		MaxRedirects:    10,
		FollowRedirects: true,
		UserAgent:       "TemrenSec/1.0 (Security Scanner)",
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
			hub.PublishScanProgress(payload.ScanID, len(urlsToScan), scanConfig.MaxPages, result.URL)

			if scanConfig.Passive {
				passiveFindings := runPassiveAnalysis(scanCtx, result.URL, result.Response)
				findingsMu.Lock()
				allFindings = append(allFindings, passiveFindings...)
				findingsMu.Unlock()
			}
		}
	}

	if scanConfig.Active {
		// The registry is the single source of truth: every scanner that ships
		// runs, unless the scan explicitly narrows to a subset. Previously the
		// worker hardcoded 26 of the 88 scanners, so two thirds never ran.
		scanners := scanner.AllScanners()
		if len(scanConfig.Scanners) > 0 {
			scanners = scanner.EnabledScanners(scanConfig.Scanners)
		}
		log.Printf("[worker] scan %s running %d scanners", payload.ScanID, len(scanners))
		scanEngine := scanner.NewScanEngine(client, scanners, scanConfig.Concurrency)

		activeFindings, err := scanEngine.RunAll(scanCtx, urlsToScan)
		if err == nil {
			allFindings = append(allFindings, activeFindings...)
		}

		scanEngine.ClearCache()
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
			OWASPCategory:     owaspCategory(f),
			FixRecommendation: fixText(f),
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
		}
		hub.PublishVulnerabilityFound(payload.ScanID, &websocket.VulnFound{Title: f.Title, Severity: string(f.Severity), URL: f.URL})
	}

	if err := scanDB.CompleteScan(ctx, scanResult); err != nil {
		log.Printf("[worker] failed to complete scan %s: %v", payload.ScanID, err)
		return err
	}

	securityScore := calculateSecurityScore(scanResult)
	_ = targetDB.UpdateSecurityScore(ctx, payload.TargetID, securityScore)

	hub.PublishScanCompleted(payload.ScanID, len(allFindings))

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

// owaspCategory picks the best OWASP tag for a finding. Scanners already emit
// their own 2021 tag (and ScanEngine fills the 2025 equivalent), so we trust the
// finding first and only fall back to the name map for the rare scanner that
// emits neither.
// owaspCategory returns a single, consistent 2025 OWASP tag for every finding.
// Active-scanner findings already carry OWASPCategory2025 (filled by the engine);
// passive analyzers and category-less scanners don't, so we normalize their 2021
// tag — or a keyword guess — through the same 2021→2025 map. No more mixed
// "A05:2021" vs "A02:2025" labels in one report.
func owaspCategory(f scanner.Finding) string {
	if f.OWASPCategory2025 != "" {
		return f.OWASPCategory2025
	}
	if f.OWASPCategory != "" {
		return scanner.MapOWASP2021To2025(f.OWASPCategory)
	}
	return scanner.MapOWASP2021To2025(guessOWASP(f))
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// guessOWASP infers a 2021 tag from the scanner name / finding title when the
// scanner emits none. Returns A00 only for genuinely informational findings
// (e.g. technology fingerprinting), which is honest — not every recon signal
// maps to a Top 10 category.
func guessOWASP(f scanner.Finding) string {
	s := strings.ToLower(f.Scanner + " " + f.Title)
	switch {
	case containsAny(s, "sql", "inject", "xss", "ssti", "template", "command", "xpath", "ldap", "nosql", "ssrf", "deserial"):
		return "A03:2021"
	case containsAny(s, "credential", "auth", "login", "jwt", "session", "password", "2fa", "mfa", "oauth", "saml"):
		return "A07:2021"
	case containsAny(s, "tls", "ssl", "https", "certificate", "cipher", "crypto", "hsts"):
		return "A02:2021"
	case containsAny(s, "idor", "access", "redirect", "traversal", "cors", "admin path", "privilege"):
		return "A01:2021"
	case containsAny(s, "header", "misconfig", "honeypot", "well-known", "clickjack", "banner", "powered", "exposed", "webdav", "swagger", "storybook"):
		return "A05:2021"
	case containsAny(s, "component", "supply", "dependency", "outdated", "vulnerable"):
		return "A06:2021"
	case containsAny(s, "log", "monitor", "alert"):
		return "A09:2021"
	case containsAny(s, "error", "exception", "stack trace"):
		return "A10:2021"
	}
	return "A00:2021" // truly informational (technology detection, recon)
}

// ruleAdvisor gives per-scanner remediation (fix + code example + references)
// offline — far richer than a keyword guess, matched on the scanner that
// produced the finding.
var ruleAdvisor = remediation.NewRuleBasedAdvisor()

func fixText(f scanner.Finding) string {
	r := ruleAdvisor.Suggest(f)
	if r == nil {
		return "Review and remediate based on OWASP guidelines for this vulnerability category."
	}
	out := r.FixSuggestion
	if r.CodeFix != "" {
		out += "\n\nÖrnek:\n" + r.CodeFix
	}
	if len(r.References) > 0 {
		out += "\n\nKaynaklar:\n- " + strings.Join(r.References, "\n- ")
	}
	return out
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
