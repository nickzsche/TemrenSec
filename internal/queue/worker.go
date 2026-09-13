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
	"github.com/temren/pkg/analyzer"
	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/plugin"
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
		}
	}

	if err := scanDB.CompleteScan(ctx, scanResult); err != nil {
		log.Printf("[worker] failed to complete scan %s: %v", payload.ScanID, err)
		return err
	}

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

// owaspCategory picks the best OWASP tag for a finding. Scanners already emit
// their own 2021 tag (and ScanEngine fills the 2025 equivalent), so we trust the
// finding first and only fall back to the name map for the rare scanner that
// emits neither.
func owaspCategory(f scanner.Finding) string {
	if f.OWASPCategory2025 != "" {
		return f.OWASPCategory2025
	}
	if f.OWASPCategory != "" {
		return f.OWASPCategory
	}
	return mapScannerToOWASP(f.Scanner)
}

func mapScannerToOWASP(scannerName string) string {
	mapping := map[string]string{
		"SQL Injection":         "A06:2021",
		"XSS":                   "A06:2021",
		"Command Injection":     "A06:2021",
		"SSRF":                  "A06:2021",
		"IDOR":                  "A01:2021",
		"Path Traversal":        "A01:2021",
		"XXE":                   "A05:2021",
		"Auth Failure":          "A07:2021",
		"Vulnerable Components": "A06:2021",
		"Logging & Monitoring":  "A09:2021",
		"Insecure Design":       "A04:2021",
		"Error Handling":        "A05:2021",
		"Supply Chain":          "A08:2021",
		"Security Headers":      "A05:2021",
		"SSL/TLS":               "A02:2021",
		"Sensitive Data":        "A02:2021",
		"CORS":                  "A05:2021",
		"Backup File":           "A05:2021",
		"Directory Brute Force": "A01:2021",
		"JWT":                   "A07:2021",
		"GraphQL":               "A06:2021",
		"Open Redirect":         "A01:2021",
		"Prototype Pollution":   "A06:2021",
		"Cloud Leak":            "A05:2021",
	}
	if cat, ok := mapping[scannerName]; ok {
		return cat
	}
	return "A00:2021"
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
