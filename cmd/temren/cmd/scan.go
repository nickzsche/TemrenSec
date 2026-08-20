package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/temren/pkg/analyzer"
	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/integration/defectdojo"
	gh "github.com/temren/pkg/integration/github"
	gl "github.com/temren/pkg/integration/gitlab"
	"github.com/temren/pkg/integration/notify"
	"github.com/temren/pkg/plugin"
	"github.com/temren/pkg/remediation"
	"github.com/temren/pkg/report"
	"github.com/temren/pkg/sbom"
	"github.com/temren/pkg/scanner"
	"github.com/temren/pkg/spider"
)

var (
	targetURL     string
	scanDepth     int
	rateLimit     int
	maxPages      int
	concurrency   int
	outputFormat  string
	outputFile    string
	enableCrawl   bool
	noCrawl       bool
	timeout       int
	sameDomain    bool
	activeScans   bool
	passiveScans  bool
	silent        bool
	subdomainEnum bool
	reportEmail   string
	smtpHost      string
	smtpPort      string
	smtpUser      string
	smtpPass      string
	fromEmail     string

	authToken        string
	authHeader       string
	authCookies      []string
	authHeaderCustom []string
	authUser         string
	authPass         string

	proxyList  string
	proxyType  string
	torEnabled bool
	customUA   string
	jitterMin  int
	jitterMax  int

	pluginsDir string
	noBatch    bool

	defectDojoPush    bool
	defectDojoURL     string
	defectDojoToken   string
	defectDojoProduct string

	apiSpecURL      string
	apiDiscover     bool
	headlessEnabled bool
	upstreamProxy   string

	complianceFilter string

	remediationProvider string
	remediationAPIKey   string
	remediationModel    string
	remediationBaseURL  string

	sbomGenerate bool

	verifyFindings bool

	notifySlackWebhook   string
	notifyDiscordWebhook string
	notifyTeamsWebhook   string

	githubToken   string
	githubRepo    string
	gitlabToken   string
	gitlabProject string
	gitlabBaseURL string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target URL for OWASP Top 10 vulnerabilities",
	Long: `Scan a target URL for security vulnerabilities.

Examples:
  temren scan --target https://example.com
  temren scan -t https://example.com --depth 3 --rate 20
  temren scan -t https://example.com --output results.json --format json
  temren scan -t https://example.com --no-crawl  # Scan only the target URL
`,
	Run: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&targetURL, "target", "t", "", "Target URL to scan (required)")
	scanCmd.Flags().IntVarP(&scanDepth, "depth", "d", 2, "Maximum crawl depth")
	scanCmd.Flags().IntVarP(&rateLimit, "rate", "r", 10, "Requests per second")
	scanCmd.Flags().IntVarP(&maxPages, "max-pages", "m", 50, "Maximum pages to crawl")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 5, "Number of concurrent workers")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format (text, json, sarif, junit)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().BoolVar(&enableCrawl, "crawl", true, "Enable web crawling")
	// The command's own examples advertised --no-crawl, which did not exist, so
	// the documented invocation exited with "unknown flag".
	scanCmd.Flags().BoolVar(&noCrawl, "no-crawl", false, "Scan only the target URL (opposite of --crawl)")
	scanCmd.Flags().BoolVar(&sameDomain, "same-domain", true, "Only crawl pages on the same domain")
	scanCmd.Flags().IntVar(&timeout, "timeout", 30, "Request timeout in seconds")
	scanCmd.Flags().BoolVar(&activeScans, "active", true, "Enable active vulnerability scanning")
	scanCmd.Flags().BoolVar(&passiveScans, "passive", true, "Enable passive security analysis")
	scanCmd.Flags().BoolVar(&subdomainEnum, "subdomain", false, "Enable subdomain enumeration")
	scanCmd.Flags().BoolVarP(&silent, "silent", "s", false, "Silent mode (only show findings)")
	scanCmd.Flags().StringVar(&reportEmail, "report-email", "", "Send HTML report to this email")
	scanCmd.Flags().StringVar(&smtpHost, "smtp-host", "smtp.gmail.com", "SMTP server host")
	scanCmd.Flags().StringVar(&smtpPort, "smtp-port", "587", "SMTP server port")
	scanCmd.Flags().StringVar(&smtpUser, "smtp-user", "", "SMTP username (email)")
	scanCmd.Flags().StringVar(&smtpPass, "smtp-pass", "", "SMTP password")
	scanCmd.Flags().StringVar(&fromEmail, "from-email", "", "From email address")

	scanCmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token for authenticated scanning")
	scanCmd.Flags().StringVar(&authHeader, "auth-header", "Authorization", "Custom header name for bearer token")
	scanCmd.Flags().StringArrayVar(&authCookies, "auth-cookie", nil, "Cookie string (name=value, repeatable)")
	scanCmd.Flags().StringArrayVar(&authHeaderCustom, "auth-header-custom", nil, "Custom header (Key:Value, repeatable)")
	scanCmd.Flags().StringVar(&authUser, "auth-user", "", "Basic auth username")
	scanCmd.Flags().StringVar(&authPass, "auth-pass", "", "Basic auth password")

	scanCmd.Flags().StringVar(&proxyList, "proxy-list", "", "Proxy list file or comma-separated proxies (user:pass@host:port)")
	scanCmd.Flags().StringVar(&proxyType, "proxy-type", "http", "Proxy type: http or socks5")
	scanCmd.Flags().BoolVar(&torEnabled, "tor", false, "Route traffic through Tor (requires Tor running on 127.0.0.1:9050)")
	scanCmd.Flags().StringVar(&customUA, "user-agent", "", "Custom user agent (leave empty to rotate randomly)")
	scanCmd.Flags().IntVar(&jitterMin, "jitter-min", 100, "Minimum jitter delay in ms between requests")
	scanCmd.Flags().IntVar(&jitterMax, "jitter-max", 500, "Maximum jitter delay in ms between requests")

	scanCmd.Flags().StringVar(&pluginsDir, "plugins-dir", defaultPluginsDir(), "Directory containing Lua plugins")
	scanCmd.Flags().BoolVar(&noBatch, "no-batch", false, "Disable request batching (for debugging)")

	scanCmd.Flags().BoolVar(&defectDojoPush, "defectdojo", false, "Push findings to DefectDojo")
	scanCmd.Flags().StringVar(&defectDojoURL, "defectdojo-url", "", "DefectDojo instance URL")
	scanCmd.Flags().StringVar(&defectDojoToken, "defectdojo-token", "", "DefectDojo API token")
	scanCmd.Flags().StringVar(&defectDojoProduct, "defectdojo-product", "", "DefectDojo product name")

	scanCmd.Flags().StringVar(&apiSpecURL, "api-spec", "", "Path or URL to OpenAPI/Swagger spec")
	scanCmd.Flags().BoolVar(&apiDiscover, "api-discover", false, "Auto-discover API spec from common paths")
	scanCmd.Flags().BoolVar(&headlessEnabled, "headless", false, "Enable headless browser for SPA/JS rendering")
	scanCmd.Flags().StringVar(&upstreamProxy, "proxy", "", "Upstream proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)")

	scanCmd.Flags().StringVar(&complianceFilter, "compliance", "", "Compliance frameworks to show (comma-separated: pci,soc2,iso27001)")
	// Default on: the queue/dashboard path always verifies, so leaving the CLI
	// unverified made the same scan report different results depending on how it
	// was run. Use --verify=false to see raw detector output.
	scanCmd.Flags().BoolVar(&verifyFindings, "verify", true, "Verify findings with proof-based exploitation (reduces false positives)")

	scanCmd.Flags().StringVar(&remediationProvider, "remediation", "none", "Remediation provider: openai, anthropic, ollama, none")
	scanCmd.Flags().StringVar(&remediationAPIKey, "remediation-key", "", "API key for remediation provider")
	scanCmd.Flags().StringVar(&remediationModel, "remediation-model", "", "Model for remediation (default: provider-specific)")
	scanCmd.Flags().StringVar(&remediationBaseURL, "remediation-url", "", "Custom endpoint URL (for Ollama/local)")

	scanCmd.Flags().BoolVar(&sbomGenerate, "sbom", false, "Generate Software Bill of Materials (CycloneDX)")

	scanCmd.Flags().StringVar(&notifySlackWebhook, "notify-slack", "", "Slack webhook URL for scan notifications")
	scanCmd.Flags().StringVar(&notifyDiscordWebhook, "notify-discord", "", "Discord webhook URL for scan notifications")
	scanCmd.Flags().StringVar(&notifyTeamsWebhook, "notify-teams", "", "Microsoft Teams webhook URL for scan notifications")

	scanCmd.Flags().StringVar(&githubToken, "github-token", "", "GitHub personal access token for creating issues")
	scanCmd.Flags().StringVar(&githubRepo, "github-repo", "", "GitHub repository (owner/repo) for creating issues")
	scanCmd.Flags().StringVar(&gitlabToken, "gitlab-token", "", "GitLab personal access token for creating issues")
	scanCmd.Flags().StringVar(&gitlabProject, "gitlab-project", "", "GitLab project ID or path for creating issues")
	scanCmd.Flags().StringVar(&gitlabBaseURL, "gitlab-url", "https://gitlab.com/api/v4", "GitLab API base URL")

	scanCmd.MarkFlagRequired("target")
}

func defaultPluginsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".temren", "plugins")
}

func runScan(cmd *cobra.Command, args []string) {
	if !silent {
		printBanner()
		fmt.Println()
	}

	// Validate target URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	// Create HTTP client
	cfg := &httpengine.Config{
		Timeout:         time.Duration(timeout) * time.Second,
		RateLimit:       rateLimit,
		MaxRedirects:    10,
		FollowRedirects: true,
		UserAgent:       "TemrenSec/1.0 (Security Scanner)",
		ProxyList:       proxyList,
		ProxyType:       proxyType,
		TorEnabled:      torEnabled,
		JitterMin:       time.Duration(jitterMin) * time.Millisecond,
		JitterMax:       time.Duration(jitterMax) * time.Millisecond,
	}

	if customUA != "" {
		cfg.UserAgent = customUA
	} else if proxyList != "" || torEnabled {
		cfg.RotateUA = true
	}

	client := httpengine.NewClient(cfg)

	// Apply upstream proxy if configured (e.g., Burp Suite)
	if upstreamProxy != "" {
		proxyCfg, err := httpengine.NewUpstreamProxyConfig(upstreamProxy)
		if err != nil {
			if !silent {
				fmt.Printf("[!] Invalid upstream proxy: %v\n", err)
			}
		} else {
			if err := proxyCfg.ApplyToClient(client); err != nil {
				if !silent {
					fmt.Printf("[!] Failed to configure upstream proxy: %v\n", err)
				}
			} else if !silent {
				fmt.Printf("[*] Upstream proxy configured: %s\n", upstreamProxy)
			}
		}
	}

	// Apply authentication if configured
	if authToken != "" || len(authCookies) > 0 || len(authHeaderCustom) > 0 || authUser != "" {
		authCfg := httpengine.NewAuthConfig()
		if authToken != "" {
			authCfg.Method = httpengine.AuthMethodBearer
			authCfg.Token = authToken
			authCfg.TokenHeader = authHeader
		}
		if authUser != "" {
			authCfg.Method = httpengine.AuthMethodBasic
			authCfg.Username = authUser
			authCfg.Password = authPass
		}
		if len(authCookies) > 0 {
			for _, c := range authCookies {
				parts := strings.SplitN(c, "=", 2)
				if len(parts) == 2 {
					authCfg.Cookies = append(authCfg.Cookies, &http.Cookie{Name: parts[0], Value: parts[1]})
				}
			}
		}
		if len(authHeaderCustom) > 0 {
			authCfg.Headers = make(map[string]string)
			for _, h := range authHeaderCustom {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					authCfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
		client.SetAuth(authCfg)
		if !silent {
			fmt.Println("[*] Authenticated scanning enabled")
		}
	}

	if !silent {
		fmt.Println("[*] Adaptive Rate Limiter enabled")
		fmt.Println("[*] Anti-Honeypot protection active")
		if proxyList != "" {
			fmt.Printf("[*] Proxy rotation enabled (%s)\n", proxyType)
		}
		if torEnabled {
			if httpengine.CheckTorRunning("") {
				fmt.Println("[*] Tor routing enabled")
			} else {
				fmt.Println("[!] Tor enabled but not detected on 127.0.0.1:9050")
			}
		}
		if customUA != "" {
			fmt.Printf("[*] Custom User-Agent: %s\n", customUA)
		} else if proxyList != "" || torEnabled {
			fmt.Println("[*] Random User-Agent rotation enabled")
		}
		if jitterMin > 0 || jitterMax > 0 {
			fmt.Printf("[*] Jitter: %d-%dms between requests\n", jitterMin, jitterMax)
		}
	}

	// Initialize findings collector
	findings := make([]scanner.Finding, 0)
	var findingsMu sync.Mutex

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Progress tracking
	var scannedPages int
	var progressMu sync.Mutex

	updateProgress := func() {
		progressMu.Lock()
		scannedPages++
		progressMu.Unlock()
	}

	if !silent {
		fmt.Printf("[*] Target: %s\n", targetURL)
		fmt.Printf("[*] Depth: %d | Rate: %d req/s | Max Pages: %d\n", scanDepth, rateLimit, maxPages)
		fmt.Println()
	}

	// Collect URLs to scan
	urlsToScan := []string{targetURL}

	var headlessClient *httpengine.HeadlessClient
	if headlessEnabled {
		headlessClient = httpengine.NewHeadlessClient(nil)
		if !silent {
			fmt.Println("[*] Headless browser enabled for SPA/JS rendering")
		}
	}

	if noCrawl {
		enableCrawl = false
	}

	if enableCrawl {
		if !silent {
			fmt.Println("[*] Starting web crawler...")
		}

		if headlessEnabled && headlessClient != nil {
			if !silent {
				fmt.Println("[*] Rendering initial page with headless browser...")
			}
			renderedHTML, err := headlessClient.FetchWithFallback(ctx, targetURL, client)
			if err == nil && renderedHTML != "" {
				headlessLinks := httpengine.ExtractLinksFromHTML(renderedHTML, targetURL)
				headlessForms, _ := httpengine.ExtractFormsFromHTML(renderedHTML, targetURL)
				if !silent {
					fmt.Printf("[*] Headless rendering discovered %d links and %d forms\n", len(headlessLinks), len(headlessForms))
				}
				for _, link := range headlessLinks {
					urlsToScan = append(urlsToScan, link)
				}
				_ = headlessForms
			}
		}

		spiderCfg := &spider.Config{
			MaxDepth:    scanDepth,
			MaxPages:    maxPages,
			Concurrency: concurrency,
			SameDomain:  sameDomain,
			Delay:       time.Second / time.Duration(rateLimit),
		}

		s := spider.New(client, spiderCfg)
		results := s.Crawl(ctx, targetURL)

		for result := range results {
			if result.Error != nil {
				continue
			}
			urlsToScan = append(urlsToScan, result.URL)
			updateProgress()

			if !silent && scannedPages%10 == 0 {
				fmt.Printf("\r[*] Crawled: %d pages", scannedPages)
			}

			// Run passive analyzers on crawled pages
			if passiveScans {
				passiveFindings := runPassiveAnalysis(ctx, result.URL, result.Response)
				findingsMu.Lock()
				findings = append(findings, passiveFindings...)
				findingsMu.Unlock()
			}
		}

		if !silent {
			fmt.Printf("\r[*] Crawled %d pages\n", scannedPages)
		}

		if !silent {
			fmt.Printf("[*] Crawled %d pages\n", len(urlsToScan))
		}
	}

	// Run active scanners
	if activeScans {
		if !silent {
			fmt.Println("[*] Running active vulnerability scanners...")
		}

		// Pull every scanner registered in pkg/scanner — new scanners are picked
		// up automatically without editing this list.
		scanners := scanner.AllScanners()

		if apiSpecURL != "" || apiDiscover {
			scanners = append(scanners, scanner.NewAPISecurityScanner(apiSpecURL, apiDiscover))
			if !silent {
				if apiSpecURL != "" {
					fmt.Printf("[*] API Security Scanner enabled with spec: %s\n", apiSpecURL)
				} else {
					fmt.Println("[*] API Security Scanner enabled with auto-discovery")
				}
			}
		}

		if subdomainEnum {
			scanners = append(scanners, scanner.NewSubdomainEnumerator())
		}

		scanEngine := scanner.NewScanEngine(client, scanners, concurrency)
		scanEngine.SetNoBatch(noBatch)

		activeFindings, err := scanEngine.RunAll(ctx, urlsToScan)
		if err == nil {
			findingsMu.Lock()
			findings = append(findings, activeFindings...)
			findingsMu.Unlock()
		}

		scanEngine.ClearCache()

		if !silent {
			fmt.Printf("[*] Active Scan completed with %d findings\n", len(activeFindings))
		}

		if verifyFindings && len(findings) > 0 {
			if !silent {
				fmt.Println("[*] Running proof-based verification on findings...")
			}
			verifier := scanner.NewProofVerifier(client)
			verified := verifier.Verify(ctx, findings)
			findings = []scanner.Finding{}
			for _, vr := range verified {
				if vr.RiskLevel != "likely_false_positive" {
					f := vr.Finding
					f.Confidence = vr.Confidence
					findings = append(findings, f)
				}
			}
			if !silent {
				fmt.Printf("[*] Verification complete: %d findings confirmed\n", len(findings))
			}
		}
	}

	// Run Lua plugins
	pluginEngine := plugin.NewPluginEngine()
	if err := pluginEngine.Load(pluginsDir); err != nil && !silent {
		fmt.Printf("[!] Plugin loading error: %v\n", err)
	}

	if pluginEngine.Count() > 0 {
		if !silent {
			fmt.Printf("[*] Running %d plugin(s)...\n", pluginEngine.Count())
		}

		for _, url := range urlsToScan {
			headers := make(map[string]string)
			baseline, baseErr := client.Get(ctx, url)
			if baseErr != nil {
				continue
			}
			for k, v := range baseline.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			bodyBytes, _ := readBodyFromResponse(baseline)
			baseline.Body.Close()

			pluginFindings := pluginEngine.RunAll(ctx, url, string(bodyBytes), headers)
			for _, pf := range pluginFindings {
				findings = append(findings, pf.ToScannerFinding("plugin"))
			}
		}

		pluginEngine.Close()
	}

	// Run passive analysis on main target if crawl is disabled
	if passiveScans && !enableCrawl {
		if !silent {
			fmt.Println("[*] Running passive security analysis...")
		}

		resp, err := client.Get(ctx, targetURL)
		if err == nil {
			wrappedResp := &httpengine.Response{
				Response:   resp,
				URL:        targetURL,
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,
			}
			body, _ := wrappedResp.ReadBody()
			wrappedResp.Body = body
			passiveFindings := runPassiveAnalysis(ctx, targetURL, wrappedResp)
			findings = append(findings, passiveFindings...)
		}
	}

	// Calculate CVSS scores for findings
	for i := range findings {
		vector := scanner.InferCVSS4Vector(findings[i])
		findings[i].CVSSScore = scanner.CalculateCVSS4(vector)
		if findings[i].Severity == "" {
			findings[i].Severity = scanner.SeverityFromCVSS(findings[i].CVSSScore)
		}
	}

	// Dedup across passive + active + plugin findings. Engine.RunAll
	// already dedups its own slice; this call collapses repeats produced
	// by passive analyzers running once per crawled page (e.g. 50× Security
	// Headers "Missing X-XSS-Protection" on the same host).
	findings = scanner.DedupFindings(findings)

	// Output results
	if !silent {
		fmt.Println()
		fmt.Println("=========================================")
		fmt.Printf(" SCAN COMPLETE - %d findings\n", len(findings))
		fmt.Println("=========================================")
		fmt.Println()
	}

	if outputFile != "" {
		writeResults(findings, outputFile, outputFormat)
		if !silent {
			fmt.Printf("[*] Results written to: %s\n", outputFile)
		}
	} else {
		printResults(findings, outputFormat, silent)
	}

	// Send email report if requested
	if reportEmail != "" {
		if !silent {
			fmt.Println("[*] Sending email report...")
		}

		cfg := report.ReportConfig{
			Target:      targetURL,
			SenderEmail: fromEmail,
			SenderPass:  smtpPass,
			SMTPHost:    smtpHost,
			SMTPPort:    smtpPort,
			ToEmail:     reportEmail,
		}

		r := report.NewReport(targetURL, findings, cfg)
		err := r.SendEmail()
		if err != nil {
			if !silent {
				fmt.Printf("[!] Failed to send email: %v\n", err)
			}
		} else {
			if !silent {
				fmt.Printf("[*] Email report sent to: %s\n", reportEmail)
			}
		}
	}

	// Push to DefectDojo if requested
	if defectDojoPush && defectDojoURL != "" && defectDojoToken != "" {
		if !silent {
			fmt.Println("[*] Pushing findings to DefectDojo...")
		}

		ddClient := defectdojo.NewClient(&defectdojo.Config{
			BaseURL:     defectDojoURL,
			APIToken:    defectDojoToken,
			ProductName: defectDojoProduct,
		})

		result, err := ddClient.ImportFindings(findings, targetURL)
		if err != nil {
			if !silent {
				fmt.Printf("[!] Failed to push to DefectDojo: %v\n", err)
			}
		} else {
			if !silent {
				fmt.Printf("[*] DefectDojo import complete: %d new, %d closed, %d reactivated\n",
					result.FindingsNew, result.FindingsClosed, result.FindingsReactivated)
			}
		}
	}

	// Send notifications
	severityCount := notify.CountSeverities(findings)
	topFindings := notify.TopCriticalHigh(findings, 5)
	scanResult := notify.ScanResult{
		Target:        targetURL,
		TotalFindings: len(findings),
		SeverityCount: severityCount,
		TopFindings:   topFindings,
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	if notifySlackWebhook != "" {
		notifier := notify.NewSlackNotifier(notify.SlackConfig{WebhookURL: notifySlackWebhook})
		if err := notifier.Send(ctx, scanResult); err != nil {
			if !silent {
				fmt.Printf("[!] Slack notification failed: %v\n", err)
			}
		} else if !silent {
			fmt.Println("[*] Slack notification sent")
		}
	}

	if notifyDiscordWebhook != "" {
		notifier := notify.NewDiscordNotifier(notify.DiscordConfig{WebhookURL: notifyDiscordWebhook})
		if err := notifier.Send(ctx, scanResult); err != nil {
			if !silent {
				fmt.Printf("[!] Discord notification failed: %v\n", err)
			}
		} else if !silent {
			fmt.Println("[*] Discord notification sent")
		}
	}

	if notifyTeamsWebhook != "" {
		notifier := notify.NewTeamsNotifier(notify.TeamsConfig{WebhookURL: notifyTeamsWebhook})
		if err := notifier.Send(ctx, scanResult); err != nil {
			if !silent {
				fmt.Printf("[!] Teams notification failed: %v\n", err)
			}
		} else if !silent {
			fmt.Println("[*] Teams notification sent")
		}
	}

	// GitHub integration
	if githubToken != "" && githubRepo != "" {
		parts := strings.SplitN(githubRepo, "/", 2)
		if len(parts) == 2 {
			ghClient := gh.NewClient(&gh.Config{
				Token: githubToken,
				Owner: parts[0],
				Repo:  parts[1],
			})
			for _, f := range findings {
				if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
					result, err := ghClient.CreateIssue(ctx, f)
					if err != nil {
						if !silent {
							fmt.Printf("[!] GitHub issue creation failed for %q: %v\n", f.Title, err)
						}
					} else if !silent {
						fmt.Printf("[*] GitHub issue created: %s\n", result.URL)
					}
				}
			}
		} else if !silent {
			fmt.Println("[!] Invalid --github-repo format, expected 'owner/repo'")
		}
	}

	// GitLab integration
	if gitlabToken != "" && gitlabProject != "" {
		glClient := gl.NewClient(&gl.Config{
			Token:   gitlabToken,
			Project: gitlabProject,
			BaseURL: gitlabBaseURL,
		})
		for _, f := range findings {
			if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
				result, err := glClient.CreateIssue(ctx, f)
				if err != nil {
					if !silent {
						fmt.Printf("[!] GitLab issue creation failed for %q: %v\n", f.Title, err)
					}
				} else if !silent {
					fmt.Printf("[*] GitLab issue created: %s\n", result.URL)
				}
			}
		}
	}

	// Generate remediation suggestions if requested
	if remediationProvider != "none" {
		if !silent {
			fmt.Println("[*] Generating remediation suggestions...")
		}

		advisor := remediation.NewAdvisor(remediation.AdvisorConfig{
			Provider: remediationProvider,
			APIKey:   remediationAPIKey,
			Model:    remediationModel,
			BaseURL:  remediationBaseURL,
		})
		remediations := advisor.Suggest(ctx, findings)

		if !silent {
			fmt.Println()
			fmt.Println("=========================================")
			fmt.Printf(" REMEDIATION SUGGESTIONS - %d findings\n", len(remediations))
			fmt.Println("=========================================")
			fmt.Println()
		}

		for _, r := range remediations {
			fmt.Printf("  [%s] %s\n", r.Priority, r.Finding.Title)
			fmt.Printf("  Fix: %s\n", r.FixSuggestion)
			if r.CodeFix != "" {
				fmt.Printf("  Code: %s\n", r.CodeFix)
			}
			if len(r.References) > 0 {
				fmt.Printf("  References: %s\n", strings.Join(r.References, ", "))
			}
			fmt.Printf("  Effort: %s | Category: %s\n", r.Effort, r.Category)
			fmt.Println()
		}
	}

	// Generate SBOM if requested
	if sbomGenerate {
		if !silent {
			fmt.Println("[*] Generating Software Bill of Materials (SBOM)...")
		}

		gen := sbom.NewGenerator(targetURL, client)
		bom, err := gen.Generate(ctx)
		if err != nil {
			if !silent {
				fmt.Printf("[!] Failed to generate SBOM: %v\n", err)
			}
		} else {
			xml, err := gen.GenerateCycloneDX(bom)
			if err != nil {
				if !silent {
					fmt.Printf("[!] Failed to generate CycloneDX XML: %v\n", err)
				}
			} else {
				if outputFile != "" {
					sbomFile := outputFile + ".sbom.xml"
					if writeErr := os.WriteFile(sbomFile, []byte(xml), 0644); writeErr != nil {
						if !silent {
							fmt.Printf("[!] Failed to write SBOM file: %v\n", writeErr)
						}
					} else if !silent {
						fmt.Printf("[*] SBOM written to: %s\n", sbomFile)
					}
				}
				if !silent {
					fmt.Println()
					fmt.Println(xml)
				}

				// Correlate SBOM with findings
				if len(findings) > 0 {
					matches := sbom.CorrelateWithFindings(bom, findings)
					if len(matches) > 0 && !silent {
						fmt.Println()
						fmt.Println("=========================================")
						fmt.Printf(" SBOM VULNERABILITY CORRELATION - %d matches\n", len(matches))
						fmt.Println("=========================================")
						for _, m := range matches {
							fmt.Printf("  [%s] %s (%s): %s\n", m.Severity, m.Component.Name, m.Component.Version, m.Description)
						}
					}
				}
			}
		}
	}

	criticalCount := 0
	for _, f := range findings {
		if f.Severity == scanner.SeverityCritical {
			criticalCount++
		}
	}
	if !silent && criticalCount > 0 {
		fmt.Println()
		fmt.Printf("\033[1;31m  %d critical vulnerabilities found\033[0m\n", criticalCount)
		fmt.Println()

		// Point at things that exist. This block used to advertise a hosted
		// report at a domain the project does not run, and tell the user to
		// re-run with "--cloud" — which is not a flag on this command, so the
		// suggested command exits with "unknown flag".
		if outputFile != "" {
			fmt.Println("  => Full results written to:")
			fmt.Println("     " + outputFile)
		} else {
			fmt.Println("  => Write the full results to a file:")
			fmt.Println("     temren scan -t " + targetURL + " --output results.json --format json")
		}
		fmt.Println()
		fmt.Println("  => Or route them somewhere your team already reads:")
		fmt.Println("     --defectdojo-url / --defectdojo-token   push to DefectDojo")
		fmt.Println("     --github-token / --gitlab-token         open issues")
		fmt.Println("     --notify-slack / --notify-discord       post a summary")
		fmt.Println()
	}

	// Exit with error code if critical findings
	if hasCriticalFindings(findings) {
		os.Exit(1)
	}
}

// runPassiveAnalysis runs all passive analyzers
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

// readResponseBody reads response body
func readResponseBody(resp *httpengine.Response) ([]byte, error) {
	if resp.Body != nil {
		return resp.Body, nil
	}
	return resp.ReadBody()
}

func readBodyFromResponse(resp *http.Response) ([]byte, error) {
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

// ScanReport represents the JSON output structure
type ScanReport struct {
	Target        string            `json:"target"`
	Timestamp     string            `json:"timestamp"`
	TotalFindings int               `json:"total_findings"`
	Summary       map[string]int    `json:"summary"`
	Finders       []scanner.Finding `json:"findings"`
	Compliance    []ComplianceEntry `json:"compliance,omitempty"`
}

// ComplianceEntry represents a compliance mapping entry for JSON output
type ComplianceEntry struct {
	Scanner   string `json:"scanner"`
	Title     string `json:"title"`
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Control   string `json:"control_name"`
}

// printResults prints findings to stdout
func printResults(findings []scanner.Finding, format string, silent bool) {
	var complianceFrameworks []report.ComplianceFramework
	if complianceFilter != "" {
		complianceFrameworks = report.ParseFrameworks(complianceFilter)
	}

	if format == "json" {
		summary := make(map[string]int)
		for _, f := range findings {
			summary[string(f.Severity)]++
		}

		var complianceEntries []ComplianceEntry
		if len(complianceFrameworks) > 0 {
			for _, f := range findings {
				mappings := report.MapToCompliance(f)
				filtered := report.FilterByFrameworks(mappings, complianceFrameworks)
				for _, m := range filtered {
					complianceEntries = append(complianceEntries, ComplianceEntry{
						Scanner:   f.Scanner,
						Title:     f.Title,
						Framework: string(m.Framework),
						ControlID: m.ControlID,
						Control:   m.ControlName,
					})
				}
			}
		}

		scanReport := ScanReport{
			Target:        targetURL,
			Timestamp:     time.Now().Format(time.RFC3339),
			TotalFindings: len(findings),
			Summary:       summary,
			Finders:       findings,
			Compliance:    complianceEntries,
		}
		data, _ := json.MarshalIndent(scanReport, "", "  ")
		fmt.Println(string(data))
		return
	}

	if format == "sarif" {
		cfg := report.ReportConfig{Target: targetURL}
		r := report.NewReport(targetURL, findings, cfg)
		fmt.Println(r.GenerateSARIF())
		return
	}

	// Group findings by severity
	grouped := make(map[scanner.Severity][]scanner.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}

	// Print by severity order
	severityOrder := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}

	severityColors := map[scanner.Severity]string{
		scanner.SeverityCritical: "\033[1;31m", // Red
		scanner.SeverityHigh:     "\033[1;31m", // Red
		scanner.SeverityMedium:   "\033[1;33m", // Yellow
		scanner.SeverityLow:      "\033[1;34m", // Blue
		scanner.SeverityInfo:     "\033[1;37m", // White
	}
	reset := "\033[0m"

	for _, sev := range severityOrder {
		findingList, exists := grouped[sev]
		if !exists || len(findingList) == 0 {
			continue
		}

		color := severityColors[sev]
		fmt.Printf("%s[%s]%s %d finding(s)\n", color, sev, reset, len(findingList))
		fmt.Println(strings.Repeat("-", 50))

		for i, f := range findingList {
			fmt.Printf("\n%d. %s\n", i+1, f.Title)
			fmt.Printf("   URL: %s\n", f.URL)
			fmt.Printf("   Scanner: %s\n", f.Scanner)
			if f.Confidence != "" {
				fmt.Printf("   Confidence: %s\n", f.Confidence)
			}
			if f.Description != "" {
				fmt.Printf("   Description: %s\n", f.Description)
			}
			if f.Payload != "" {
				fmt.Printf("   Payload: %s\n", f.Payload)
			}
			if f.Evidence != "" {
				fmt.Printf("   Evidence: %s\n", f.Evidence)
			}

			if len(complianceFrameworks) > 0 {
				mappings := report.MapToCompliance(f)
				filtered := report.FilterByFrameworks(mappings, complianceFrameworks)
				if len(filtered) > 0 {
					fmt.Printf("   Compliance:\n")
					for _, m := range filtered {
						fmt.Printf("     - %s %s: %s\n", m.Framework, m.ControlID, m.ControlName)
					}
				}
			}
		}
		fmt.Println()
	}
}

// writeResults writes findings to file
func writeResults(findings []scanner.Finding, filename, format string) error {
	var data []byte

	if format == "json" {
		summary := make(map[string]int)
		for _, f := range findings {
			summary[string(f.Severity)]++
		}

		var complianceEntries []ComplianceEntry
		complianceFrameworks := report.ParseFrameworks(complianceFilter)
		if len(complianceFrameworks) > 0 {
			for _, f := range findings {
				mappings := report.MapToCompliance(f)
				filtered := report.FilterByFrameworks(mappings, complianceFrameworks)
				for _, m := range filtered {
					complianceEntries = append(complianceEntries, ComplianceEntry{
						Scanner:   f.Scanner,
						Title:     f.Title,
						Framework: string(m.Framework),
						ControlID: m.ControlID,
						Control:   m.ControlName,
					})
				}
			}
		}

		scanReport := ScanReport{
			Target:        targetURL,
			Timestamp:     time.Now().Format(time.RFC3339),
			TotalFindings: len(findings),
			Summary:       summary,
			Finders:       findings,
			Compliance:    complianceEntries,
		}
		data, _ = json.MarshalIndent(scanReport, "", "  ")
	} else if format == "sarif" {
		cfg := report.ReportConfig{Target: targetURL}
		r := report.NewReport(targetURL, findings, cfg)
		data = []byte(r.GenerateSARIF())
	} else {
		// Plain text format
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("TemrenSec Security Scan Report\n"))
		sb.WriteString(fmt.Sprintf("================================\n"))
		sb.WriteString(fmt.Sprintf("Target: %s\n", targetURL))
		sb.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(findings)))

		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("[%s] %s\n", f.Severity, f.Title))
			sb.WriteString(fmt.Sprintf("URL: %s\n", f.URL))
			sb.WriteString(fmt.Sprintf("Scanner: %s\n", f.Scanner))
			if f.Confidence != "" {
				sb.WriteString(fmt.Sprintf("Confidence: %s\n", f.Confidence))
			}
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("Description: %s\n", f.Description))
			}
			if f.Payload != "" {
				sb.WriteString(fmt.Sprintf("Payload: %s\n", f.Payload))
			}
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("Evidence: %s\n", f.Evidence))
			}
			sb.WriteString("\n")
		}
		data = []byte(sb.String())
	}

	return os.WriteFile(filename, data, 0644)
}

// hasCriticalFindings checks for critical/high severity findings
func hasCriticalFindings(findings []scanner.Finding) bool {
	for _, f := range findings {
		if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
			return true
		}
	}
	return false
}
