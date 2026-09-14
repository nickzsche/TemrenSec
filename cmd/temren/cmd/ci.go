package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/report"
	"github.com/temren/pkg/scanner"
	"github.com/temren/pkg/spider"
	"github.com/spf13/cobra"
)

var (
	ciTarget    string
	ciThreshold string
	ciFormat    string
	ciOutput    string
	ciTimeout   int
	ciSkipCrawl bool
	ciMaxPages  int
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Run CI/CD optimized security scan",
	Long: `Run a quick security scan optimized for CI/CD pipelines.

Exit codes:
  0 - No vulnerabilities above threshold found
  1 - Vulnerabilities above threshold found
  2 - Scan error occurred

Examples:
  temren ci --target https://example.com --threshold high
  temren ci --target https://example.com --threshold critical --format sarif --output results.sarif
  temren ci --target https://example.com --threshold medium --skip-crawl
`,
	Run: runCI,
}

func init() {
	rootCmd.AddCommand(ciCmd)

	ciCmd.Flags().StringVarP(&ciTarget, "target", "t", "", "Target URL (required)")
	ciCmd.Flags().StringVar(&ciThreshold, "threshold", "high", "Severity threshold: critical, high, medium, low")
	ciCmd.Flags().StringVarP(&ciFormat, "format", "f", "json", "Output format: json, sarif, text")
	ciCmd.Flags().StringVarP(&ciOutput, "output", "o", "", "Output file path")
	ciCmd.Flags().IntVar(&ciTimeout, "timeout", 300, "Scan timeout in seconds")
	ciCmd.Flags().BoolVar(&ciSkipCrawl, "skip-crawl", false, "Skip crawling, scan only target URL")
	ciCmd.Flags().IntVar(&ciMaxPages, "max-pages", 10, "Maximum pages to crawl")

	ciCmd.MarkFlagRequired("target")
}

var severityOrder = map[scanner.Severity]int{
	scanner.SeverityCritical: 4,
	scanner.SeverityHigh:     3,
	scanner.SeverityMedium:   2,
	scanner.SeverityLow:    1,
	scanner.SeverityInfo:    0,
}

func thresholdSeverity(threshold string) scanner.Severity {
	switch strings.ToLower(threshold) {
	case "critical":
		return scanner.SeverityCritical
	case "high":
		return scanner.SeverityHigh
	case "medium":
		return scanner.SeverityMedium
	case "low":
		return scanner.SeverityLow
	default:
		return scanner.SeverityHigh
	}
}

type ciScanResult struct {
	Target              string            `json:"target"`
	Timestamp           string            `json:"timestamp"`
	Threshold          string            `json:"threshold"`
	TotalFindings      int               `json:"total_findings"`
	SeverityCounts      map[string]int    `json:"severity_counts"`
	FindingsAboveThreshold int            `json:"findings_above_threshold"`
	Passed             bool              `json:"passed"`
	Findings           []scanner.Finding `json:"findings"`
}

func runCI(cmd *cobra.Command, args []string) {
	if !strings.HasPrefix(ciTarget, "http://") && !strings.HasPrefix(ciTarget, "https://") {
		ciTarget = "https://" + ciTarget
	}

	threshold := thresholdSeverity(ciThreshold)
	thresholdLevel := severityOrder[threshold]

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ciTimeout)*time.Second)
	defer cancel()

	cfg := &httpengine.Config{
		Timeout:         time.Duration(ciTimeout) * time.Second,
		RateLimit:       50,
		MaxRedirects:    10,
		FollowRedirects: true,
		UserAgent:       "TemrenSec/1.0 (CI Scanner)",
	}
	client := httpengine.NewClient(cfg)

	urlsToScan := []string{ciTarget}

	if !ciSkipCrawl {
		spiderCfg := &spider.Config{
			MaxDepth:    2,
			MaxPages:    ciMaxPages,
			Concurrency: 10,
			SameDomain:  true,
			Delay:       time.Second / 50,
		}
		s := spider.New(client, spiderCfg)
		results := s.Crawl(ctx, ciTarget)
		for result := range results {
			if result.Error == nil {
				urlsToScan = append(urlsToScan, result.URL)
			}
		}
	}

	// CI mode runs the standard "fast" subset: top OWASP injection + auth + crypto.
	// New scanners added to pkg/scanner are picked up automatically via the registry.
	ciScanners := scanner.EnabledScanners([]string{
		"sql injection", "scripting", "command injection", "ssrf", "path traversal",
		"xxe", "auth", "secret", "cors", "ssti", "nosql", "llm",
	})

	scanEngine := scanner.NewScanEngine(client, ciScanners, 10)

	findings, err := scanEngine.RunAll(ctx, urlsToScan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Scan failed: %v\n", err)
		os.Exit(2)
	}

	for i := range findings {
		vector := scanner.InferCVSS4Vector(findings[i])
		findings[i].CVSSScore = scanner.CalculateCVSS4(vector)
		if findings[i].Severity == "" {
			findings[i].Severity = scanner.SeverityFromCVSS(findings[i].CVSSScore)
		}
	}

	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	findingsAboveThreshold := 0
	for _, f := range findings {
		sev := strings.ToLower(string(f.Severity))
		severityCounts[sev]++
		level, ok := severityOrder[f.Severity]
		if !ok {
			level = 0
		}
		if level >= thresholdLevel {
			findingsAboveThreshold++
		}
	}

	passed := findingsAboveThreshold == 0

	result := ciScanResult{
		Target:                 ciTarget,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		Threshold:             ciThreshold,
		TotalFindings:         len(findings),
		SeverityCounts:        severityCounts,
		FindingsAboveThreshold: findingsAboveThreshold,
		Passed:                passed,
		Findings:              findings,
	}

	switch ciFormat {
	case "sarif":
		rpt := report.NewReport(ciTarget, findings, report.ReportConfig{Target: ciTarget})
		sarifOutput := rpt.GenerateSARIF()
		if ciOutput != "" {
			if writeErr := os.WriteFile(ciOutput, []byte(sarifOutput), 0644); writeErr != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Failed to write SARIF output: %v\n", writeErr)
				os.Exit(2)
			}
		} else {
			fmt.Println(sarifOutput)
		}

	case "text":
		printCIResultText(result)

	default:
		data, jsonErr := json.MarshalIndent(result, "", "  ")
		if jsonErr != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to marshal JSON: %v\n", jsonErr)
			os.Exit(2)
		}
		if ciOutput != "" {
			if writeErr := os.WriteFile(ciOutput, data, 0644); writeErr != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] Failed to write output: %v\n", writeErr)
				os.Exit(2)
			}
		} else {
			fmt.Println(string(data))
		}
	}

	if !passed {
		os.Exit(1)
	}
}

func printCIResultText(result ciScanResult) {
	status := "PASS"
	if !result.Passed {
		status = "FAIL"
	}
	fmt.Printf("Temren CI Scan: %s\n", status)
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Threshold: %s\n", result.Threshold)
	fmt.Printf("Total Findings: %d\n", result.TotalFindings)
	fmt.Printf("Above Threshold: %d\n", result.FindingsAboveThreshold)
	fmt.Printf("  Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d\n",
		result.SeverityCounts["critical"],
		result.SeverityCounts["high"],
		result.SeverityCounts["medium"],
		result.SeverityCounts["low"],
		result.SeverityCounts["info"],
	)
	fmt.Println()

	if len(result.Findings) > 0 {
		fmt.Println("Findings:")
		for _, f := range result.Findings {
			fmt.Printf("  [%s] %s - %s (CVSS: %.1f)\n", f.Severity, f.Title, f.URL, f.CVSSScore)
		}
	}
}