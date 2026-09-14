package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	target := flag.String("target", "http://localhost:3000", "URL of the running benchmark target")
	truthPath := flag.String("truth", "", "Path to ground_truth.yaml")
	compare := flag.String("compare", "", "Comma-separated list: zap,nuclei (optional)")
	temrenBin := flag.String("temren", "temren", "Path to the temren binary")
	reportDir := flag.String("out", "reports", "Output directory for the markdown report")
	flag.Parse()

	if *truthPath == "" {
		fmt.Fprintln(os.Stderr, "--truth is required")
		os.Exit(2)
	}

	truth, err := loadTruth(*truthPath)
	if err != nil {
		fail("load truth: %v", err)
	}
	fmt.Fprintf(os.Stderr, "loaded %d ground-truth findings\n", len(truth))

	var scores []Score

	// 1. Temren
	t0 := time.Now()
	temrenReports, err := runTemren(*temrenBin, *target)
	dur := time.Since(t0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "temren run failed: %v (continuing with partial reports)\n", err)
	}
	s := Compute("temren", temrenReports, truth)
	scores = append(scores, withSeconds(s, dur))

	// 2. Optional competitors
	for _, comp := range strings.Split(*compare, ",") {
		comp = strings.TrimSpace(comp)
		if comp == "" {
			continue
		}
		t0 := time.Now()
		var reports []Reported
		var err error
		switch comp {
		case "zap":
			reports, err = runZAP(*target)
		case "nuclei":
			reports, err = runNuclei(*target)
		default:
			fmt.Fprintf(os.Stderr, "skip unknown comparator %q\n", comp)
			continue
		}
		dur := time.Since(t0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s run failed: %v\n", comp, err)
		}
		scores = append(scores, withSeconds(Compute(comp, reports, truth), dur))
	}

	report := buildReport(scores, truth, *target)
	fmt.Print(report)

	if err := os.MkdirAll(*reportDir, 0o755); err != nil {
		fail("mkdir reports: %v", err)
	}
	out := filepath.Join(*reportDir, fmt.Sprintf("run-%s.md", time.Now().Format("20060102-150405")))
	_ = os.WriteFile(out, []byte(report), 0o644)
	fmt.Fprintf(os.Stderr, "\nfull report: %s\n", out)
}

// withSeconds attaches duration metadata to a Score for the markdown table.
// Score struct doesn't carry runtime to keep scoring.go pure; we render
// duration alongside it.
type scoredRun struct {
	Score
	Seconds int
}

var runtimes = map[string]int{}

func withSeconds(s Score, d time.Duration) Score {
	runtimes[s.Tool] = int(d.Seconds())
	return s
}

func loadTruth(path string) ([]GroundTruth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Findings []GroundTruth `yaml:"findings"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Findings, nil
}

// runTemren invokes `temren scan --target <url> --format json` and parses
// the JSON. We don't import pkg/scanner directly because the benchmark
// must measure the binary end-to-end (spider + scanners + plugins + ai).
func runTemren(bin, target string) ([]Reported, error) {
	cmd := exec.Command(bin, "scan", "--target", target, "--format", "json", "--no-progress")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("temren scan: %w", err)
	}
	var payload struct {
		Findings []struct {
			URL       string `json:"url"`
			Parameter string `json:"parameter"`
			Scanner   string `json:"scanner"`
			Severity  string `json:"severity"`
			OWASP     string `json:"owasp_category"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil, fmt.Errorf("decode temren json: %w", err)
	}
	reports := make([]Reported, 0, len(payload.Findings))
	for _, f := range payload.Findings {
		reports = append(reports, Reported{
			URL:       f.URL,
			Parameter: f.Parameter,
			Scanner:   f.Scanner,
			Severity:  f.Severity,
		})
	}
	return reports, nil
}

// runZAP / runNuclei are stubs that shell out to Docker. The harness is
// useful even when comparators are unavailable — they'll just be skipped.
func runZAP(target string) ([]Reported, error) {
	return nil, fmt.Errorf("ZAP comparator not yet wired — install owasp/zap2docker-stable and run zap-baseline.py")
}

func runNuclei(target string) ([]Reported, error) {
	return nil, fmt.Errorf("Nuclei comparator not yet wired — install projectdiscovery/nuclei and add a json parser here")
}

func buildReport(scores []Score, truth []GroundTruth, target string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Temren accuracy benchmark — %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "**Target:** %s  \n", target)
	fmt.Fprintf(&b, "**Ground truth rows:** %d\n\n", len(truth))

	fmt.Fprintln(&b, "| Tool   | TP | FP | FN | Precision | Recall | F1   | Seconds |")
	fmt.Fprintln(&b, "|--------|----|----|----|-----------|--------|------|---------|")
	for _, s := range scores {
		fmt.Fprintf(&b, "| %-6s | %2d | %2d | %2d | %.2f      | %.2f   | %.2f | %d |\n",
			s.Tool, s.TruePos, s.FalsePos, s.FalseNeg, s.Precision, s.Recall, s.F1, runtimes[s.Tool])
	}
	return b.String()
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
