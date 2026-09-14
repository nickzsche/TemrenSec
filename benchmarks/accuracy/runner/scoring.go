// Package main implements precision/recall scoring for Temren accuracy
// benchmarks. Lives under benchmarks/accuracy/runner; not built into the
// main temren binary (separate go module would be cleaner, but we keep it
// in-tree for grep-ability).
package main

import (
	"regexp"
	"strings"
)

// GroundTruth row, parsed from juice-shop/ground_truth.yaml (and peers).
type GroundTruth struct {
	ID          string `yaml:"id"`
	URL         string `yaml:"url"`
	Parameter   string `yaml:"parameter,omitempty"`
	Scanner     string `yaml:"scanner"`
	CWE         string `yaml:"cwe"`
	OWASP2025   string `yaml:"owasp_2025"`
	Severity    string `yaml:"severity"`
	FPOK        bool   `yaml:"fp_ok"`
}

// Reported is the minimal projection of a finding we need to score. We
// take this from whatever JSON the tool under test emits (Temren native,
// ZAP `--format=json`, Nuclei `-jsonl`, etc.).
type Reported struct {
	URL       string
	Parameter string
	Scanner   string
	CWE       string
	Severity  string
}

// Score is per-tool: counts and derived metrics.
type Score struct {
	Tool      string
	TruePos   int
	FalsePos  int
	FalseNeg  int
	Precision float64
	Recall    float64
	F1        float64
}

// Match returns true if a Reported finding matches a GroundTruth row.
// URL match: ground truth URL is treated as a regex (^/path...) when it
// starts with ^, otherwise prefix match. Parameter must match when the
// ground truth specifies one. CWE either matches or one is empty.
func Match(r Reported, gt GroundTruth) bool {
	if !urlMatches(r.URL, gt.URL) {
		return false
	}
	if gt.Parameter != "" && r.Parameter != "" && !strings.EqualFold(r.Parameter, gt.Parameter) {
		return false
	}
	if gt.CWE != "" && r.CWE != "" && !strings.EqualFold(gt.CWE, r.CWE) {
		return false
	}
	return true
}

func urlMatches(have, want string) bool {
	if strings.HasPrefix(want, "^") {
		re, err := regexp.Compile(want)
		if err != nil {
			return false
		}
		return re.MatchString(have)
	}
	return strings.HasPrefix(have, want)
}

// Compute scores a slice of reports against the truth set. Each truth
// row is counted at most once (we don't reward a tool 5x for spamming
// the same URL).
func Compute(tool string, reports []Reported, truth []GroundTruth) Score {
	matchedTruth := make(map[string]bool, len(truth))
	matchedReport := make(map[int]bool, len(reports))

	for ti, gt := range truth {
		for ri, rp := range reports {
			if matchedReport[ri] {
				continue
			}
			if Match(rp, gt) {
				matchedTruth[gt.ID] = true
				matchedReport[ri] = true
				_ = ti
				break
			}
		}
	}

	tp := len(matchedTruth)
	fn := len(truth) - tp
	fp := 0
	for i, rp := range reports {
		if matchedReport[i] {
			continue
		}
		if isFPOK(rp, truth) {
			continue
		}
		fp++
	}

	s := Score{Tool: tool, TruePos: tp, FalsePos: fp, FalseNeg: fn}
	if tp+fp > 0 {
		s.Precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		s.Recall = float64(tp) / float64(tp+fn)
	}
	if s.Precision+s.Recall > 0 {
		s.F1 = 2 * s.Precision * s.Recall / (s.Precision + s.Recall)
	}
	return s
}

// isFPOK lets ground truth flag certain scanners as noisy-but-legitimate
// (security headers fire on every page; that's expected, not 50 FPs).
func isFPOK(r Reported, truth []GroundTruth) bool {
	for _, gt := range truth {
		if gt.FPOK && strings.EqualFold(gt.Scanner, r.Scanner) {
			return true
		}
	}
	return false
}
