// Package scandiff computes a semantic diff between two scan runs:
//   - Added findings
//   - Fixed findings
//   - Severity changed (regressed / improved)
//   - Stable findings
//
// Identity uses the triage fingerprint when available, otherwise (scanner, URL, parameter).
package scandiff

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/temren/pkg/scanner"
)

type Result struct {
	Added       []scanner.Finding
	Fixed       []scanner.Finding
	Regressed   []SeverityChange
	Improved    []SeverityChange
	Stable      int
}

type SeverityChange struct {
	Finding scanner.Finding
	From    scanner.Severity
	To      scanner.Severity
}

// Diff compares two finding lists.
func Diff(baseline, current []scanner.Finding) Result {
	var r Result
	bIdx := index(baseline)
	cIdx := index(current)

	for fp, c := range cIdx {
		b, ok := bIdx[fp]
		if !ok {
			r.Added = append(r.Added, c)
			continue
		}
		if b.Severity == c.Severity {
			r.Stable++
		} else if severityRank[c.Severity] > severityRank[b.Severity] {
			r.Regressed = append(r.Regressed, SeverityChange{Finding: c, From: b.Severity, To: c.Severity})
		} else {
			r.Improved = append(r.Improved, SeverityChange{Finding: c, From: b.Severity, To: c.Severity})
		}
	}
	for fp, b := range bIdx {
		if _, ok := cIdx[fp]; !ok {
			r.Fixed = append(r.Fixed, b)
		}
	}
	return r
}

var severityRank = map[scanner.Severity]int{
	scanner.SeverityCritical: 4,
	scanner.SeverityHigh:     3,
	scanner.SeverityMedium:   2,
	scanner.SeverityLow:      1,
	scanner.SeverityInfo:     0,
}

func index(fs []scanner.Finding) map[string]scanner.Finding {
	out := make(map[string]scanner.Finding, len(fs))
	for _, f := range fs {
		key := f.Scanner + "|" + normalizeURL(f.URL) + "|" + f.Parameter + "|" + f.Title
		sum := sha1.Sum([]byte(key))
		out[hex.EncodeToString(sum[:])] = f
	}
	return out
}

func normalizeURL(u string) string {
	if i := strings.Index(u, "?"); i >= 0 {
		return u[:i]
	}
	return u
}
