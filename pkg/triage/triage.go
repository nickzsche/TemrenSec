// Package triage de-duplicates and re-prioritizes findings before they reach
// downstream channels (issue trackers, dashboards, paging). It applies:
//
//   - Stable fingerprinting   group near-duplicates (same scanner + host + path
//                              shape + parameter family)
//   - Suppression rules       drop findings matching a YAML allowlist
//   - Severity overrides      bump or lower severity per rule
//
// Triage is idempotent: re-running it on already-triaged findings is a no-op.
package triage

import (
	"crypto/sha1"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/temren/pkg/scanner"
)

// Suppression matches and discards findings.
type Suppression struct {
	Scanner string `yaml:"scanner,omitempty"`
	URL     string `yaml:"url,omitempty"`      // glob
	Param   string `yaml:"param,omitempty"`
	Reason  string `yaml:"reason,omitempty"`
}

// SeverityOverride bumps or lowers severity for matching findings.
type SeverityOverride struct {
	Scanner string           `yaml:"scanner,omitempty"`
	URL     string           `yaml:"url,omitempty"`
	To      scanner.Severity `yaml:"to"`
}

// Config tunes the engine.
type Config struct {
	Suppressions []Suppression      `yaml:"suppressions"`
	Overrides    []SeverityOverride `yaml:"overrides"`
}

// Result is the triage outcome.
type Result struct {
	Findings   []scanner.Finding
	Dedup      int // number of findings collapsed into representatives
	Suppressed int // number of findings filtered out
	Overridden int
}

// Run applies dedup + suppression + overrides and returns the cleaned list.
func Run(findings []scanner.Finding, cfg Config) Result {
	var res Result
	if len(findings) == 0 {
		return res
	}

	// Suppression first — cheapest, drops the most noise.
	filtered := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if matchesAnySuppression(f, cfg.Suppressions) {
			res.Suppressed++
			continue
		}
		filtered = append(filtered, f)
	}

	// Dedup via fingerprint.
	groups := map[string]int{}
	out := make([]scanner.Finding, 0, len(filtered))
	for _, f := range filtered {
		fp := Fingerprint(f)
		if idx, ok := groups[fp]; ok {
			// Bump rep's evidence with extra URL.
			rep := &out[idx]
			rep.Description = appendUnique(rep.Description, "Also seen at "+f.URL)
			res.Dedup++
			continue
		}
		groups[fp] = len(out)
		out = append(out, f)
	}

	// Overrides.
	for i := range out {
		for _, o := range cfg.Overrides {
			if matchesOverride(out[i], o) {
				out[i].Severity = o.To
				res.Overridden++
				break
			}
		}
	}

	// Stable order: severity desc, then URL.
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank[out[i].Severity] != severityRank[out[j].Severity] {
			return severityRank[out[i].Severity] > severityRank[out[j].Severity]
		}
		return out[i].URL < out[j].URL
	})

	res.Findings = out
	return res
}

var severityRank = map[scanner.Severity]int{
	scanner.SeverityCritical: 4,
	scanner.SeverityHigh:     3,
	scanner.SeverityMedium:   2,
	scanner.SeverityLow:      1,
	scanner.SeverityInfo:     0,
}

// Fingerprint hashes (scanner, host, path-shape, parameter) to a stable ID so
// /users/42 and /users/77 collapse together.
func Fingerprint(f scanner.Finding) string {
	host, pathShape := shape(f.URL)
	src := strings.Join([]string{f.Scanner, host, pathShape, f.Parameter, f.Title}, "|")
	sum := sha1.Sum([]byte(src))
	return hex.EncodeToString(sum[:])
}

var idChunk = regexp.MustCompile(`/(?:[0-9]+|[0-9a-f]{8,}|[A-Z0-9]{12,})`)

func shape(raw string) (host, pathShape string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, raw
	}
	shaped := idChunk.ReplaceAllString(u.Path, "/{id}")
	return u.Host, shaped
}

func matchesAnySuppression(f scanner.Finding, rules []Suppression) bool {
	for _, r := range rules {
		if r.Scanner != "" && !strings.EqualFold(r.Scanner, f.Scanner) {
			continue
		}
		if r.Param != "" && !strings.EqualFold(r.Param, f.Parameter) {
			continue
		}
		if r.URL != "" && !globMatch(r.URL, f.URL) {
			continue
		}
		return true
	}
	return false
}

func matchesOverride(f scanner.Finding, o SeverityOverride) bool {
	if o.Scanner != "" && !strings.EqualFold(o.Scanner, f.Scanner) {
		return false
	}
	if o.URL != "" && !globMatch(o.URL, f.URL) {
		return false
	}
	return true
}

// globMatch supports *, ** wildcards.
func globMatch(pattern, s string) bool {
	regex := "^" + regexp.QuoteMeta(pattern) + "$"
	regex = strings.ReplaceAll(regex, `\*\*`, `.*`)
	regex = strings.ReplaceAll(regex, `\*`, `[^/]*`)
	re, err := regexp.Compile(regex)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

func appendUnique(haystack, line string) string {
	if strings.Contains(haystack, line) {
		return haystack
	}
	if haystack == "" {
		return line
	}
	return haystack + "\n" + line
}

// Suppress drops findings matching any rule and returns the kept findings plus
// the number removed. Unlike Run it does only suppression (no dedup/overrides),
// so callers that already deduped (e.g. the scan engine) don't collapse twice.
func Suppress(findings []scanner.Finding, rules []Suppression) ([]scanner.Finding, int) {
	if len(rules) == 0 {
		return findings, 0
	}
	kept := make([]scanner.Finding, 0, len(findings))
	removed := 0
	for _, f := range findings {
		if matchesAnySuppression(f, rules) {
			removed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, removed
}
