package compliance

import (
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestMapInjectionFinding(t *testing.T) {
	f := scanner.Finding{
		Title:         "SQL Injection",
		Scanner:       "sqli",
		OWASPCategory: "A03:2021-Injection",
		Severity:      scanner.SeverityHigh,
	}
	hits := Map(f)
	if len(hits) == 0 {
		t.Fatal("expected injection finding to map to controls")
	}
	seenASVS := false
	for _, h := range hits {
		if h.Framework == ASVS {
			seenASVS = true
		}
	}
	if !seenASVS {
		t.Errorf("expected ASVS hit for injection, got: %+v", hits)
	}
}

func TestSummaryAggregates(t *testing.T) {
	findings := []scanner.Finding{
		{Scanner: "sqli", OWASPCategory: "A03:2021-Injection", Severity: scanner.SeverityCritical},
		{Scanner: "headers", OWASPCategory: "A05:2021-Security Misconfiguration", Severity: scanner.SeverityHigh},
		{Scanner: "sqli", OWASPCategory: "A03:2021-Injection", Severity: scanner.SeverityHigh},
	}
	s := Summary(findings)
	if len(s) == 0 {
		t.Fatal("expected non-empty summary")
	}
	for _, fw := range s {
		if fw.Findings == 0 {
			t.Errorf("framework %s has 0 findings", fw.Framework)
		}
	}
}

func TestMapDeduplicatesControls(t *testing.T) {
	f := scanner.Finding{
		Title:         "Injection",
		Scanner:       "injection",
		OWASPCategory: "A03:2021-Injection",
	}
	hits := Map(f)
	seen := map[string]int{}
	for _, h := range hits {
		seen[string(h.Framework)+"|"+h.ControlID]++
	}
	for k, c := range seen {
		if c > 1 {
			t.Errorf("control %s reported %d times — should be deduped", k, c)
		}
	}
}
