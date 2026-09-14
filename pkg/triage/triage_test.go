package triage

import (
	"strings"
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestFingerprintCollapsesNumericIDs(t *testing.T) {
	a := scanner.Finding{Scanner: "idor", URL: "https://x.com/users/42", Parameter: "id", Title: "IDOR"}
	b := scanner.Finding{Scanner: "idor", URL: "https://x.com/users/9999", Parameter: "id", Title: "IDOR"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("expected same fingerprint, got\n%s\n%s", Fingerprint(a), Fingerprint(b))
	}
}

func TestFingerprintCollapsesHexAndUUIDs(t *testing.T) {
	a := scanner.Finding{Scanner: "idor", URL: "https://x.com/files/c3a8d9f0e2b1"}
	b := scanner.Finding{Scanner: "idor", URL: "https://x.com/files/aaaaaaaaaaaa"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("hex ids should be collapsed")
	}
}

func TestSuppression(t *testing.T) {
	findings := []scanner.Finding{
		{Scanner: "headers", Severity: scanner.SeverityLow, URL: "https://x.com/a"},
		{Scanner: "sqli", Severity: scanner.SeverityHigh, URL: "https://x.com/api"},
	}
	res := Run(findings, Config{Suppressions: []Suppression{{Scanner: "headers"}}})
	if len(res.Findings) != 1 || res.Suppressed != 1 {
		t.Fatalf("suppression failed: %+v", res)
	}
}

func TestSeverityOverride(t *testing.T) {
	findings := []scanner.Finding{
		{Scanner: "headers", Severity: scanner.SeverityLow, URL: "https://prod.com/x"},
	}
	res := Run(findings, Config{Overrides: []SeverityOverride{
		{URL: "https://prod.com/*", To: scanner.SeverityHigh},
	}})
	if res.Findings[0].Severity != scanner.SeverityHigh || res.Overridden != 1 {
		t.Errorf("override failed: %+v", res)
	}
}

func TestDedupReportsExtraURLs(t *testing.T) {
	findings := []scanner.Finding{
		{Scanner: "idor", URL: "https://x.com/u/1", Parameter: "id", Title: "IDOR"},
		{Scanner: "idor", URL: "https://x.com/u/2", Parameter: "id", Title: "IDOR"},
		{Scanner: "idor", URL: "https://x.com/u/3", Parameter: "id", Title: "IDOR"},
	}
	res := Run(findings, Config{})
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 collapsed finding, got %d", len(res.Findings))
	}
	if res.Dedup != 2 {
		t.Errorf("expected 2 dedups, got %d", res.Dedup)
	}
	if !strings.Contains(res.Findings[0].Description, "/u/2") {
		t.Errorf("missing extra URL note: %q", res.Findings[0].Description)
	}
}

func TestSeverityOrder(t *testing.T) {
	findings := []scanner.Finding{
		{Scanner: "a", URL: "https://x.com/a", Severity: scanner.SeverityLow},
		{Scanner: "b", URL: "https://x.com/b", Severity: scanner.SeverityCritical},
		{Scanner: "c", URL: "https://x.com/c", Severity: scanner.SeverityMedium},
	}
	res := Run(findings, Config{})
	if res.Findings[0].Severity != scanner.SeverityCritical {
		t.Errorf("critical should be first")
	}
}
