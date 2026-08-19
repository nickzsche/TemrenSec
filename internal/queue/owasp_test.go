package queue

import (
	"regexp"
	"strings"
	"testing"

	"github.com/temren/pkg/scanner"
)

// validOWASP2021 matches A01..A10 for the 2021 Top 10. "A00" — what the old
// fallback returned — is deliberately not a valid category.
var validOWASP2021 = regexp.MustCompile(`^A(0[1-9]|10):2021$`)

// TestEveryRegisteredScannerMapsToARealCategory walks the shared registry and
// asserts each scanner resolves to a real OWASP category.
//
// The mapping table used to be keyed on informal names ("XSS", "IDOR", "JWT")
// that matched no scanner, so most findings were filed under a category that
// does not exist. Adding a scanner without a category now fails here.
func TestEveryRegisteredScannerMapsToARealCategory(t *testing.T) {
	all := scanner.AllScanners()
	if len(all) == 0 {
		t.Fatal("registry returned no scanners")
	}

	for _, s := range all {
		name := s.Name()
		got := mapScannerToOWASP(name)

		if !validOWASP2021.MatchString(got) {
			t.Errorf("scanner %q mapped to %q, which is not an OWASP 2021 category", name, got)
		}
	}
}

// TestOWASPTableKeysMatchRealScanners is the check that would have caught the
// original bug: every key in the explicit table must be a name some registered
// scanner actually reports.
func TestOWASPTableKeysMatchRealScanners(t *testing.T) {
	registered := map[string]bool{}
	for _, s := range scanner.AllScanners() {
		registered[s.Name()] = true
	}

	for key := range owaspByScannerName {
		if !registered[key] {
			t.Errorf("owaspByScannerName has key %q, but no registered scanner reports that name", key)
		}
	}
}

// TestInjectionScannersAreA03 pins the categories that were previously wrong:
// SQL injection, XSS and command injection were all filed under A06
// (Vulnerable and Outdated Components) instead of A03 (Injection).
func TestInjectionScannersAreA03(t *testing.T) {
	for _, name := range []string{
		"SQL Injection",
		"NoSQL Injection",
		"Cross-Site Scripting (XSS)",
		"Command Injection",
		"LDAP Injection",
	} {
		if got := mapScannerToOWASP(name); got != "A03:2021" {
			t.Errorf("mapScannerToOWASP(%q) = %q, want A03:2021 (Injection)", name, got)
		}
	}
}

// TestSSRFIsA10 — SSRF has its own category in the 2021 list.
func TestSSRFIsA10(t *testing.T) {
	if got := mapScannerToOWASP("SSRF — Cloud Metadata"); got != "A10:2021" {
		t.Errorf("SSRF mapped to %q, want A10:2021", got)
	}
}

func TestAccessControlScannersAreA01(t *testing.T) {
	for _, name := range []string{
		"Insecure Direct Object Reference (IDOR)",
		"Path Traversal",
		"Open Redirect",
	} {
		if got := mapScannerToOWASP(name); got != "A01:2021" {
			t.Errorf("mapScannerToOWASP(%q) = %q, want A01:2021", name, got)
		}
	}
}

// TestUnknownScannerFallsBackToARealCategory — an unrecognised name must still
// produce something valid, never "A00:2021".
func TestUnknownScannerFallsBackToARealCategory(t *testing.T) {
	got := mapScannerToOWASP("Totally Novel Check That Matches No Keyword")
	if !validOWASP2021.MatchString(got) {
		t.Errorf("unknown scanner mapped to %q, which is not a real category", got)
	}
	if strings.HasPrefix(got, "A00") {
		t.Errorf("unknown scanner mapped to A00, which is not an OWASP category")
	}
}

// TestKeywordFallbackCatchesRenames — if a scanner is renamed, the keyword rules
// should still place it sensibly rather than dropping it into the default.
func TestKeywordFallbackCatchesRenames(t *testing.T) {
	cases := map[string]string{
		"Blind SQL Injection (time-based)": "A03:2021",
		"Reflected Cross-Site Scripting":   "A03:2021",
		"SSRF via PDF renderer":            "A10:2021",
		"JWT kid Path Traversal":           "A01:2021",
		"Outdated jQuery component":        "A06:2021",
		"Weak TLS configuration":           "A02:2021",
	}
	for name, want := range cases {
		if got := mapScannerToOWASP(name); got != want {
			t.Errorf("mapScannerToOWASP(%q) = %q, want %q", name, got, want)
		}
	}
}
