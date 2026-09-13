package queue

import (
	"strings"
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestOwaspCategoryPrefers2025(t *testing.T) {
	f := scanner.Finding{OWASPCategory2025: "A02:2025-Security Misconfiguration", OWASPCategory: "A05:2021"}
	if got := owaspCategory(f); got != "A02:2025-Security Misconfiguration" {
		t.Fatalf("2025 etiketi tercih edilmeli, gelen %q", got)
	}
}

func TestOwaspCategoryNormalizes2021(t *testing.T) {
	// Pasif bulgu: sadece ham 2021 tag'i var → 2025'e maplenmeli
	f := scanner.Finding{OWASPCategory: "A03:2021"}
	got := owaspCategory(f)
	if !strings.Contains(got, ":2025-") {
		t.Fatalf("2021 tag 2025'e normalize olmalı, gelen %q", got)
	}
	if !strings.Contains(got, "Injection") {
		t.Fatalf("A03:2021 (Injection) → A05:2025-Injection bekleniyordu, gelen %q", got)
	}
}

func TestOwaspCategoryMalformedFallsToGuess(t *testing.T) {
	// Bozuk etiket (yıl yok) → keyword tahminine düşmeli, olduğu gibi geçmemeli
	f := scanner.Finding{Scanner: "Default Credentials", Title: "Default creds", OWASPCategory: "A08 Authentication Failures"}
	got := owaspCategory(f)
	if got == "A08 Authentication Failures" {
		t.Fatal("bozuk etiket olduğu gibi geçmemeli")
	}
	if !strings.Contains(got, ":2025-") {
		t.Fatalf("kanonik 2025 etiketi bekleniyordu, gelen %q", got)
	}
}

func TestGuessOWASPKeywords(t *testing.T) {
	cases := map[string]string{
		"SQL Injection":        "A03:2021",
		"JWT Analysis":         "A07:2021",
		"TLS Audit":            "A02:2021",
		"Security Headers":     "A05:2021",
		"Technology Detection": "A00:2021",
	}
	for scannerName, want := range cases {
		got := guessOWASP(scanner.Finding{Scanner: scannerName})
		if got != want {
			t.Errorf("%s: beklenen %s, gelen %s", scannerName, want, got)
		}
	}
}

func TestFixTextRich(t *testing.T) {
	txt := fixText(scanner.Finding{Scanner: "SQL Injection", Title: "SQLi"})
	if !strings.Contains(txt, "Kaynaklar:") {
		t.Fatalf("SQL fix'i kaynak içermeli, gelen: %q", txt)
	}
}

func TestIsCanonicalOWASP(t *testing.T) {
	if !isCanonicalOWASP("A02:2025-Security Misconfiguration") {
		t.Fatal("kanonik etiket true olmalı")
	}
	if isCanonicalOWASP("A08 Authentication Failures") {
		t.Fatal("bozuk etiket false olmalı")
	}
}
