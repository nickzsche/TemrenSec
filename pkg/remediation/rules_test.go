package remediation

import (
	"strings"
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestScannerSpecificRule(t *testing.T) {
	a := NewRuleBasedAdvisor()
	r := a.Suggest(scanner.Finding{Scanner: "SQL Injection", Title: "SQLi"})
	if r == nil || !strings.Contains(strings.ToLower(r.FixSuggestion), "parameter") {
		t.Fatalf("SQL için parametreli sorgu önerisi bekleniyordu, gelen: %+v", r)
	}
	if r.CodeFix == "" {
		t.Fatal("SQL kuralı kod örneği içermeli")
	}
}

func TestCategoryFallback(t *testing.T) {
	a := NewRuleBasedAdvisor()
	// Bespoke kuralı olmayan bir scanner ama OWASP kategorisi olan bulgu:
	r := a.Suggest(scanner.Finding{Scanner: "Web Cache Deception", OWASPCategory2025: "A02:2025-Security Misconfiguration"})
	if r == nil {
		t.Fatal("kategori yedeği bir öneri döndürmeli")
	}
	if strings.Contains(r.FixSuggestion, "Review the finding details") {
		t.Fatalf("kategori yedeği yerine generic döndü: %q", r.FixSuggestion)
	}
	if !strings.Contains(strings.ToLower(r.FixSuggestion), "yapılandırma") {
		t.Fatalf("misconfig için yapılandırma önerisi bekleniyordu: %q", r.FixSuggestion)
	}
}

func TestGenericOnlyWhenNoCategory(t *testing.T) {
	a := NewRuleBasedAdvisor()
	r := a.Suggest(scanner.Finding{Scanner: "Totally Unknown Thing"})
	if r == nil || !strings.Contains(r.FixSuggestion, "Review the finding details") {
		t.Fatalf("kategorisiz+kuralsız bulgu generic almalı, gelen: %+v", r)
	}
}
