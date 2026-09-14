package scanner

import (
	"testing"
)

func findScenario(paths []AttackPath, name string) *AttackPath {
	for i := range paths {
		if paths[i].Name == name {
			return &paths[i]
		}
	}
	return nil
}

func TestScenario_AccountTakeover(t *testing.T) {
	findings := []Finding{
		makeFinding("Open Redirect", "https://app.example.com/go?url=x", "Open redirect", SeverityMedium, 6.1),
		makeFinding("Security Headers Audit", "https://app.example.com/", "Missing CSP", SeverityLow, 3.1),
		makeFinding("Cross-Site Scripting (XSS)", "https://app.example.com/search?q=x", "Reflected XSS", SeverityHigh, 7.4),
	}
	paths := NewAttackPathAnalyzer(findings).Analyze()
	ap := findScenario(paths, "Account takeover chain")
	if ap == nil {
		t.Fatalf("expected account takeover scenario, got %d paths", len(paths))
	}
	if ap.OverallRisk != SeverityCritical || ap.OverallCVSS < 9.0 {
		t.Errorf("expected critical/high-cvss chain, got %s / %.1f", ap.OverallRisk, ap.OverallCVSS)
	}
	if len(ap.Steps) != 3 {
		t.Errorf("expected 3 steps, got %d", len(ap.Steps))
	}
}

func TestScenario_PrivilegeEscalation(t *testing.T) {
	findings := []Finding{
		makeFinding("Insecure Direct Object Reference (IDOR)", "https://api.example.com/orders?id=5", "IDOR", SeverityHigh, 7.1),
		makeFinding("Authentication Failures", "https://api.example.com/login", "Weak auth", SeverityHigh, 8.0),
	}
	paths := NewAttackPathAnalyzer(findings).Analyze()
	if findScenario(paths, "Privilege escalation chain") == nil {
		t.Fatalf("expected privilege escalation scenario, got %+v", paths)
	}
}

func TestScenario_SessionHijack(t *testing.T) {
	findings := []Finding{
		makeFinding("Subdomain Takeover", "https://blog.example.com/", "Dangling CNAME", SeverityHigh, 8.1),
		makeFinding("Session Fixation", "https://blog.example.com/login", "Session fixation", SeverityMedium, 5.4),
	}
	paths := NewAttackPathAnalyzer(findings).Analyze()
	if findScenario(paths, "Session hijack chain") == nil {
		t.Fatalf("expected session hijack scenario, got %+v", paths)
	}
}

func TestScenario_RequiresSameHost(t *testing.T) {
	// Open redirect and XSS on different hosts must NOT form the chain.
	findings := []Finding{
		makeFinding("Open Redirect", "https://a.example.com/go?url=x", "Open redirect", SeverityMedium, 6.1),
		makeFinding("Security Headers Audit", "https://a.example.com/", "Missing CSP", SeverityLow, 3.1),
		makeFinding("Cross-Site Scripting (XSS)", "https://b.example.com/search?q=x", "Reflected XSS", SeverityHigh, 7.4),
	}
	paths := NewAttackPathAnalyzer(findings).Analyze()
	if findScenario(paths, "Account takeover chain") != nil {
		t.Fatal("chain should not form across different hosts")
	}
}

func TestScenario_EmptyFindings(t *testing.T) {
	if paths := NewAttackPathAnalyzer(nil).Analyze(); len(paths) != 0 {
		t.Fatalf("expected no paths for no findings, got %d", len(paths))
	}
}
