package policy

import (
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestEvalSeverityEquals(t *testing.T) {
	cases := []struct {
		expr string
		sev  scanner.Severity
		want bool
	}{
		{`severity == "CRITICAL"`, scanner.SeverityCritical, true},
		{`severity == "CRITICAL"`, scanner.SeverityLow, false},
		{`severity != "INFO"`, scanner.SeverityHigh, true},
		{`cvss >= 7`, scanner.SeverityHigh, true},
		{`cvss < 1 || severity == "HIGH"`, scanner.SeverityHigh, true},
	}
	for _, c := range cases {
		env := map[string]any{"severity": string(c.sev), "cvss": 8.5}
		got, err := eval(c.expr, env)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got != c.want {
			t.Errorf("%s with sev %s: got %v want %v", c.expr, c.sev, got, c.want)
		}
	}
}

func TestEvalContainsAssetTag(t *testing.T) {
	env := map[string]any{"severity": "HIGH", "cvss": 8.0, "asset.tag": []string{"prod", "pii"}}
	got, err := eval(`severity == "HIGH" && asset.tag contains "prod"`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Error("expected true")
	}
}

func TestPolicyEvaluate(t *testing.T) {
	yamlBlob := []byte(`rules:
  - name: block-prod-criticals
    when: severity == "CRITICAL" && asset.tag contains "prod"
    action: fail
    message: "Critical on prod"
  - name: warn-headers
    when: scanner == "Security Headers Audit"
    action: warn
`)
	p, err := Load(yamlBlob)
	if err != nil {
		t.Fatal(err)
	}
	findings := []scanner.Finding{
		{Severity: scanner.SeverityCritical, CVSSScore: 9.0, Scanner: "sqli"},
		{Severity: scanner.SeverityLow, Scanner: "Security Headers Audit"},
	}
	decisions, err := p.Evaluate(findings, []string{"prod", "pii"})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}
	if !HasFailure(decisions) {
		t.Error("expected fail decision present")
	}
}
