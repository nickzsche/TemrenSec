package scanner

import (
	"fmt"
	"math"
	"testing"
)

func TestCalculateCVSS4_SQLi(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "C",
		Confidentiality:   "H",
		Integrity:         "H",
		Availability:      "H",
	}
	score := CalculateCVSS4(vector)
	if score < 9.0 || score > 10.0 {
		t.Errorf("SQLi CVSS score = %.1f, want between 9.0 and 10.0", score)
	}
}

func TestCalculateCVSS4_XSS(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "A",
		Scope:              "U",
		Confidentiality:   "N",
		Integrity:         "L",
		Availability:      "N",
	}
	score := CalculateCVSS4(vector)
	if score < 3.0 || score > 6.0 {
		t.Errorf("XSS CVSS score = %.1f, want between 3.0 and 6.0", score)
	}
}

func TestCalculateCVSS4_CommandInjection(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "C",
		Confidentiality:   "H",
		Integrity:         "H",
		Availability:      "H",
	}
	score := CalculateCVSS4(vector)
	if score < 9.0 {
		t.Errorf("Command Injection CVSS score = %.1f, want >= 9.0", score)
	}
	if score > 10.0 {
		t.Errorf("Command Injection CVSS score = %.1f, want <= 10.0", score)
	}
}

func TestCalculateCVSS4_SecurityHeaders(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "P",
		Scope:              "U",
		Confidentiality:   "N",
		Integrity:         "L",
		Availability:      "N",
	}
	score := CalculateCVSS4(vector)
	if score < 4.0 || score > 7.0 {
		t.Errorf("Security Headers CVSS score = %.1f, want between 4.0 and 7.0", score)
	}
}

func TestCalculateCVSS4_ZeroImpact(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "U",
		Confidentiality:   "N",
		Integrity:         "N",
		Availability:      "N",
	}
	score := CalculateCVSS4(vector)
	if score != 0.0 {
		t.Errorf("Zero impact CVSS score = %.1f, want 0.0", score)
	}
}

func TestCalculateCVSS4_PhysicalAttackVector(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "P",
		AttackComplexity:   "H",
		AttackRequirements: "R",
		PrivilegesRequired: "H",
		UserInteraction:    "A",
		Scope:              "U",
		Confidentiality:   "L",
		Integrity:         "L",
		Availability:      "N",
	}
	score := CalculateCVSS4(vector)
	if score > 5.0 {
		t.Errorf("Physical/High complexity CVSS score = %.1f, want <= 5.0", score)
	}
}

func TestCalculateCVSS4_ScopeChanged(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "C",
		Confidentiality:   "H",
		Integrity:         "N",
		Availability:      "N",
	}
	score := CalculateCVSS4(vector)
	if score < 8.0 || score > 10.0 {
		t.Errorf("Scope Changed CVSS score = %.1f, want between 8.0 and 10.0", score)
	}
}

func TestCalculateCVSS4_LowPrivileges(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "L",
		UserInteraction:    "N",
		Scope:              "U",
		Confidentiality:   "H",
		Integrity:         "N",
		Availability:      "N",
	}
	score := CalculateCVSS4(vector)
	if score < 7.0 || score > 9.0 {
		t.Errorf("Low Privileges CVSS score = %.1f, want between 7.0 and 9.0", score)
	}
}

func TestInferCVSS4Vector(t *testing.T) {
	tests := []struct {
		scanner       string
		wantAV        string
		wantScope     string
		wantMinScore  float64
		wantMaxScore  float64
	}{
		{"SQL Injection", "N", "C", 9.0, 10.0},
		{"Cross-Site Scripting (XSS)", "N", "U", 3.0, 7.0},
		{"Command Injection", "N", "C", 9.0, 10.0},
		{"Server-Side Request Forgery (SSRF)", "N", "C", 8.0, 10.0},
		{"Path Traversal", "N", "U", 7.0, 10.0},
		{"XML External Entity (XXE)", "N", "C", 8.0, 10.0},
		{"Authentication Failures", "N", "U", 5.0, 8.0},
		{"CORS Misconfiguration", "N", "U", 4.0, 7.0},
		{"Server-Side Template Injection (SSTI)", "N", "C", 9.0, 10.0},
		{"NoSQL Injection", "N", "C", 9.0, 10.0},
		{"Secret Scanner", "N", "C", 9.0, 10.0},
		{"Insecure Direct Object Reference (IDOR)", "N", "U", 7.0, 9.0},
		{"Unknown Scanner", "N", "U", 7.0, 10.0},
	}

	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			finding := Finding{Scanner: tt.scanner}
			vector := InferCVSS4Vector(finding)
			if vector.AttackVector != tt.wantAV {
				t.Errorf("InferCVSS4Vector(%q).AttackVector = %q, want %q", tt.scanner, vector.AttackVector, tt.wantAV)
			}
			if vector.Scope != tt.wantScope {
				t.Errorf("InferCVSS4Vector(%q).Scope = %q, want %q", tt.scanner, vector.Scope, tt.wantScope)
			}
			score := CalculateCVSS4(vector)
			if score < tt.wantMinScore || score > tt.wantMaxScore {
				t.Errorf("InferCVSS4Vector(%q) score = %.1f, want between %.1f and %.1f", tt.scanner, score, tt.wantMinScore, tt.wantMaxScore)
			}
		})
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  Severity
	}{
		{10.0, SeverityCritical},
		{9.5, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.5, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{5.0, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{2.0, SeverityLow},
		{0.1, SeverityLow},
		{0.0, SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%.1f", tt.score), func(t *testing.T) {
			got := SeverityFromCVSS(tt.score)
			if got != tt.want {
				t.Errorf("SeverityFromCVSS(%.1f) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestVectorString(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "C",
		Confidentiality:   "H",
		Integrity:         "H",
		Availability:      "H",
	}
	want := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/S:C/C:H/I:H/A:H"
	got := vector.VectorString()
	if got != want {
		t.Errorf("VectorString() = %q, want %q", got, want)
	}
}

func TestParseCVSS4Vector(t *testing.T) {
	vectorStr := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/S:C/C:H/I:H/A:H"
	vector := ParseCVSS4Vector(vectorStr)
	if vector.AttackVector != "N" {
		t.Errorf("ParseCVSS4Vector AttackVector = %q, want %q", vector.AttackVector, "N")
	}
	if vector.AttackComplexity != "L" {
		t.Errorf("ParseCVSS4Vector AttackComplexity = %q, want %q", vector.AttackComplexity, "L")
	}
	if vector.Scope != "C" {
		t.Errorf("ParseCVSS4Vector Scope = %q, want %q", vector.Scope, "C")
	}
	if vector.Confidentiality != "H" {
		t.Errorf("ParseCVSS4Vector Confidentiality = %q, want %q", vector.Confidentiality, "H")
	}
}

func TestRoundup(t *testing.T) {
	tests := []struct {
		input float64
		want  float64
	}{
		{7.51, 7.6},
		{7.50, 7.5},
		{0.01, 0.1},
		{9.99, 10.0},
		{5.0, 5.0},
	}
	for _, tt := range tests {
		got := roundup(tt.input)
		if math.Abs(got-tt.want) > 0.001 {
			t.Errorf("roundup(%.2f) = %.1f, want %.1f", tt.input, got, tt.want)
		}
	}
}

func TestCalculateCVSS4_Roundtrip(t *testing.T) {
	vector := CVSS4Vector{
		AttackVector:       "N",
		AttackComplexity:   "L",
		AttackRequirements: "N",
		PrivilegesRequired: "N",
		UserInteraction:    "N",
		Scope:              "C",
		Confidentiality:   "H",
		Integrity:         "H",
		Availability:      "H",
	}
	vectorStr := vector.VectorString()
	parsed := ParseCVSS4Vector(vectorStr)
	originalScore := CalculateCVSS4(vector)
	parsedScore := CalculateCVSS4(parsed)
	if math.Abs(originalScore-parsedScore) > 0.001 {
		t.Errorf("Roundtrip score mismatch: original=%.1f, parsed=%.1f", originalScore, parsedScore)
	}
}