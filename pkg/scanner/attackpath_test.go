package scanner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func makeFinding(scannerName, urlStr, title string, severity Severity, cvss float64) Finding {
	return Finding{
		URL:           urlStr,
		Title:         title,
		Description:   title,
		Severity:      severity,
		Confidence:    ConfidenceHigh,
		Scanner:       scannerName,
		Timestamp:     time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		CVSSScore:     cvss,
		OWASPCategory: "A01:2021",
	}
}

func TestChainByURL(t *testing.T) {
	findings := []Finding{
		makeFinding("SQL Injection", "https://example.com/users?id=1", "SQL Injection in users", SeverityCritical, 9.8),
		makeFinding("Cross-Site Scripting (XSS)", "https://example.com/search?q=test", "XSS in search", SeverityHigh, 6.1),
		makeFinding("Path Traversal", "https://example.com/files?path=etc", "Path traversal in files", SeverityHigh, 7.5),
		makeFinding("SQL Injection", "https://api.example.com/query", "SQL Injection in API", SeverityCritical, 9.2),
	}

	analyzer := NewAttackPathAnalyzer(findings)
	groups := analyzer.ChainByURL()

	assert.Len(t, groups, 2, "should group into 2 URL hosts")

	exampleGroup := groups["https://example.com"]
	assert.NotNil(t, exampleGroup)
	assert.Len(t, exampleGroup, 3, "example.com should have 3 findings")

	apiGroup := groups["https://api.example.com"]
	assert.NotNil(t, apiGroup)
	assert.Len(t, apiGroup, 1, "api.example.com should have 1 finding")
}

func TestIdentifyEntryPoints(t *testing.T) {
	findings := []Finding{
		makeFinding("SQL Injection", "https://example.com/users?id=1", "SQLi", SeverityCritical, 9.8),
		makeFinding("Cross-Site Scripting (XSS)", "https://example.com/search?q=test", "XSS", SeverityHigh, 6.1),
		makeFinding("Path Traversal", "https://example.com/files?path=etc", "Path Traversal", SeverityHigh, 7.5),
		makeFinding("Authentication Failures", "https://example.com/login", "Auth Failure", SeverityHigh, 8.0),
		makeFinding("Secret Scanner", "https://example.com/config", "Secret Exposure", SeverityCritical, 9.0),
	}

	analyzer := NewAttackPathAnalyzer(findings)
	entryPoints := analyzer.IdentifyEntryPoints()

	scannerNames := make(map[string]bool)
	for _, ep := range entryPoints {
		scannerNames[ep.Scanner] = true
	}

	assert.True(t, scannerNames["SQL Injection"], "SQL Injection should be an entry point")
	assert.True(t, scannerNames["Cross-Site Scripting (XSS)"], "XSS should be an entry point")
	assert.True(t, scannerNames["Authentication Failures"], "Auth Failure should be an entry point")
	assert.False(t, scannerNames["Path Traversal"], "Path Traversal should NOT be an entry point")
	assert.False(t, scannerNames["Secret Scanner"], "Secret Scanner should NOT be an entry point")
}

func TestAnalyze(t *testing.T) {
	findings := []Finding{
		makeFinding("Cross-Site Scripting (XSS)", "https://example.com/search?q=test", "XSS", SeverityHigh, 6.1),
		makeFinding("Command Injection", "https://example.com/exec?cmd=ls", "Cmd Injection", SeverityCritical, 9.8),
		makeFinding("SQL Injection", "https://example.com/users?id=1", "SQLi", SeverityCritical, 9.8),
	}

	analyzer := NewAttackPathAnalyzer(findings)
	paths := analyzer.Analyze()

	assert.NotEmpty(t, paths, "should generate at least one attack path")

	for _, path := range paths {
		assert.NotEmpty(t, path.ID, "path should have an ID")
		assert.NotEmpty(t, path.Name, "path should have a name")
		assert.NotEmpty(t, path.Description, "path should have a description")
		assert.GreaterOrEqual(t, len(path.Steps), 2, "path should have at least 2 steps")
		assert.NotEmpty(t, path.OverallRisk, "path should have overall risk")
		assert.GreaterOrEqual(t, path.OverallCVSS, 0.0, "path should have CVSS score")
		assert.Contains(t, []string{"low", "medium", "high"}, path.AttackComplexity, "attack complexity should be valid")
	}
}

func TestAnalyze_Deterministic(t *testing.T) {
	findings := []Finding{
		makeFinding("Cross-Site Scripting (XSS)", "https://example.com/search?q=test", "XSS", SeverityHigh, 6.1),
		makeFinding("Command Injection", "https://example.com/exec?cmd=ls", "Cmd Injection", SeverityCritical, 9.8),
	}

	analyzer1 := NewAttackPathAnalyzer(findings)
	paths1 := analyzer1.Analyze()

	analyzer2 := NewAttackPathAnalyzer(findings)
	paths2 := analyzer2.Analyze()

	assert.Equal(t, len(paths1), len(paths2), "same input should produce same number of paths")
	for i := range paths1 {
		if i < len(paths2) {
			assert.Equal(t, paths1[i].Name, paths2[i].Name, "path names should be deterministic")
			assert.Equal(t, paths1[i].OverallCVSS, paths2[i].OverallCVSS, "CVSS scores should be deterministic")
		}
	}
}

func TestAnalyze_NoEntryPoints(t *testing.T) {
	findings := []Finding{
		makeFinding("Path Traversal", "https://example.com/files?path=etc", "Path Traversal", SeverityHigh, 7.5),
		makeFinding("Secret Scanner", "https://example.com/config", "Secret Exposure", SeverityCritical, 9.0),
	}

	analyzer := NewAttackPathAnalyzer(findings)
	paths := analyzer.Analyze()

	assert.Empty(t, paths, "should produce no paths when there are no entry points")
}

func TestPathStepChain(t *testing.T) {
	findings := []Finding{
		makeFinding("Server-Side Request Forgery (SSRF)", "https://example.com/fetch?url=int", "SSRF", SeverityHigh, 7.5),
		makeFinding("Cloud Leak Detection", "https://example.com/metadata", "Cloud Leak", SeverityCritical, 9.1),
	}

	analyzer := NewAttackPathAnalyzer(findings)
	paths := analyzer.Analyze()

	assert.NotEmpty(t, paths, "SSRF → Cloud Leak should produce a path")

	found := false
	for _, path := range paths {
		if len(path.Steps) >= 2 {
			first := path.Steps[0]
			second := path.Steps[1]
			if first.Finding.Scanner == "Server-Side Request Forgery (SSRF)" &&
				second.Finding.Scanner == "Cloud Leak Detection" {
				found = true
				assert.Equal(t, "entry_point", first.Role, "SSRF should be entry point")
				assert.Equal(t, "data_exfiltration", second.Role, "Cloud Leak should be data exfiltration")
				assert.NotEmpty(t, first.EnablesNext, "first step should enable next")
			}
		}
	}
	assert.True(t, found, "should find SSRF → Cloud Leak chain")
}

func TestCalculateOverallRisk(t *testing.T) {
	tests := []struct {
		name     string
		steps    []PathStep
		expected Severity
	}{
		{
			name: "single high step",
			steps: []PathStep{
				{Finding: Finding{Severity: SeverityHigh, CVSSScore: 7.5}},
			},
			expected: SeverityHigh,
		},
		{
			name: "max severity wins",
			steps: []PathStep{
				{Finding: Finding{Severity: SeverityLow, CVSSScore: 3.0}},
				{Finding: Finding{Severity: SeverityCritical, CVSSScore: 9.8}},
			},
			expected: SeverityCritical,
		},
		{
			name: "boost with 3+ steps",
			steps: []PathStep{
				{Finding: Finding{Severity: SeverityMedium, CVSSScore: 5.0}},
				{Finding: Finding{Severity: SeverityMedium, CVSSScore: 5.5}},
				{Finding: Finding{Severity: SeverityMedium, CVSSScore: 4.5}},
			},
			expected: SeverityHigh, // Medium boosted by 1 = High
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateOverallRisk(tt.steps)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateOverallCVSS(t *testing.T) {
	tests := []struct {
		name     string
		steps    []PathStep
		expected float64
	}{
		{
			name:     "empty steps",
			steps:    []PathStep{},
			expected: 0.0,
		},
		{
			name: "single step",
			steps: []PathStep{
				{Finding: Finding{CVSSScore: 7.5}},
			},
			expected: 7.5,
		},
		{
			name: "two steps adds 0.5",
			steps: []PathStep{
				{Finding: Finding{CVSSScore: 7.5}},
				{Finding: Finding{CVSSScore: 6.0}},
			},
			expected: 8.0, // 7.5 + 0.5*(2-1) = 8.0
		},
		{
			name: "capped at 10.0",
			steps: []PathStep{
				{Finding: Finding{CVSSScore: 9.8}},
				{Finding: Finding{CVSSScore: 8.0}},
				{Finding: Finding{CVSSScore: 7.5}},
			},
			expected: 10.0, // 9.8 + 0.5*2 = 10.8 → capped at 10.0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateOverallCVSS(tt.steps)
			assert.InDelta(t, tt.expected, result, 0.01)
		})
	}
}

func TestCalculateAttackComplexity(t *testing.T) {
	tests := []struct {
		name     string
		steps    []PathStep
		expected string
	}{
		{
			name: "same URL = low",
			steps: []PathStep{
				{Finding: Finding{URL: "https://example.com/a"}},
				{Finding: Finding{URL: "https://example.com/b"}},
			},
			expected: "low",
		},
		{
			name: "2-3 URLs = medium",
			steps: []PathStep{
				{Finding: Finding{URL: "https://example.com/a"}},
				{Finding: Finding{URL: "https://api.example.com/b"}},
			},
			expected: "medium",
		},
		{
			name: "4+ URLs = high",
			steps: []PathStep{
				{Finding: Finding{URL: "https://example.com/a"}},
				{Finding: Finding{URL: "https://api.example.com/b"}},
				{Finding: Finding{URL: "https://internal.example.com/c"}},
				{Finding: Finding{URL: "https://db.example.com/d"}},
			},
			expected: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateAttackComplexity(tt.steps)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChainByURL_InvalidURL(t *testing.T) {
	findings := []Finding{
		{
			URL:       "://invalid",
			Scanner:   "SQL Injection",
			Severity:  SeverityCritical,
			CVSSScore: 9.8,
			Timestamp: time.Now(),
		},
	}

	analyzer := NewAttackPathAnalyzer(findings)
	groups := analyzer.ChainByURL()

	assert.NotEmpty(t, groups, "should still group invalid URLs")
}

func TestAnalyze_MultiStepChain(t *testing.T) {
	findings := []Finding{
		makeFinding("Open Redirect", "https://example.com/redirect?url=evil", "Open Redirect", SeverityMedium, 5.4),
		makeFinding("Authentication Failures", "https://example.com/login", "Default Credentials", SeverityHigh, 8.0),
		makeFinding("SQL Injection", "https://example.com/users?id=1", "SQLi", SeverityCritical, 9.8),
	}

	analyzer := NewAttackPathAnalyzer(findings)
	paths := analyzer.Analyze()

	assert.NotEmpty(t, paths, "should generate attack paths from multi-step chains")

	for _, path := range paths {
		for i, step := range path.Steps {
			if i > 0 {
				assert.NotEmpty(t, step.Role, "each non-first step should have a role")
			}
		}
	}
}