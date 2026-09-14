package triage

import (
	"fmt"
	"testing"

	"github.com/temren/pkg/scanner"
)

func BenchmarkFingerprint(b *testing.B) {
	f := scanner.Finding{Scanner: "idor", URL: "https://example.com/users/42", Parameter: "id", Title: "IDOR"}
	for i := 0; i < b.N; i++ {
		Fingerprint(f)
	}
}

func BenchmarkRunLargeBatch(b *testing.B) {
	findings := make([]scanner.Finding, 10_000)
	for i := range findings {
		findings[i] = scanner.Finding{
			Scanner: "idor",
			URL:     fmt.Sprintf("https://example.com/users/%d", i),
			Title:   "IDOR",
			Severity: scanner.SeverityHigh,
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Run(findings, Config{})
	}
}
