package exporter

import (
	"io"
	"testing"

	"github.com/temren/pkg/scanner"
)

func bigSet() []scanner.Finding {
	out := make([]scanner.Finding, 1000)
	for i := range out {
		out[i] = scanner.Finding{
			Title: "F", URL: "https://x", Severity: scanner.SeverityHigh,
			Scanner: "test", OWASPCategory: "A03:2021-Injection", CVSSScore: 7.5,
			Description: "desc",
		}
	}
	return out
}

func BenchmarkSARIF(b *testing.B) {
	set := bigSet()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SARIF(io.Discard, set)
	}
}

func BenchmarkCycloneDX(b *testing.B) {
	set := bigSet()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CycloneDX(io.Discard, set)
	}
}

func BenchmarkMarkdown(b *testing.B) {
	set := bigSet()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Markdown(io.Discard, set)
	}
}
