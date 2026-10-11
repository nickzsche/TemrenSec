package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestExternalToolScanner(t *testing.T) {
	s := &ExternalToolScanner{
		ScannerName: "echo-tool",
		Binary:      "sh",
		Args:        func(target string) []string { return []string{"-c", "echo open:" + target + "; exit 1"} },
		Parse: func(out, _ string) []Finding {
			var f []Finding
			for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
				f = append(f, Finding{Title: l, Severity: SeverityInfo})
			}
			return f
		},
	}
	got, err := s.Scan(context.Background(), "example.com", nil)
	if err != nil || len(got) != 1 || got[0].Title != "open:example.com" || got[0].Scanner != "echo-tool" || got[0].Timestamp.IsZero() {
		t.Fatalf("unexpected: %+v err=%v", got, err)
	}
	s.Binary = "definitely-not-installed-xyz"
	if got, err := s.Scan(context.Background(), "x", nil); got != nil || err != nil {
		t.Fatalf("missing binary should be a silent no-op, got %v %v", got, err)
	}
}
