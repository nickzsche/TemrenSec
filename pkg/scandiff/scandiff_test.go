package scandiff

import (
	"testing"

	"github.com/temren/pkg/scanner"
)

func TestDiffAddedFixedStableRegressed(t *testing.T) {
	baseline := []scanner.Finding{
		{Scanner: "sqli", URL: "https://x/a", Severity: scanner.SeverityMedium},
		{Scanner: "xss", URL: "https://x/b", Severity: scanner.SeverityHigh},
		{Scanner: "headers", URL: "https://x/c", Severity: scanner.SeverityLow},
	}
	current := []scanner.Finding{
		// sqli still here but worse → regression
		{Scanner: "sqli", URL: "https://x/a", Severity: scanner.SeverityCritical},
		// xss gone → fixed
		// headers stable
		{Scanner: "headers", URL: "https://x/c", Severity: scanner.SeverityLow},
		// new ssrf → added
		{Scanner: "ssrf", URL: "https://x/d", Severity: scanner.SeverityHigh},
	}
	r := Diff(baseline, current)
	if len(r.Added) != 1 || r.Added[0].Scanner != "ssrf" {
		t.Errorf("added wrong: %+v", r.Added)
	}
	if len(r.Fixed) != 1 || r.Fixed[0].Scanner != "xss" {
		t.Errorf("fixed wrong: %+v", r.Fixed)
	}
	if len(r.Regressed) != 1 || r.Regressed[0].To != scanner.SeverityCritical {
		t.Errorf("regressed wrong: %+v", r.Regressed)
	}
	if r.Stable != 1 {
		t.Errorf("stable wrong: %d", r.Stable)
	}
}

func TestDiffURLIgnoresQueryString(t *testing.T) {
	baseline := []scanner.Finding{{Scanner: "idor", URL: "https://x/u?id=1", Severity: scanner.SeverityHigh, Title: "IDOR"}}
	current := []scanner.Finding{{Scanner: "idor", URL: "https://x/u?id=999", Severity: scanner.SeverityHigh, Title: "IDOR"}}
	r := Diff(baseline, current)
	if r.Stable != 1 || len(r.Added) != 0 {
		t.Errorf("query string should be ignored in identity: %+v", r)
	}
}
