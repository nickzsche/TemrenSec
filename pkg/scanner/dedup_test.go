package scanner

import "testing"

func TestDedupFindings_CollapsesSameVulnAcrossPaths(t *testing.T) {
	in := []Finding{
		{Scanner: "Security Headers", Title: "Missing X-Frame-Options", URL: "https://x.com/"},
		{Scanner: "Security Headers", Title: "Missing X-Frame-Options", URL: "https://x.com/about"},
		{Scanner: "Security Headers", Title: "Missing X-Frame-Options", URL: "https://x.com/contact"},
		{Scanner: "Security Headers", Title: "Missing X-Frame-Options", URL: "https://other.com/"},
	}
	out := DedupFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 (1 per host), got %d: %+v", len(out), out)
	}
}

func TestDedupFindings_KeepsDifferentParameters(t *testing.T) {
	in := []Finding{
		{Scanner: "SQL Injection", Title: "Time-based SQLi", URL: "https://x.com/api", Parameter: "id"},
		{Scanner: "SQL Injection", Title: "Time-based SQLi", URL: "https://x.com/api", Parameter: "user"},
		{Scanner: "SQL Injection", Title: "Time-based SQLi", URL: "https://x.com/api", Parameter: "id"}, // dup
	}
	out := DedupFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 distinct params, got %d", len(out))
	}
}

func TestDedupFindings_KeepsDifferentPayloads(t *testing.T) {
	in := []Finding{
		{Scanner: "XSS", Title: "Reflected XSS", URL: "https://x.com/", Parameter: "q", Payload: "<svg/onload=1>"},
		{Scanner: "XSS", Title: "Reflected XSS", URL: "https://x.com/", Parameter: "q", Payload: "<img src=x onerror=1>"},
	}
	out := DedupFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 distinct payloads, got %d", len(out))
	}
}

func TestDedupFindings_EmptyInputIsSafe(t *testing.T) {
	if got := DedupFindings(nil); got != nil {
		t.Errorf("DedupFindings(nil) = %v, want nil", got)
	}
	if got := DedupFindings([]Finding{}); len(got) != 0 {
		t.Errorf("DedupFindings([]) = %v, want []", got)
	}
}

func TestHostOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com/a/b", "example.com"},
		{"http://sub.example.com:8080/x", "sub.example.com:8080"},
		{"not-a-url", "not-a-url"},
		{"", ""},
	}
	for _, c := range cases {
		if got := hostOf(c.in); got != c.want {
			t.Errorf("hostOf(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
