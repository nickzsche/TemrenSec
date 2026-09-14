package main

import "testing"

func TestUrlMatches_PrefixAndRegex(t *testing.T) {
	cases := []struct {
		have, want string
		ok         bool
	}{
		{"/api/Users/1", "/api/Users", true},
		{"/api/Users", "/api/Users", true},
		{"/api/Other", "/api/Users", false},
		{"/api/Users/42", `^/api/Users/\d+`, true},
		{"/api/Users/abc", `^/api/Users/\d+`, false},
		{"/", "/", true},
	}
	for _, c := range cases {
		if got := urlMatches(c.have, c.want); got != c.ok {
			t.Errorf("urlMatches(%q, %q) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}

func TestCompute_PerfectMatch(t *testing.T) {
	truth := []GroundTruth{
		{ID: "a", URL: "/foo", Scanner: "X", Severity: "HIGH"},
		{ID: "b", URL: `^/api/Users/\d+`, Scanner: "IDOR", Severity: "HIGH"},
	}
	reports := []Reported{
		{URL: "/foo/bar", Scanner: "X", Severity: "HIGH"},
		{URL: "/api/Users/42", Scanner: "IDOR", Severity: "HIGH"},
	}
	s := Compute("test", reports, truth)
	if s.TruePos != 2 || s.FalseNeg != 0 || s.FalsePos != 0 {
		t.Errorf("got TP=%d FP=%d FN=%d, want 2/0/0", s.TruePos, s.FalsePos, s.FalseNeg)
	}
	if s.Recall != 1.0 || s.Precision != 1.0 {
		t.Errorf("got P=%.2f R=%.2f, want both 1.0", s.Precision, s.Recall)
	}
}

func TestCompute_PartialAndFPs(t *testing.T) {
	truth := []GroundTruth{
		{ID: "a", URL: "/foo", Scanner: "X"},
		{ID: "b", URL: "/missing", Scanner: "Y"},
	}
	reports := []Reported{
		{URL: "/foo", Scanner: "X"}, // TP for a
		{URL: "/junk", Scanner: "Z"}, // FP
	}
	s := Compute("test", reports, truth)
	if s.TruePos != 1 {
		t.Errorf("TP=%d, want 1", s.TruePos)
	}
	if s.FalseNeg != 1 {
		t.Errorf("FN=%d, want 1", s.FalseNeg)
	}
	if s.FalsePos != 1 {
		t.Errorf("FP=%d, want 1", s.FalsePos)
	}
}

func TestCompute_FPOKSuppresses(t *testing.T) {
	truth := []GroundTruth{
		{ID: "h", URL: "/", Scanner: "Headers", FPOK: true},
	}
	reports := []Reported{
		{URL: "/", Scanner: "Headers"},          // TP for h
		{URL: "/another", Scanner: "Headers"},    // would be FP, but Headers is FPOK
	}
	s := Compute("test", reports, truth)
	if s.TruePos != 1 {
		t.Errorf("TP=%d, want 1", s.TruePos)
	}
	if s.FalsePos != 0 {
		t.Errorf("FP=%d, want 0 (Headers excluded by fp_ok)", s.FalsePos)
	}
}
