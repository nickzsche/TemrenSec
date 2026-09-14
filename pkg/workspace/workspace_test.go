package workspace

import "testing"

func TestCreateAndFetch(t *testing.T) {
	s := New()
	if _, err := s.Create("acme", "main team"); err != nil {
		t.Fatal(err)
	}
	w, ok := s.Get("acme")
	if !ok || w.Description != "main team" {
		t.Errorf("missing or wrong workspace: %+v", w)
	}
}

func TestDuplicateRejected(t *testing.T) {
	s := New()
	s.Create("x", "")
	if _, err := s.Create("x", ""); err == nil {
		t.Fatal("expected duplicate to fail")
	}
}

func TestAddTargetAndDedup(t *testing.T) {
	s := New()
	s.Create("acme", "")
	if err := s.AddTarget("acme", Target{URL: "https://a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTarget("acme", Target{URL: "https://a"}); err == nil {
		t.Fatal("expected duplicate target to fail")
	}
	if err := s.AddTarget("acme", Target{URL: "https://b"}); err != nil {
		t.Fatal(err)
	}
	w, _ := s.Get("acme")
	if len(w.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(w.Targets))
	}
}

func TestListIsSorted(t *testing.T) {
	s := New()
	s.Create("b", "")
	s.Create("a", "")
	s.Create("c", "")
	out := s.List()
	if out[0].Name != "a" || out[2].Name != "c" {
		t.Errorf("not sorted: %+v", out)
	}
}
