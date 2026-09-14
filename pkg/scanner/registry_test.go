package scanner

import (
	"strings"
	"testing"
)

func TestAllScannersImplementInterface(t *testing.T) {
	all := AllScanners()
	if len(all) < 50 {
		t.Fatalf("expected ≥50 scanners, got %d", len(all))
	}
	for _, s := range all {
		if s.Name() == "" {
			t.Errorf("scanner returned empty Name(): %T", s)
		}
	}
}

func TestAllScannerNamesUnique(t *testing.T) {
	all := AllScanners()
	seen := map[string]bool{}
	for _, s := range all {
		if seen[s.Name()] {
			t.Errorf("duplicate scanner name: %s", s.Name())
		}
		seen[s.Name()] = true
	}
}

func TestEnabledScannersFilters(t *testing.T) {
	got := EnabledScanners([]string{"sql injection", "scripting"})
	if len(got) < 2 {
		t.Fatalf("expected ≥2 matches, got %d", len(got))
	}
	for _, s := range got {
		name := strings.ToLower(s.Name())
		if !strings.Contains(name, "sql injection") && !strings.Contains(name, "scripting") {
			t.Errorf("unexpected scanner in filter: %s", s.Name())
		}
	}
}

func TestEnabledScannersEmptyMeansAll(t *testing.T) {
	if len(EnabledScanners(nil)) != len(AllScanners()) {
		t.Error("empty filter should return all")
	}
}
