package profiles

import "testing"

func TestNamesCoverCorePresets(t *testing.T) {
	expected := []string{"quick", "standard", "deep", "compliance", "api-only", "llm-only", "mcp-only"}
	names := Names()
	for _, want := range expected {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing profile %q", want)
		}
	}
}

func TestProfilesAreUseful(t *testing.T) {
	for _, p := range All() {
		if p.Name == "" || len(p.Scanners) == 0 {
			t.Errorf("profile %s missing fields", p.Name)
		}
	}
}

func TestDeepIncludesExperimental(t *testing.T) {
	if !Get("deep").IncludeExperimental {
		t.Error("deep should set IncludeExperimental")
	}
}

func TestUnknownProfileIsZero(t *testing.T) {
	if Get("bogus").Name != "" {
		t.Error("unknown profile should return zero value")
	}
}
