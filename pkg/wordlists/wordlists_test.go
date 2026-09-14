package wordlists

import "testing"

func TestEmbeddedWordlistsNonEmpty(t *testing.T) {
	if len(Paths()) < 10 {
		t.Errorf("paths wordlist too small: %d", len(Paths()))
	}
	if len(Params()) < 10 {
		t.Errorf("params wordlist too small: %d", len(Params()))
	}
	if len(Subdomains()) < 10 {
		t.Errorf("subdomains wordlist too small: %d", len(Subdomains()))
	}
}

func TestNoBlanksOrComments(t *testing.T) {
	for _, w := range Paths() {
		if w == "" || w[0] == '#' {
			t.Errorf("blank/comment leaked: %q", w)
		}
	}
}
