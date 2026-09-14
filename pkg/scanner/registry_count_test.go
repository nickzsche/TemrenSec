package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestScannerCountMatchesDocs is the single-source-of-truth guard: the number
// of registered scanners (AllScanners) must equal the count advertised in
// README.md. If you add or remove a scanner, this test fails until the docs
// are updated, so the two never drift apart.
func TestScannerCountMatchesDocs(t *testing.T) {
	got := len(AllScanners())
	if got == 0 {
		t.Fatal("AllScanners() returned nothing")
	}

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Skipf("README.md not readable from test cwd: %v", err)
	}

	// Match phrases like "89 Scanners" / "89 scanners" / "89-scanner".
	re := regexp.MustCompile(`(?i)(\d+)[ -]scanner`)
	matches := re.FindAllStringSubmatch(string(readme), -1)
	if len(matches) == 0 {
		t.Fatal("no scanner count found in README.md")
	}

	want := strconv.Itoa(got)
	for _, m := range matches {
		if m[1] != want {
			t.Errorf("README advertises %q scanners but AllScanners() has %d; update README.md (found %q)",
				m[1], got, strings.TrimSpace(m[0]))
		}
	}
	fmt.Fprintf(os.Stderr, "scanner count OK: %d\n", got)
}
