package auditlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendVerifyClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append("sahan", "test", "obj", map[string]string{"i": "x"}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	line, err := Verify(path)
	if err != nil || line != 0 {
		t.Errorf("Verify clean log: line=%d err=%v", line, err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path)
	l.Append("sahan", "a", "", nil)
	l.Append("sahan", "b", "", nil)
	l.Append("sahan", "c", "", nil)
	l.Close()

	// Mangle line 2.
	data, _ := os.ReadFile(path)
	mangled := []byte(string(data)[:50] + "X" + string(data)[51:])
	_ = os.WriteFile(path, mangled, 0o600)

	line, err := Verify(path)
	if line == 0 || err == nil {
		t.Errorf("expected tamper detection")
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, _ := Open(path)
	l.Append("a", "first", "", nil)
	l.Close()
	l2, _ := Open(path)
	l2.Append("a", "second", "", nil)
	l2.Close()
	if line, err := Verify(path); line != 0 {
		t.Errorf("Verify failed after reopen: line=%d err=%v", line, err)
	}
}
