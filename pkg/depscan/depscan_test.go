package depscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParsePackageLock(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package-lock.json", `{
  "dependencies": {
    "lodash": {"version": "4.17.0"},
    "express": {"version": "4.18.1"}
  }
}`)
	pkgs, err := New(dir).Inventory()
	if err != nil || len(pkgs) < 2 {
		t.Fatalf("expected 2 npm pkgs, got %d (err=%v)", len(pkgs), err)
	}
}

func TestParseGoSum(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.sum", `github.com/temren/foo v1.2.3 h1:abc=
github.com/temren/foo v1.2.3/go.mod h1:def=
golang.org/x/net v0.21.0 h1:xyz=
`)
	pkgs, err := New(dir).Inventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 go pkgs, got %d", len(pkgs))
	}
	if pkgs[0].Ecosystem != "Go" {
		t.Errorf("wrong ecosystem: %s", pkgs[0].Ecosystem)
	}
}

func TestParseRequirements(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "requirements.txt", `# comment
flask==2.3.0
requests==2.28.0
`)
	pkgs, _ := New(dir).Inventory()
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 pypi pkgs, got %d", len(pkgs))
	}
}

func TestOfflineProducesSummary(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.sum", "github.com/x/y v1 h1:a=\n")
	s := New(dir)
	s.Offline = true
	findings, _ := s.Scan(context.Background())
	if len(findings) != 1 {
		t.Errorf("offline mode should return one summary finding, got %d", len(findings))
	}
}
