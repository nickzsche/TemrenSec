package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePlugin(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "p.lua")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestSandboxBlocksRequire(t *testing.T) {
	src := `
function name() return "x" end
function scan(target, body, headers)
  require("os")
  return {}
end`
	p, err := loadPlugin(writePlugin(t, src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()
	_, err = p.Run(context.Background(), "http://x", "", map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "scan() error") {
		t.Fatalf("expected scan error from require, got: %v", err)
	}
}

func TestSandboxBlocksLoadstring(t *testing.T) {
	src := `
function name() return "x" end
function scan(target, body, headers)
  local f = loadstring("return 1")
  return {}
end`
	p, err := loadPlugin(writePlugin(t, src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()
	_, err = p.Run(context.Background(), "http://x", "", map[string]string{})
	if err == nil {
		t.Fatal("expected loadstring to be nil and error, got success")
	}
}

func TestSandboxBlocksOsLib(t *testing.T) {
	src := `
function name() return "x" end
function scan(target, body, headers)
  return { { title = os.getenv("PATH") or "no-os", severity = "INFO", url = target } }
end`
	p, err := loadPlugin(writePlugin(t, src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()
	_, err = p.Run(context.Background(), "http://x", "", map[string]string{})
	if err == nil {
		t.Fatal("expected os.getenv to fail, got nil error")
	}
}

func TestSandboxDeadlineCancelsInfiniteLoop(t *testing.T) {
	src := `
function name() return "x" end
function scan(target, body, headers)
  while true do end
end`
	p, err := loadPlugin(writePlugin(t, src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := p.Run(ctx, "http://x", "", map[string]string{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected loop to be cancelled, got nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("plugin did not honor ctx cancellation within 5s")
	}
}

func TestSandboxAllowsStringMathTable(t *testing.T) {
	src := `
function name() return "ok" end
function scan(target, body, headers)
  local t = {}
  table.insert(t, { title = string.upper("hi"), severity = "INFO", url = target })
  local _ = math.floor(1.5)
  return t
end`
	p, err := loadPlugin(writePlugin(t, src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer p.Close()
	findings, err := p.Run(context.Background(), "http://x", "", map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Title != "HI" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}
