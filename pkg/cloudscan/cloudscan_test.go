package cloudscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDockerfileScanner(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM nginx:latest\nADD https://example.com/x.tar /tmp/\nRUN chmod 777 /tmp\n")
	issues, err := New(dir).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) < 3 {
		t.Fatalf("expected >=3 issues, got %d", len(issues))
	}
	var sawLatest, sawAdd, sawChmod, sawRoot bool
	for _, i := range issues {
		switch {
		case strings.Contains(i.Title, ":latest"):
			sawLatest = true
		case strings.Contains(i.Title, "ADD with remote"):
			sawAdd = true
		case strings.Contains(i.Title, "World-writable"):
			sawChmod = true
		case strings.Contains(i.Title, "runs as root"):
			sawRoot = true
		}
	}
	if !(sawLatest && sawAdd && sawChmod && sawRoot) {
		t.Fatalf("missing expected findings: latest=%v add=%v chmod=%v root=%v", sawLatest, sawAdd, sawChmod, sawRoot)
	}
}

func TestKubernetesScanner(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.yaml", "securityContext:\n  privileged: true\n  runAsNonRoot: false\n  allowPrivilegeEscalation: true\n")
	issues, err := New(dir).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) < 3 {
		t.Fatalf("expected >=3 k8s findings, got %d", len(issues))
	}
}

func TestTerraformScanner(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.tf", "resource \"aws_security_group\" \"x\" { cidr_blocks = [\"0.0.0.0/0\"] }\nresource \"aws_db_instance\" \"x\" { publicly_accessible = true }\n")
	issues, err := New(dir).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) < 2 {
		t.Fatalf("expected >=2 tf findings, got %d", len(issues))
	}
}
