package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunCapturesStdout(t *testing.T) {
	res, err := Run(context.Background(), "sh", []string{"-c", "echo hello"}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("missing stdout: %q", res.Stdout)
	}
}

func TestRunTimesOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, _ := Run(ctx, "sh", []string{"-c", "sleep 2"}, Limits{})
	if !res.TimedOut {
		t.Errorf("expected TimedOut=true, got %+v", res)
	}
}

func TestCapWriterCaps(t *testing.T) {
	res, err := Run(context.Background(), "sh", []string{"-c", "yes hello | head -c 200000"}, Limits{MaxOutputBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) > 1024 {
		t.Errorf("stdout exceeded cap: %d bytes", len(res.Stdout))
	}
}

func TestEnvScrubbed(t *testing.T) {
	t.Setenv("PWNED", "yes")
	res, _ := Run(context.Background(), "sh", []string{"-c", "echo $PWNED"}, Limits{})
	if strings.Contains(res.Stdout, "yes") {
		t.Errorf("env leaked into sandbox: %q", res.Stdout)
	}
}
