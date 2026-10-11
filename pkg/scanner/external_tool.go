package scanner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/sandbox"
)

// ExternalToolScanner adapts an external security binary to the Scanner
// interface: it runs the binary through sandbox.Run (time/output bounded,
// scrubbed env) and converts stdout into Findings via Parse.
type ExternalToolScanner struct {
	ScannerName string
	Binary      string
	// Args builds the command line for a target.
	Args func(target string) []string
	// Parse converts the tool's stdout into findings. Scanner/Timestamp are
	// filled in by the wrapper when left empty.
	Parse   func(stdout, target string) []Finding
	Timeout time.Duration // default 60s
	Limits  sandbox.Limits
}

func (e *ExternalToolScanner) Name() string { return e.ScannerName }

func (e *ExternalToolScanner) Scan(ctx context.Context, target string, _ *httpengine.Client) ([]Finding, error) {
	if e.Args == nil || e.Parse == nil {
		return nil, errors.New("external scanner: Args and Parse are required")
	}
	// Missing tool = scanner silently unavailable, not a scan failure.
	if _, err := exec.LookPath(e.Binary); err != nil {
		return nil, nil
	}
	to := e.Timeout
	if to <= 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	res, err := sandbox.Run(ctx, e.Binary, e.Args(target), e.Limits)
	if res == nil {
		return nil, err
	}
	if res.TimedOut {
		return nil, fmt.Errorf("%s: timed out after %s", e.ScannerName, to)
	}
	// Many tools exit non-zero when they find something; only fail if there is no output.
	if err != nil && strings.TrimSpace(res.Stdout) == "" {
		return nil, fmt.Errorf("%s: %w: %s", e.ScannerName, err, strings.TrimSpace(res.Stderr))
	}
	out := e.Parse(res.Stdout, target)
	now := time.Now()
	for i := range out {
		if out[i].Scanner == "" {
			out[i].Scanner = e.ScannerName
		}
		if out[i].Timestamp.IsZero() {
			out[i].Timestamp = now
		}
		if out[i].URL == "" {
			out[i].URL = target
		}
	}
	return out, nil
}
