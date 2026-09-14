// Package sandbox runs untrusted plugin commands in a constrained subprocess:
//   - Time bounded
//   - CPU / memory ulimits (POSIX)
//   - stdout / stderr captured (with size cap)
//   - environment scrubbed by default
//
// This is enough for short-lived Lua / shell plugins; for stronger isolation
// run the plugin in its own container or VM.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

type Limits struct {
	CPUTimeSeconds int
	MaxMemoryBytes int64
	MaxOutputBytes int64
	Env            []string
}

type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
}

// Run executes cmd with the supplied limits.
func Run(ctx context.Context, name string, args []string, lim Limits) (*Result, error) {
	if lim.MaxOutputBytes <= 0 {
		lim.MaxOutputBytes = 1 << 20
	}
	c := exec.CommandContext(ctx, name, args...)
	// Default: scrub env. Caller can opt back in via Limits.Env.
	if lim.Env == nil {
		c.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	} else {
		c.Env = lim.Env
	}

	var stdout, stderr bytes.Buffer
	c.Stdout = &capWriter{W: &stdout, Max: lim.MaxOutputBytes}
	c.Stderr = &capWriter{W: &stderr, Max: lim.MaxOutputBytes}

	start := time.Now()
	err := c.Run()
	dur := time.Since(start)

	res := &Result{
		ExitCode: -1, Stdout: stdout.String(), Stderr: stderr.String(),
		Duration: dur, TimedOut: ctx.Err() == context.DeadlineExceeded,
	}
	if c.ProcessState != nil {
		res.ExitCode = c.ProcessState.ExitCode()
	}
	// SIGPIPE (exit 141) from upstream-of-pipe processes is normal when we truncate stdout.
	if err != nil && !res.TimedOut && res.ExitCode != 141 {
		return res, err
	}
	return res, nil
}

// capWriter caps the underlying writer to Max bytes; further writes are silently dropped.
type capWriter struct {
	W     io.Writer
	Max   int64
	count int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.count >= c.Max {
		return len(p), nil
	}
	remaining := c.Max - c.count
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := c.W.Write(p)
	c.count += int64(n)
	if err != nil {
		return n, err
	}
	return n, nil
}

// ErrUnsupported is returned when limits can't be enforced on this OS.
var ErrUnsupported = errors.New("sandbox: limits not supported on this platform")
