package httpengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestPerHostRateLimitIsolatesHosts confirms that two hosts get independent
// token buckets — i.e. saturating host A doesn't starve host B.
func TestPerHostRateLimitIsolatesHosts(t *testing.T) {
	var hitA, hitB int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hitA, 1)
		w.WriteHeader(200)
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hitB, 1)
		w.WriteHeader(200)
	}))
	defer srvB.Close()

	cfg := DefaultConfig()
	cfg.RateLimit = 1000  // global is generous
	cfg.PerHostRate = 1000 // per-host is generous too — we're not testing throttling here
	c := NewClient(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Issue requests against both; both should land.
	if _, err := c.Get(ctx, srvA.URL); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := c.Get(ctx, srvB.URL); err != nil {
		t.Fatalf("B: %v", err)
	}

	if atomic.LoadInt32(&hitA) != 1 || atomic.LoadInt32(&hitB) != 1 {
		t.Fatalf("expected 1/1 hits, got %d/%d", atomic.LoadInt32(&hitA), atomic.LoadInt32(&hitB))
	}

	// Verify a separate limiter was actually created for each host.
	var hosts []string
	c.hostLimiters.Range(func(k, _ any) bool {
		hosts = append(hosts, k.(string))
		return true
	})
	if len(hosts) != 2 {
		t.Fatalf("expected 2 host-limiters, got %d: %v", len(hosts), hosts)
	}
}

// TestPerHostRateLimitDefaultsToGlobal: when PerHostRate is unset, the
// per-host limiter inherits the global rate — there's no regression from
// the pre-change behaviour.
func TestPerHostRateLimitDefaultsToGlobal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit = 7
	// cfg.PerHostRate left zero
	c := NewClient(cfg)
	if c.perHostRate != 7 {
		t.Fatalf("perHostRate=%d, want 7", c.perHostRate)
	}
}
