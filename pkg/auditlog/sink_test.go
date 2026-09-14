package auditlog

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNoopSink(t *testing.T) {
	var s Sink = NoopSink{}
	if s.Name() != "noop" {
		t.Fatal("name")
	}
}

func TestWebhookSink_ShipsEachAppend(t *testing.T) {
	var received int32
	var mu sync.Mutex
	var last Event

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var e Event
		if err := json.Unmarshal(body, &e); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		mu.Lock()
		last = e
		mu.Unlock()
		atomic.AddInt32(&received, 1)
		w.WriteHeader(202)
	}))
	defer srv.Close()

	log, err := Open(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer log.Close()

	shipper := log.Attach(NewWebhookSink(srv.URL))
	defer shipper.Close()

	for i := 0; i < 3; i++ {
		if _, err := log.Append("alice", "scan.start", "target/1", map[string]string{"i": "x"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&received) < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&received); got != 3 {
		t.Fatalf("expected 3 webhook deliveries, got %d", got)
	}
	mu.Lock()
	if last.Actor != "alice" {
		t.Errorf("last event actor=%q, want alice", last.Actor)
	}
	mu.Unlock()
}

func TestAsyncShipper_DropsWhenFull(t *testing.T) {
	// Sink that blocks until the test signals — simulates a stuck remote
	// so we can observe drop behaviour deterministically.
	release := make(chan struct{})
	a := &AsyncShipper{
		sink: &blockingSink{release: release},
		ch:   make(chan Event, 1),
		done: make(chan struct{}),
	}
	go a.run()
	defer func() {
		close(release)
		a.Close()
	}()

	// First event will be picked up by the goroutine and stuck in Ship.
	// Second fills the buffer. Subsequent ones must drop.
	for i := 0; i < 10; i++ {
		a.enqueue(Event{Actor: "x"})
	}
	// Give the worker a moment to consume the first event.
	time.Sleep(50 * time.Millisecond)
	if d := a.Dropped(); d == 0 {
		t.Fatal("expected some drops under saturation, got 0")
	}
}

type blockingSink struct {
	release chan struct{}
}

func (b *blockingSink) Ship(ctx context.Context, _ Event) error {
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nil
}
func (b *blockingSink) Name() string { return "block" }
