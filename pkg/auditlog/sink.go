package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Sink ships every audit event to an off-system store so that tampering
// with the local file (or DB row) still leaves a witness elsewhere.
//
// Implementations are deliberately best-effort: a failing Sink must NOT
// block the local append. The local hash-chain remains the primary
// integrity record; the Sink is a redundancy layer.
type Sink interface {
	Ship(ctx context.Context, e Event) error
	Name() string
}

// NoopSink discards every event. Default in single-host deployments.
type NoopSink struct{}

func (NoopSink) Ship(context.Context, Event) error { return nil }
func (NoopSink) Name() string                      { return "noop" }

// WebhookSink POSTs each event as JSON to a remote endpoint. Pair with
// an immutable target (S3 Object Lock via API gateway, Loki with
// retention=immutable, etc.) for real tamper prevention.
type WebhookSink struct {
	URL     string
	Client  *http.Client
	Headers map[string]string
}

func NewWebhookSink(url string) *WebhookSink {
	return &WebhookSink{
		URL:    url,
		Client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (w *WebhookSink) Ship(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook sink %s: HTTP %d", w.URL, resp.StatusCode)
	}
	return nil
}

func (w *WebhookSink) Name() string { return "webhook:" + w.URL }

// Attach wires a Sink onto a Log. The Log will fire-and-forget Ship on
// each Append, capped by a small worker pool so a slow remote can't stall
// the audit path.
//
// NOTE: this returns a wrapped *AsyncShipper that the caller is responsible
// for closing on shutdown so in-flight events drain.
func (l *Log) Attach(sink Sink) *AsyncShipper {
	a := &AsyncShipper{
		sink: sink,
		ch:   make(chan Event, 256),
		done: make(chan struct{}),
	}
	l.mu.Lock()
	l.sink = a
	l.mu.Unlock()
	go a.run()
	return a
}

// AsyncShipper drains audit events to a Sink in a background goroutine
// so the synchronous Append path stays fast even when the remote is slow.
// Drops events (with a counter increment) when the buffer is full —
// audit availability over audit completeness when we're under duress.
type AsyncShipper struct {
	sink     Sink
	ch       chan Event
	done     chan struct{}
	closeMu  sync.Mutex
	closed   bool
	dropped  uint64
	droppedM sync.Mutex
}

func (a *AsyncShipper) enqueue(e Event) {
	if a == nil {
		return
	}
	select {
	case a.ch <- e:
	default:
		a.droppedM.Lock()
		a.dropped++
		a.droppedM.Unlock()
	}
}

func (a *AsyncShipper) run() {
	defer close(a.done)
	for e := range a.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = a.sink.Ship(ctx, e)
		cancel()
	}
}

// Dropped returns the running count of events dropped because the buffer
// was full. Surface this in /metrics so an operator knows the sink is lagging.
func (a *AsyncShipper) Dropped() uint64 {
	a.droppedM.Lock()
	defer a.droppedM.Unlock()
	return a.dropped
}

func (a *AsyncShipper) Close() {
	a.closeMu.Lock()
	if a.closed {
		a.closeMu.Unlock()
		return
	}
	a.closed = true
	a.closeMu.Unlock()
	close(a.ch)
	<-a.done
}
