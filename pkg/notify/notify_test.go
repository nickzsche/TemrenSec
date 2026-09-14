package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type stub struct {
	name string
	hit  *int32
	err  error
}

func (s *stub) Name() string { return s.name }
func (s *stub) Send(ctx context.Context, e Event) error {
	atomic.AddInt32(s.hit, 1)
	return s.err
}

func TestDispatcherFanOut(t *testing.T) {
	d := NewDispatcher()
	var a, b int32
	d.Register(&stub{name: "a", hit: &a})
	d.Register(&stub{name: "b", hit: &b})
	if err := d.Dispatch(context.Background(), Event{Severity: SeverityHigh}); err != nil {
		t.Fatal(err)
	}
	if a != 1 || b != 1 {
		t.Errorf("expected both channels hit once, got a=%d b=%d", a, b)
	}
}

func TestDispatcherAggregatesErrors(t *testing.T) {
	d := NewDispatcher()
	var a int32
	d.Register(&stub{name: "fail", hit: &a, err: errors.New("boom")})
	err := d.Dispatch(context.Background(), Event{Severity: SeverityCritical})
	if err == nil || !strings.Contains(err.Error(), "fail:") {
		t.Fatalf("expected aggregated error, got %v", err)
	}
}

func TestDispatcherSeverityGate(t *testing.T) {
	d := NewDispatcher()
	d.MinSeverity = SeverityHigh
	var a int32
	d.Register(&stub{name: "a", hit: &a})
	d.Dispatch(context.Background(), Event{Severity: SeverityLow})
	if a != 0 {
		t.Errorf("low severity should be dropped")
	}
}

func TestNtfyChannel(t *testing.T) {
	var gotTitle, gotPriority string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTitle = r.Header.Get("Title")
		gotPriority = r.Header.Get("Priority")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	n := NewNtfy(srv.URL, "test-topic")
	err := n.Send(context.Background(), Event{Title: "X", Severity: SeverityCritical, Description: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if gotTitle != "X" || gotPriority != "5" {
		t.Errorf("title=%q priority=%q", gotTitle, gotPriority)
	}
}

func TestWebhookSignsPayload(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Temren-Signature")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	w := NewWebhook(srv.URL)
	w.Secret = "shh"
	if err := w.Send(context.Background(), Event{Title: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") || len(gotSig) < 30 {
		t.Errorf("expected signed payload, got %q", gotSig)
	}
}
