package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

func TestCmdInjection_TimeBlind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := strings.ToLower(r.URL.Query().Get("host"))
		if strings.Contains(v, "sleep") || strings.Contains(v, "ping") {
			time.Sleep(2 * time.Second)
		}
		_, _ = w.Write([]byte("pong")) // constant length -> no other signal
	}))
	defer srv.Close()

	s := &CommandInjectionScanner{SleepSeconds: 2}
	f, _ := s.Scan(context.Background(), srv.URL+"/?host=127.0.0.1", httpengine.NewClient(httpengine.DefaultConfig()))
	if hasTitle(f, "time-based blind") == nil {
		t.Fatalf("expected time-based command injection, got %+v", f)
	}
}

func TestCmdInjection_NoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("static"))
	}))
	defer srv.Close()
	s := NewCommandInjectionScanner()
	f, _ := s.Scan(context.Background(), srv.URL+"/?host=127.0.0.1", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}

func TestSSRF_ResponseDiff(t *testing.T) {
	// Emulate an app that fetches the url param server-side: reachable internal
	// target yields a long body, unreachable yields a short error page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.Contains(u, ":1/") || strings.Contains(u, "240.0.0.1") {
			w.WriteHeader(502)
			_, _ = w.Write([]byte("fetch failed"))
			return
		}
		if strings.HasPrefix(u, "http://127.0.0.1:80") || strings.Contains(u, "169.254.169.254") {
			_, _ = w.Write([]byte(strings.Repeat("internal-content ", 100)))
			return
		}
		_, _ = w.Write([]byte("default"))
	}))
	defer srv.Close()

	s := NewSSRFScanner()
	f, _ := s.Scan(context.Background(), srv.URL+"/?url=http://example.com", httpengine.NewClient(httpengine.DefaultConfig()))
	if hasTitle(f, "response-diff") == nil {
		t.Fatalf("expected blind SSRF response-diff finding, got %+v", f)
	}
}

func TestSSRF_NoFalsePositiveOnReflector(t *testing.T) {
	// Pure reflector: returns identical body regardless of the url param.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("you requested a resource"))
	}))
	defer srv.Close()
	s := NewSSRFScanner()
	f, _ := s.Scan(context.Background(), srv.URL+"/?url=http://example.com", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("expected no SSRF findings on reflector, got %+v", f)
	}
}
