package honeypot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectsIdenticalResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.1 (Cowrie SSH/2.0)")
		w.WriteHeader(200)
		w.Write([]byte("Welcome — your IP has been logged."))
	}))
	defer srv.Close()
	v := Analyze(context.Background(), srv.URL, srv.Client())
	if v.Score < 60 {
		t.Errorf("expected high score, got %d (%v)", v.Score, v.Signals)
	}
}

func TestCleanServerScoresLow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if r.URL.Path == "/temren_canary_1" {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		} else {
			w.WriteHeader(404)
			w.Write([]byte("Not Found - This is a different page"))
		}
	}))
	defer srv.Close()
	v := Analyze(context.Background(), srv.URL, srv.Client())
	if v.Score > 30 {
		t.Errorf("clean server scored too high: %d", v.Score)
	}
}
