package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestOpenRedirectPath_NoFPOnSameOriginNormalize(t *testing.T) {
	// Server collapses "//evil.example" to a same-origin relative path — the
	// Location contains "evil.example" but stays on this host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect//evil.example" {
			w.Header().Set("Location", "/redirect/evil.example")
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	f, _ := NewOpenRedirectPathScanner().Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("same-origin normalization redirect must not be flagged, got %+v", f)
	}
}

func TestOpenRedirectPath_DetectsRealExternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.example/")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	f, _ := NewOpenRedirectPathScanner().Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) == 0 {
		t.Fatal("genuine off-origin redirect to evil.example must be detected")
	}
}
