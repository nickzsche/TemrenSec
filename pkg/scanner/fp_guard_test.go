package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

// spaCatchAll serves the same 200 HTML shell for every path with a public
// cache header — the pattern that used to cause false positives.
func spaCatchAll() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>ACME single-page app shell</body></html>"))
	}))
}

func TestWebCacheDeception_NoFPOnSPACatchAll(t *testing.T) {
	srv := spaCatchAll()
	defer srv.Close()
	f, _ := NewWebCacheDeceptionScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("SPA catch-all should not trigger web cache deception, got %+v", f)
	}
}

func TestWebCacheDeception_DetectsRealCase(t *testing.T) {
	// No-suffix unknown paths 404; a static-suffixed path returns a cacheable
	// dynamic page — the genuine cache-deception signal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".css") || strings.Contains(r.URL.Path, ".jpg") {
			w.Header().Set("Cache-Control", "public, max-age=600")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><body>Welcome back, user! Balance: $4210</body></html>"))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()
	f, _ := NewWebCacheDeceptionScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) == 0 {
		t.Fatal("expected web cache deception on genuinely cacheable dynamic static-suffixed response")
	}
}

func TestWellKnown_NoFPDiscoveredOnCatchAll(t *testing.T) {
	srv := spaCatchAll()
	defer srv.Close()
	f, _ := NewWellKnownScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	for _, x := range f {
		if strings.HasPrefix(x.Title, "Discovered") {
			t.Fatalf("catch-all should not 'discover' well-known endpoints, got %q", x.Title)
		}
	}
}

func TestWellKnown_DetectsRealJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"issuer":"https://acme.example","authorization_endpoint":"https://acme.example/auth"}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	f, _ := NewWellKnownScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	found := false
	for _, x := range f {
		if strings.Contains(x.Title, "Discovered /.well-known/openid-configuration") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected genuine openid-configuration to be discovered, got %+v", f)
	}
}
