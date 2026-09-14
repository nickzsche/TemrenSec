package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

// spaCatchAllHandler returns 200 + HTML for every path, including the
// nonexistent baseline probe — the Next.js / Cloudflare wildcard scenario
// that produced 935 false-positive findings on the first real-world scan.
func spaCatchAllHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html lang="tr"><head><title>app</title></head><body><div>path: %s — Teklif Bulunamadı</div></body></html>`, r.URL.Path)
	})
}

func TestDirectoryBruteForce_SkipsSPAShell(t *testing.T) {
	srv := httptest.NewServer(spaCatchAllHandler())
	defer srv.Close()

	s := NewDirectoryBruteForceScanner()
	findings, err := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Admin") {
			t.Errorf("SPA shell produced admin-path finding: %s @ %s", f.Title, f.URL)
		}
	}
}

func TestDirectoryBruteForce_404IsNotFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewDirectoryBruteForceScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Errorf("404 host produced %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestDirectoryBruteForce_Real401IsLow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewDirectoryBruteForceScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Protected Admin Path") && f.Severity == SeverityLow {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real 401 admin path was missed: findings=%+v", findings)
	}
}

func TestDirectoryBruteForce_PerHostCache(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewDirectoryBruteForceScanner()
	c := httpengine.NewClient(httpengine.DefaultConfig())
	// Call against three different paths on the same host. The scanner
	// should probe once and return cached findings on the next two calls.
	_, _ = s.Scan(context.Background(), srv.URL+"/page1", c)
	first := hits
	_, _ = s.Scan(context.Background(), srv.URL+"/page2", c)
	_, _ = s.Scan(context.Background(), srv.URL+"/page3", c)
	if hits != first {
		t.Errorf("per-host cache not engaged: %d new probes after first scan (want 0)", hits-first)
	}
}
