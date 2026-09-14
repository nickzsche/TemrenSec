package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestLLMScanner_SkipsSPAWildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cloudflare + Next.js: every path returns 200 + HTML.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta property="og:url" content="https://x.com"></head><body>Teklif Bulunamadı</body></html>`))
	}))
	defer srv.Close()

	s := NewLLMScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/_next/static/chunks/abc.js", httpengine.NewClient(httpengine.DefaultConfig()))
	for _, f := range findings {
		if f.Severity == SeverityHigh || f.Severity == SeverityCritical {
			t.Errorf("SPA wildcard produced %s LLM finding: %s @ %s", f.Severity, f.Title, f.URL)
		}
	}
}

func TestLLMScanner_TargetURLNotAppendedAsPath(t *testing.T) {
	// If the bug came back, we'd see requests to URLs like
	// /_next/static/chunks/abc.js/v1/chat/completions
	var sawConcatenated bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/_next/") {
			sawConcatenated = true
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewLLMScanner()
	_, _ = s.Scan(context.Background(), srv.URL+"/_next/static/chunks/abc.js", httpengine.NewClient(httpengine.DefaultConfig()))
	if sawConcatenated {
		t.Errorf("scanner appended the crawled path as part of the probe URL — regression of FP-causing bug")
	}
}

func TestLLMScanner_RealJSONEndpointStillDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":{"message":"missing API key","type":"authentication_error"}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewLLMScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	detected := false
	for _, f := range findings {
		if f.Title == "LLM/API Endpoint Detected" {
			detected = true
		}
	}
	if !detected {
		t.Fatalf("real LLM endpoint (401 JSON) was missed: findings=%+v", findings)
	}
}

func TestLLMScanner_PerHostCache(t *testing.T) {
	probes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes++
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewLLMScanner()
	c := httpengine.NewClient(httpengine.DefaultConfig())
	_, _ = s.Scan(context.Background(), srv.URL+"/a", c)
	first := probes
	_, _ = s.Scan(context.Background(), srv.URL+"/b", c)
	_, _ = s.Scan(context.Background(), srv.URL+"/c", c)
	if probes != first {
		t.Errorf("LLM scanner re-probed same host: %d extra requests after cache should be in place", probes-first)
	}
}
