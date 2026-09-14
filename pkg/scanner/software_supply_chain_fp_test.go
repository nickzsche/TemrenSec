package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

// TestSoftwareSupplyChain_SkipsStaticAssets — JS/CSS chunks shouldn't be
// scanned for supply-chain leakage at all; the substring approach guarantees
// false positives on minified bundles.
func TestSoftwareSupplyChain_SkipsStaticAssets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// Body literally contains ".env" and "package.json" as JS strings.
		_, _ = w.Write([]byte(`var paths={env:".env",pkg:"package.json"};module.exports=paths;`))
	}))
	defer srv.Close()

	s := NewSoftwareSupplyChainScanner()
	got, err := s.Scan(context.Background(), srv.URL+"/_next/static/chunks/abc.js", httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("static asset produced supply-chain findings: %+v", got)
	}
}

// TestSoftwareSupplyChain_CriticalNeedsShape — a page that merely mentions
// ".env" in prose must not produce a critical finding.
func TestSoftwareSupplyChain_CriticalNeedsShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><p>How to manage .env files in production</p></body></html>`))
	}))
	defer srv.Close()

	s := NewSoftwareSupplyChainScanner()
	got, _ := s.Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	for _, f := range got {
		if f.Severity == SeverityCritical {
			t.Errorf("prose mention of .env produced critical FP: %s", f.Title)
		}
	}
}

// TestSoftwareSupplyChain_RealEnvCriticalStillFires — when the body actually
// looks like a .env file, the critical finding must still be produced.
func TestSoftwareSupplyChain_RealEnvCriticalStillFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("DB_PASSWORD=hunter2\nSECRET_KEY=changeme\n# .env file\n"))
	}))
	defer srv.Close()

	s := NewSoftwareSupplyChainScanner()
	got, _ := s.Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	hit := false
	for _, f := range got {
		if strings.Contains(f.Title, "Environment file") && f.Severity == SeverityCritical {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real .env content was missed: findings=%+v", got)
	}
}
