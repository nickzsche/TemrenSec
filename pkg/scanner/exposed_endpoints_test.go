package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

// soft404Handler mimics a Next.js / Vite catch-all that returns 200 + HTML
// for any path, which used to trip the .env / .git probes as critical FPs.
func soft404Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"></head><body><div>Teklif Bulunamadı</div></body></html>`))
	})
}

func TestExposedEndpoints_SoftHTML404IsNotCritical(t *testing.T) {
	srv := httptest.NewServer(soft404Handler())
	defer srv.Close()

	s := NewExposedEndpointsScanner()
	findings, err := s.Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			t.Errorf("SPA soft-404 produced %s finding: %s @ %s", f.Severity, f.Title, f.URL)
		}
	}
}

func TestExposedEndpoints_RealEnvIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("DB_PASSWORD=hunter2\nAPI_KEY=sk-live-xxx\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewExposedEndpointsScanner()
	findings, err := s.Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, ".env") && f.Severity == SeverityCritical {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real .env exposure was missed; findings=%+v", findings)
	}
}

func TestExposedEndpoints_RealGitHeadIsDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	s := NewExposedEndpointsScanner()
	findings, err := s.Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, ".git") && f.Severity == SeverityCritical {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real .git/HEAD exposure was missed")
	}
}

func TestExposedEndpoints_HTMLBodyWithoutCTIsRejected(t *testing.T) {
	// Some misconfigured servers strip Content-Type but still send HTML.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "") // no CT
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>oops</body></html>"))
	}))
	defer srv.Close()

	s := NewExposedEndpointsScanner()
	findings, _ := s.Scan(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			t.Errorf("HTML-without-CT produced critical FP: %s", f.Title)
		}
	}
}
