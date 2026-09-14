package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestSourceMapLeak_ExposedMapIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><script src="/app.js"></script></body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`console.log("minified")`))
		case "/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	findings, _ := NewSourceMapLeakScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) == 0 {
		t.Fatalf("exposed source map was not flagged")
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("expected SeverityLow, got %s", findings[0].Severity)
	}
	if findings[0].OWASPCategory != "A02 Security Misconfiguration" {
		t.Errorf("unexpected OWASP category: %s", findings[0].OWASPCategory)
	}
}

func TestSourceMapLeak_NoMapProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><script src="/app.js"></script></body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`console.log("minified")`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	findings, _ := NewSourceMapLeakScanner().Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}
