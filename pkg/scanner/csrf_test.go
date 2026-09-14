package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestCSRF_FormWithTokenProducesNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/transfer">
				<input type="hidden" name="csrf_token" value="abc123">
				<input type="text" name="amount">
			</form>
		</body></html>`))
	}))
	defer srv.Close()

	s := NewCSRFScanner()
	findings, err := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("token-protected form produced %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestCSRF_PostFormWithoutTokenIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="POST" action="/transfer">
				<input type="text" name="amount">
				<input type="submit">
			</form>
		</body></html>`))
	}))
	defer srv.Close()

	s := NewCSRFScanner()
	findings, err := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CSRF") && f.Severity == SeverityMedium {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("POST form without token was missed: %+v", findings)
	}
}

func TestCSRF_GetFormAndSPAIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form method="GET" action="/search"><input type="text" name="q"></form>
			<script>fetch('/api/json')</script>
		</body></html>`))
	}))
	defer srv.Close()

	s := NewCSRFScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Fatalf("GET form / SPA shell produced %d findings, want 0: %+v", len(findings), findings)
	}
}
