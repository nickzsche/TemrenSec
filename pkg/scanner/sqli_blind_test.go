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

func hasTitle(fs []Finding, substr string) *Finding {
	for i := range fs {
		if strings.Contains(fs[i].Title, substr) {
			return &fs[i]
		}
	}
	return nil
}

func TestSQLi_ErrorBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"") {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("You have an error in your SQL syntax near '''"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	s := NewSQLiScanner()
	f, _ := s.Scan(context.Background(), srv.URL+"/?id=1", httpengine.NewClient(httpengine.DefaultConfig()))
	if hasTitle(f, "error-based") == nil {
		t.Fatalf("expected error-based finding, got %+v", f)
	}
}

func TestSQLi_BooleanBlind(t *testing.T) {
	long := strings.Repeat("row ", 400) // ~1600 bytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// FALSE conditions collapse the result set to a short page.
		if strings.Contains(id, "1'='2") || strings.Contains(id, "1\"=\"2") || strings.Contains(id, "1=2") {
			_, _ = w.Write([]byte("no results"))
			return
		}
		// Baseline and TRUE conditions return the full page. No SQL errors.
		_, _ = w.Write([]byte(long))
	}))
	defer srv.Close()

	s := NewSQLiScanner()
	f, _ := s.Scan(context.Background(), srv.URL+"/?id=1", httpengine.NewClient(httpengine.DefaultConfig()))
	if hasTitle(f, "boolean-based blind") == nil {
		t.Fatalf("expected boolean-based blind finding, got %+v", f)
	}
}

func TestSQLi_TimeBlind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(strings.ToLower(id), "sleep(") ||
			strings.Contains(strings.ToLower(id), "pg_sleep") ||
			strings.Contains(strings.ToLower(id), "waitfor") {
			time.Sleep(2 * time.Second)
		}
		_, _ = w.Write([]byte("constant body")) // same length always -> no boolean signal
	}))
	defer srv.Close()

	s := &SQLiScanner{SleepSeconds: 2}
	f, _ := s.Scan(context.Background(), srv.URL+"/?id=1", httpengine.NewClient(httpengine.DefaultConfig()))
	if hasTitle(f, "time-based blind") == nil {
		t.Fatalf("expected time-based blind finding, got %+v", f)
	}
}

func TestSQLi_NoFalsePositiveOnStatic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>static page, always identical</html>"))
	}))
	defer srv.Close()

	s := NewSQLiScanner()
	f, _ := s.Scan(context.Background(), srv.URL+"/?id=1", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(f) != 0 {
		t.Fatalf("expected no findings on static page, got %+v", f)
	}
}

func TestSimilarLen(t *testing.T) {
	if !similarLen(1000, 1010) {
		t.Error("1000~1010 should be similar")
	}
	if similarLen(1000, 100) {
		t.Error("1000 vs 100 should differ")
	}
	if !similarLen(10, 12) { // within 32-byte floor
		t.Error("tiny bodies within 32 bytes should be similar")
	}
}
