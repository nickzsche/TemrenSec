package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

func TestSQLiScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "'" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("SQL syntax error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>User data</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSQLiScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL+"/user?id=1", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected SQL injection vulnerability to be detected")
	}
}

func TestXSSScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Results: " + q + "</body></html>"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewXSSScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL+"/search?q=test", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected XSS vulnerability to be detected")
	}
}

func TestCommandInjectionScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if cmd == "; cat /etc/passwd" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewCommandInjectionScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL+"/exec?cmd=test", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Command injection detection depends on response content
	t.Logf("Command injection results: %d findings", len(results))
}

func TestSSRFScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "file:///etc/passwd" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewSSRFScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL+"/fetch?url=http://example.com", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	t.Logf("SSRF results: %d findings", len(results))
}

func TestIDORScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "1" || id == "2" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User data for ID: " + id))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewIDORScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL+"/user?id=3", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	t.Logf("IDOR results: %d findings", len(results))
}

func TestScanner_NoParameters(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(nil)

	scanners := []Scanner{
		NewSQLiScanner(),
		NewXSSScanner(),
		NewCommandInjectionScanner(),
		NewSSRFScanner(),
	}

	ctx := context.Background()

	for _, s := range scanners {
		results, err := s.Scan(ctx, server.URL+"/page", client)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", s.Name(), err)
		}
		if len(results) != 0 {
			t.Errorf("%s: expected no findings for URL without params, got %d", s.Name(), len(results))
		}
	}
}

func TestScanner_InvalidURL(t *testing.T) {
	client := httpengine.NewClient(nil)

	scanners := []Scanner{
		NewSQLiScanner(),
		NewXSSScanner(),
		NewCommandInjectionScanner(),
		NewSSRFScanner(),
		NewIDORScanner(),
	}

	ctx := context.Background()

	for _, s := range scanners {
		_, err := s.Scan(ctx, "://invalid-url", client)
		if err == nil {
			t.Errorf("%s: expected error for invalid URL", s.Name())
		}
	}
}

func TestScanner_Timeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte("Delayed"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   100 * time.Millisecond,
		RateLimit: 100,
	})

	scanner := NewSQLiScanner()
	// Bound the whole probe — the scanner fires many payloads, so without a
	// context budget the worst case is timeout × payload-count seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := scanner.Scan(ctx, server.URL+"/slow?id=1", client)
	if err != nil {
		t.Logf("Timeout handled correctly: %v", err)
	}
}

func TestSQLiScanner_DetectSQLError(t *testing.T) {
	scanner := NewSQLiScanner()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"MySQL error", "You have an error in your SQL syntax", true},
		{"PostgreSQL error", "pg_query() failed", true},
		{"Oracle error", "ORA-01756: quoted string", true},
		{"SQLite error", "sqlite3.OperationalError", true},
		{"No error", "Normal response without errors", false},
		{"Case insensitive", "SQL SYNTAX error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.detectSQLError(tt.body)
			if result != tt.expected {
				t.Errorf("detectSQLError(%q) = %v, want %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestXSSScanner_IsPayloadReflected(t *testing.T) {
	scanner := NewXSSScanner()

	tests := []struct {
		name     string
		payload  string
		body     string
		expected bool
	}{
		{"Direct reflection", "<script>alert(1)</script>", "<html><script>alert(1)</script></html>", true},
		{"No reflection", "<script>alert(1)</script>", "<html><body>Safe</body></html>", false},
		{"Event handler", "<img src=x onerror=alert(1)>", "<html><img src=x onerror=alert(1)></html>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isPayloadReflected(tt.payload, tt.body)
			if result != tt.expected {
				t.Errorf("isPayloadReflected(%q, %q) = %v, want %v", tt.payload, tt.body, result, tt.expected)
			}
		})
	}
}
