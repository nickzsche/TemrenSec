package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestJWTJKU_PlainUnauthorizedIsNotFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	defer srv.Close()

	s := NewJWTJKUInjectionScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Errorf("plain 401 produced %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestJWTJKU_JWKSMarkerInResponseFires(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"unable to fetch jwks from provided jku","detail":"connection refused"}`))
	}))
	defer srv.Close()

	s := NewJWTJKUInjectionScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 1 {
		t.Fatalf("JWKS marker should fire exactly one finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %s, want medium", findings[0].Severity)
	}
}

func TestJWTJKU_PerHostCache(t *testing.T) {
	probes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes++
		w.WriteHeader(401)
	}))
	defer srv.Close()

	s := NewJWTJKUInjectionScanner()
	c := httpengine.NewClient(httpengine.DefaultConfig())
	_, _ = s.Scan(context.Background(), srv.URL+"/a", c)
	first := probes
	_, _ = s.Scan(context.Background(), srv.URL+"/b", c)
	_, _ = s.Scan(context.Background(), srv.URL+"/c", c)
	if probes != first {
		t.Errorf("per-host cache not engaged: %d extra probes", probes-first)
	}
}
