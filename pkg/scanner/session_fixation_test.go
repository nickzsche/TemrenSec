package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestSessionFixation_NoRotationIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "anon123"})
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			w.WriteHeader(http.StatusUnauthorized) // no Set-Cookie: session not rotated
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	s := NewSessionFixationScanner()
	findings, err := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	hit := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Session Fixation") && f.Severity == SeverityMedium {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("non-rotated session was missed: %+v", findings)
	}
}

func TestSessionFixation_RotatedSessionIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "anon123"})
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "fresh456"})
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	s := NewSessionFixationScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Fatalf("rotated session produced %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestSessionFixation_NoSessionCookieIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // no Set-Cookie at all
	}))
	defer srv.Close()

	s := NewSessionFixationScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Fatalf("stateless host produced %d findings, want 0: %+v", len(findings), findings)
	}
}
