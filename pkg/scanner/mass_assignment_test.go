package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestMassAssignment_SkipsNonAPIPaths(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts++
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>admin role verified approved</body></html>`))
	}))
	defer srv.Close()

	s := NewMassAssignmentScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/contact", httpengine.NewClient(httpengine.DefaultConfig()))
	if posts != 0 {
		t.Errorf("scanner posted to non-API path %d times", posts)
	}
	if len(findings) != 0 {
		t.Errorf("non-API path produced findings: %+v", findings)
	}
}

func TestMassAssignment_SkipsHTMLResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// HTML body that literally contains "role" and "admin" prose.
		_, _ = w.Write([]byte(`<html><body>user role: admin verified approved</body></html>`))
	}))
	defer srv.Close()

	s := NewMassAssignmentScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/api/users", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Errorf("HTML response on API path produced findings: %+v", findings)
	}
}

func TestMassAssignment_RealJSONEchoIsFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real vuln: server accepts the role field, echoes it back as JSON.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"role":"admin","email":"x@y.com"}`))
	}))
	defer srv.Close()

	s := NewMassAssignmentScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/api/v1/users", httpengine.NewClient(httpengine.DefaultConfig()))
	hit := false
	for _, f := range findings {
		if f.Parameter == "role" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("real JSON echo of role field was missed: %+v", findings)
	}
}

func TestMassAssignment_JSONWithoutEchoIsNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Server returns JSON but strips the privileged field.
		_, _ = w.Write([]byte(`{"id":42,"email":"x@y.com"}`))
	}))
	defer srv.Close()

	s := NewMassAssignmentScanner()
	findings, _ := s.Scan(context.Background(), srv.URL+"/api/users", httpengine.NewClient(httpengine.DefaultConfig()))
	if len(findings) != 0 {
		t.Errorf("JSON without echo should not produce findings: %+v", findings)
	}
}

func TestLooksLikeAPIPath(t *testing.T) {
	cases := []struct{ url string; want bool }{
		{"https://x.com/api/users", true},
		{"https://x.com/v1/users", true},
		{"https://x.com/v2/x", true},
		{"https://x.com/rest/foo", true},
		{"https://x.com/graphql", true},
		{"https://x.com/contact", false},
		{"https://x.com/", false},
		{"https://x.com/about", false},
	}
	for _, c := range cases {
		if got := looksLikeAPIPath(c.url); got != c.want {
			t.Errorf("looksLikeAPIPath(%q)=%v want %v", c.url, got, c.want)
		}
	}
}
