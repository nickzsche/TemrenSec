package templates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func engineWith(t Template) *Engine { return &Engine{templates: []Template{t}} }

// statusOnly template (like exposed-svn-entries) — fires on any 200.
func statusTemplate(path string) Template {
	return Template{ID: "test-status", Info: Info{Name: "X", Severity: "medium"}, Requests: []Request{{
		Method: "GET", Path: []string{"{{BaseURL}}" + path},
		Matchers: []Matcher{{Type: "status", Status: []int{200}}},
	}}}
}

func TestSoftGuard_SuppressesCatchAll200(t *testing.T) {
	// Server returns 200 + a big shell that reflects the path, for EVERY URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("shell ", 2000) + " path=" + r.URL.Path + "</body></html>"))
	}))
	defer srv.Close()
	m := engineWith(statusTemplate("/.svn/entries")).Run(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(m) != 0 {
		t.Fatalf("catch-all 200 must be suppressed, got %+v", m)
	}
}

func TestSoftGuard_KeepsGenuineHit(t *testing.T) {
	// Real .svn/entries exists (distinct small body); everything else 404s.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.svn/entries" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("12\n\ndir\n0\n"))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("notfound ", 2000) + "</body></html>"))
	}))
	defer srv.Close()
	m := engineWith(statusTemplate("/.svn/entries")).Run(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(m) != 1 {
		t.Fatalf("genuine exposure (200 vs 404 sibling) must be kept, got %+v", m)
	}
}

func TestSoftGuard_SuppressesReflectedWord(t *testing.T) {
	// Uniform 404 shell that reflects the path → the word "kibana" appears in
	// the body only because the path does. Must not be flagged.
	tpl := Template{ID: "test-kibana", Info: Info{Name: "K", Severity: "medium"}, Requests: []Request{{
		Method: "GET", Path: []string{"{{BaseURL}}/app/kibana"},
		Matchers: []Matcher{{Type: "word", Part: "all", Words: []string{"kibana"}}},
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html><body>Sayfa bulunamadı: " + r.URL.Path + " " + strings.Repeat("x ", 1500) + "</body></html>"))
	}))
	defer srv.Close()
	m := engineWith(tpl).Run(context.Background(), srv.URL, httpengine.NewClient(httpengine.DefaultConfig()))
	if len(m) != 0 {
		t.Fatalf("reflected-word soft-404 must be suppressed, got %+v", m)
	}
}
