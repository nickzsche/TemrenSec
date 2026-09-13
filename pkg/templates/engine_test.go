package templates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/temren/pkg/httpengine"
)

func TestMatcherStatus(t *testing.T) {
	m := Matcher{Type: "status", Status: []int{200, 301}}
	if !m.Match(Response{Status: 301}) {
		t.Fatal("301 should match")
	}
	if m.Match(Response{Status: 404}) {
		t.Fatal("404 should not match")
	}
}

func TestMatcherWordAndOr(t *testing.T) {
	body := Response{Body: "PHP Version 8.2 phpinfo()"}
	or := Matcher{Type: "word", Words: []string{"nope", "phpinfo()"}, Condition: "or"}
	if !or.Match(body) {
		t.Fatal("or should match on one hit")
	}
	and := Matcher{Type: "word", Words: []string{"PHP Version", "missing"}, Condition: "and"}
	if and.Match(body) {
		t.Fatal("and should fail when one word absent")
	}
}

func TestMatcherRegexAndNegative(t *testing.T) {
	r := Response{Body: "DB_PASSWORD=secret"}
	m := Matcher{Type: "regex", Regex: []string{`(?i)DB_PASSWORD=`}}
	if !m.Match(r) {
		t.Fatal("regex should match")
	}
	neg := Matcher{Type: "regex", Regex: []string{`NOTHERE`}, Negative: true}
	if !neg.Match(r) {
		t.Fatal("negative of a non-match should be true")
	}
}

func TestRequestMatchersCondition(t *testing.T) {
	r := Response{Status: 200, Body: "[core] repositoryformatversion = 0"}
	req := Request{
		MatchersCondition: "and",
		Matchers: []Matcher{
			{Type: "status", Status: []int{200}},
			{Type: "word", Words: []string{"[core]"}},
		},
	}
	if !req.Matches(r) {
		t.Fatal("both matchers should pass under AND")
	}
	req.Matchers[1].Words = []string{"absent"}
	if req.Matches(r) {
		t.Fatal("AND should fail when one matcher fails")
	}
}

func TestBundledTemplatesLoad(t *testing.T) {
	e := New()
	if e.Count() < 8 {
		t.Fatalf("expected the bundled template set to load, got %d", e.Count())
	}
}

func TestEngineRunAgainstServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	e := New()
	client := httpengine.NewClient(&httpengine.Config{Timeout: 5_000_000_000, RateLimit: 50, MaxRedirects: 5, FollowRedirects: true})
	matches := e.Run(context.Background(), srv.URL, client)

	var got bool
	for _, m := range matches {
		if m.TemplateID == "exposed-git-config" {
			got = true
		}
	}
	if !got {
		t.Fatalf("expected exposed-git-config to match, got %d matches", len(matches))
	}
}
