package defectdojo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPullFindings_PaginatesAndProjects(t *testing.T) {
	// Two-page response. The first page returns Next pointing at ?page=2;
	// the second returns Next = "" to terminate.
	var page2URL string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/findings/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			resp := ddFindingPage{
				Results: []ddFinding{
					{ID: 2, Title: "B", Severity: "Low", FalseP: true, Tags: []string{"temren-id:vuln-2"}, LastStatusUpdate: time.Now()},
				},
			}
			body, _ := json.Marshal(resp)
			w.Write(body)
			return
		}
		// First page
		resp := ddFindingPage{
			Next: page2URL,
			Results: []ddFinding{
				{ID: 1, Title: "A", Severity: "High", Active: true, Tags: []string{"temren-id:vuln-1", "env:prod"}, LastStatusUpdate: time.Now()},
			},
		}
		body, _ := json.Marshal(resp)
		w.Write(body)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	page2URL = srv.URL + "/api/v2/findings/?page=2"

	c := NewClient(&Config{BaseURL: srv.URL, APIToken: "test"})
	got, err := c.PullFindings(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("PullFindings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	if got[0].TemrenVulnID != "vuln-1" || got[1].TemrenVulnID != "vuln-2" {
		t.Errorf("temren IDs not extracted: %+v %+v", got[0], got[1])
	}
	if got[1].Status != "false_positive" {
		t.Errorf("expected false_positive status for #2, got %q", got[1].Status)
	}
}

func TestPullFindings_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no auth", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewClient(&Config{BaseURL: srv.URL, APIToken: "bad"})
	_, err := c.PullFindings(context.Background(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got: %v", err)
	}
}

func TestExtractTemrenID(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"temren-id:abc-123":                 "abc-123",
		"prefix-stripped":                  "",
		"temren-id:":                        "",
	}
	for in, want := range cases {
		tags := []string{"env:prod", in, "auto-import"}
		if got := extractTemrenID(tags); got != want {
			t.Errorf("extractTemrenID(%q) = %q, want %q", in, got, want)
		}
	}
}
