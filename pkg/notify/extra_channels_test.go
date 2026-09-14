package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSlackSendsAttachment(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	s := NewSlack(srv.URL)
	if err := s.Send(context.Background(), Event{Title: "x", Severity: SeverityCritical, Description: "d"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["attachments"]; !ok {
		t.Errorf("missing attachments: %v", body)
	}
}

func TestDiscordSendsEmbedColor(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := NewDiscord(srv.URL)
	if err := d.Send(context.Background(), Event{Title: "x", Severity: SeverityHigh, Description: "d"}); err != nil {
		t.Fatal(err)
	}
	embeds, ok := body["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatalf("missing embeds: %v", body)
	}
}

func TestTeamsSendsMessageCard(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	te := NewTeams(srv.URL)
	if err := te.Send(context.Background(), Event{Title: "x", Severity: SeverityMedium, Description: "d"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "MessageCard") {
		t.Errorf("missing MessageCard: %s", raw)
	}
}
