package llmscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPromptInjectionDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		// Echo the literal injected marker
		json.NewEncoder(w).Encode(map[string]string{"reply": "TEMREN_PWNED"})
		_ = body
	}))
	defer srv.Close()

	s := New(srv.URL)
	findings, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	var seenInjection bool
	for _, f := range findings {
		if strings.Contains(f.Title, "Prompt Injection") {
			seenInjection = true
		}
	}
	if !seenInjection {
		t.Errorf("expected prompt-injection finding; got %d findings", len(findings))
	}
}

func TestNoFalsePositiveOnSafeServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"reply": "I can't help with that."})
	}))
	defer srv.Close()
	s := New(srv.URL)
	findings, _ := s.Run(context.Background())
	if len(findings) != 0 {
		t.Errorf("safe replies should not produce findings, got %d", len(findings))
	}
}

func TestExtractReplyOpenAIStyle(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"content":"hello world"}}]}`)
	if got := extractReply(body, "choices[0].message.content"); got != "hello world" {
		t.Errorf("got %q", got)
	}
}

func TestExtractReplyFallback(t *testing.T) {
	body := []byte(`{"text":"hi"}`)
	if got := extractReply(body, ""); got != "hi" {
		t.Errorf("got %q", got)
	}
}
