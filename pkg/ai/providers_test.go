package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnthropicProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": "hello from claude"}},
		})
	}))
	defer srv.Close()
	p := NewAnthropicProvider("key")
	p.BaseURL = srv.URL
	out, err := p.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("unexpected: %q", out)
	}
}

func TestOpenAIProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "hi from gpt"}}},
		})
	}))
	defer srv.Close()
	p := NewOpenAIProvider("k")
	p.BaseURL = srv.URL
	out, err := p.Complete(context.Background(), "sys", "u")
	if err != nil {
		t.Fatal(err)
	}
	if out != "hi from gpt" {
		t.Errorf("got %q", out)
	}
}

func TestOllamaProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]string{"content": "hi from llama"},
		})
	}))
	defer srv.Close()
	p := NewOllamaProvider("")
	p.BaseURL = srv.URL
	out, err := p.Complete(context.Background(), "sys", "u")
	if err != nil {
		t.Fatal(err)
	}
	if out != "hi from llama" {
		t.Errorf("got %q", out)
	}
}

func TestProvidersImplementInterface(t *testing.T) {
	var _ Provider = NewAnthropicProvider("k")
	var _ Provider = NewOpenAIProvider("k")
	var _ Provider = NewOllamaProvider("")
}

func TestAnthropicModelResolution(t *testing.T) {
	t.Setenv("TEMREN_ANTHROPIC_MODEL", "")
	if got := NewAnthropicProvider("k").Model; got != DefaultAnthropicModel {
		t.Errorf("default model = %q, want %q", got, DefaultAnthropicModel)
	}
	t.Setenv("TEMREN_ANTHROPIC_MODEL", "claude-opus-5-0-future")
	if got := NewAnthropicProvider("k").Model; got != "claude-opus-5-0-future" {
		t.Errorf("env override = %q, want claude-opus-5-0-future", got)
	}
}

func TestOpenAIModelResolution(t *testing.T) {
	t.Setenv("TEMREN_OPENAI_MODEL", "")
	if got := NewOpenAIProvider("k").Model; got != DefaultOpenAIModel {
		t.Errorf("default model = %q, want %q", got, DefaultOpenAIModel)
	}
	t.Setenv("TEMREN_OPENAI_MODEL", "gpt-5-experimental")
	if got := NewOpenAIProvider("k").Model; got != "gpt-5-experimental" {
		t.Errorf("env override = %q", got)
	}
}

func TestOllamaModelResolution(t *testing.T) {
	t.Setenv("TEMREN_OLLAMA_MODEL", "")
	t.Setenv("TEMREN_OLLAMA_URL", "")
	p := NewOllamaProvider("")
	if p.Model != DefaultOllamaModel {
		t.Errorf("default model = %q, want %q", p.Model, DefaultOllamaModel)
	}
	if p.BaseURL != "http://localhost:11434" {
		t.Errorf("default base url = %q", p.BaseURL)
	}
	t.Setenv("TEMREN_OLLAMA_MODEL", "mistral")
	t.Setenv("TEMREN_OLLAMA_URL", "http://ollama.internal:11434")
	p = NewOllamaProvider("")
	if p.Model != "mistral" || p.BaseURL != "http://ollama.internal:11434" {
		t.Errorf("env override = model=%q url=%q", p.Model, p.BaseURL)
	}
	// Explicit model arg wins over env.
	t.Setenv("TEMREN_OLLAMA_MODEL", "mistral")
	if got := NewOllamaProvider("phi3").Model; got != "phi3" {
		t.Errorf("explicit arg = %q, want phi3", got)
	}
}
