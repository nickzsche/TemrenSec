package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// DefaultOllamaModel is the fallback when no model is passed and the
// TEMREN_OLLAMA_MODEL env var is also empty.
const DefaultOllamaModel = "llama3"

// OllamaProvider talks to a local Ollama server (default http://localhost:11434).
// No API key needed; great for air-gapped deployments.
//
// Base URL resolution: TEMREN_OLLAMA_URL env var, else http://localhost:11434.
type OllamaProvider struct {
	HTTP    *http.Client
	BaseURL string
	Model   string
}

func NewOllamaProvider(model string) *OllamaProvider {
	if model == "" {
		model = os.Getenv("TEMREN_OLLAMA_MODEL")
	}
	if model == "" {
		model = DefaultOllamaModel
	}
	baseURL := os.Getenv("TEMREN_OLLAMA_URL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{
		HTTP:    &http.Client{Timeout: 120 * time.Second},
		BaseURL: baseURL,
		Model:   model,
	}
}

func (o *OllamaProvider) Name() string { return "ollama" }

func (o *OllamaProvider) Complete(ctx context.Context, system, user string) (string, error) {
	payload := map[string]any{
		"model": o.Model,
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"stream": false,
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/api/chat", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("ollama %d: %s", resp.StatusCode, body)
	}
	var raw struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}
	return raw.Message.Content, nil
}
