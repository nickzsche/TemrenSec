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

// DefaultAnthropicModel is the fallback when neither the Model field nor the
// TEMREN_ANTHROPIC_MODEL env var is set. Kept as a constant so it shows up in
// `go doc` and stays greppable when Anthropic ships a new model.
const DefaultAnthropicModel = "claude-opus-4-7"

// AnthropicProvider talks to api.anthropic.com (Messages API).
//
// Model resolution order:
//  1. Model field (set explicitly via struct literal)
//  2. TEMREN_ANTHROPIC_MODEL env var
//  3. DefaultAnthropicModel
type AnthropicProvider struct {
	HTTP      *http.Client
	APIKey    string
	Model     string
	MaxTokens int
	BaseURL   string
}

func NewAnthropicProvider(apiKey string) *AnthropicProvider {
	model := os.Getenv("TEMREN_ANTHROPIC_MODEL")
	if model == "" {
		model = DefaultAnthropicModel
	}
	return &AnthropicProvider{
		HTTP:      &http.Client{Timeout: 60 * time.Second},
		APIKey:    apiKey,
		Model:     model,
		MaxTokens: 1024,
		BaseURL:   "https://api.anthropic.com",
	}
}

func (a *AnthropicProvider) Name() string { return "anthropic" }

func (a *AnthropicProvider) Complete(ctx context.Context, system, user string) (string, error) {
	payload := map[string]any{
		"model":      a.Model,
		"max_tokens": a.MaxTokens,
		"system":     system,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+"/v1/messages", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, body)
	}
	var raw struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}
	var out string
	for _, c := range raw.Content {
		if c.Type == "text" {
			out += c.Text
		}
	}
	return out, nil
}
