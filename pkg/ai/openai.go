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

// DefaultOpenAIModel is the fallback when neither the Model field nor the
// TEMREN_OPENAI_MODEL env var is set.
const DefaultOpenAIModel = "gpt-4o-mini"

// OpenAIProvider implements the chat-completions API.
//
// Model resolution order:
//  1. Model field (explicit)
//  2. TEMREN_OPENAI_MODEL env var
//  3. DefaultOpenAIModel
type OpenAIProvider struct {
	HTTP    *http.Client
	APIKey  string
	Model   string
	BaseURL string
}

func NewOpenAIProvider(apiKey string) *OpenAIProvider {
	model := os.Getenv("TEMREN_OPENAI_MODEL")
	if model == "" {
		model = DefaultOpenAIModel
	}
	return &OpenAIProvider{
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		APIKey:  apiKey,
		Model:   model,
		BaseURL: "https://api.openai.com",
	}
}

func (o *OpenAIProvider) Name() string { return "openai" }

func (o *OpenAIProvider) Complete(ctx context.Context, system, user string) (string, error) {
	payload := map[string]any{
		"model": o.Model,
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": 0,
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/v1/chat/completions", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.APIKey)
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("openai %d: %s", resp.StatusCode, body)
	}
	var raw struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return "", err
	}
	if len(raw.Choices) == 0 {
		return "", fmt.Errorf("no choices returned")
	}
	return raw.Choices[0].Message.Content, nil
}
