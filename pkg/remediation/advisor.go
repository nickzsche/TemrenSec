package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/temren/pkg/scanner"
)

type Remediation struct {
	Finding       scanner.Finding
	FixSuggestion string
	CodeFix       string
	References    []string
	Priority      string // "immediate", "high", "medium", "low"
	Effort        string // "trivial", "moderate", "significant"
	Category      string // OWASP category
}

type AdvisorConfig struct {
	Provider    string  // "openai", "anthropic", "ollama", "none"
	APIKey      string
	Model       string
	BaseURL     string
	MaxTokens   int
	Temperature float64
}

type Advisor struct {
	config    AdvisorConfig
	client    *http.Client
	ruleBased *RuleBasedAdvisor
}

func NewAdvisor(config AdvisorConfig) *Advisor {
	if config.MaxTokens == 0 {
		config.MaxTokens = 1024
	}
	if config.Temperature == 0 {
		config.Temperature = 0.3
	}
	return &Advisor{
		config:    config,
		client:    &http.Client{Timeout: 30 * time.Second},
		ruleBased: NewRuleBasedAdvisor(),
	}
}

func (a *Advisor) Suggest(ctx context.Context, findings []scanner.Finding) []Remediation {
	results := make([]Remediation, 0, len(findings))
	for _, f := range findings {
		r, err := a.SuggestSingle(ctx, f)
		if err != nil || r == nil {
			continue
		}
		results = append(results, *r)
	}
	return results
}

func (a *Advisor) SuggestSingle(ctx context.Context, finding scanner.Finding) (*Remediation, error) {
	if a.config.Provider == "none" || a.config.Provider == "" {
		return a.ruleBased.Suggest(finding), nil
	}

	prompt := buildPrompt(finding)

	var llmResult *llmResponse
	var err error

	switch a.config.Provider {
	case "openai":
		llmResult, err = a.callOpenAI(ctx, prompt)
	case "anthropic":
		llmResult, err = a.callAnthropic(ctx, prompt)
	case "ollama":
		llmResult, err = a.callOllama(ctx, prompt)
	default:
		return a.ruleBased.Suggest(finding), nil
	}

	if err != nil || llmResult == nil {
		return a.ruleBased.Suggest(finding), nil
	}

	return &Remediation{
		Finding:       finding,
		FixSuggestion: llmResult.Fix,
		CodeFix:       llmResult.Code,
		References:    llmResult.References,
		Priority:      llmResult.Priority,
		Effort:        llmResult.Effort,
		Category:      finding.OWASPCategory,
	}, nil
}

type llmResponse struct {
	Fix        string   `json:"fix"`
	Code       string   `json:"code"`
	References []string `json:"references"`
	Priority   string   `json:"priority"`
	Effort     string   `json:"effort"`
}

func buildPrompt(f scanner.Finding) string {
	return fmt.Sprintf(`You are a security expert. Given this vulnerability finding, provide a specific, actionable fix.

Finding: %s
Severity: %s
URL: %s
Evidence: %s
Scanner: %s

Provide:
1. A brief description of the fix (2-3 sentences)
2. A code example showing the fix
3. Relevant references (OWASP, CVE links)

Format your response as JSON:
{
  "fix": "...",
  "code": "...",
  "references": ["..."],
  "priority": "immediate|high|medium|low",
  "effort": "trivial|moderate|significant"
}`, f.Title, f.Severity, f.URL, f.Evidence, f.Scanner)
}

func parseLLMResponse(body []byte) (*llmResponse, error) {
	var resp llmResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse LLM response: %w", err)
	}
	return &resp, nil
}