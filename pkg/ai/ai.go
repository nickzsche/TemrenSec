// Package ai provides LLM-backed analysis helpers (triage, exploit-chain reasoning,
// executive summary, NL→scan-config). Backends are pluggable via the Provider interface
// so callers can swap Anthropic / OpenAI / Ollama / mock without changing call sites.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/temren/pkg/scanner"
)

// Provider is the minimum LLM surface used by this package.
type Provider interface {
	Complete(ctx context.Context, system, user string) (string, error)
	Name() string
}

// Engine wraps a provider with high-level operations.
type Engine struct {
	P Provider
}

func New(p Provider) *Engine { return &Engine{P: p} }

// TriageVerdict describes the engine's confidence that a finding is real.
type TriageVerdict struct {
	Finding    scanner.Finding `json:"finding"`
	IsTrueHit  bool            `json:"is_true_hit"`
	Confidence float64         `json:"confidence"` // 0..1
	Reasoning  string          `json:"reasoning"`
	Remediation string         `json:"remediation"`
}

const triageSystem = `You are a senior application security engineer.
You receive a vulnerability finding from an automated scanner and rate the probability
that it is a real exploit-worthy issue vs. a false positive. Reply with strict JSON:
{"is_true_hit": bool, "confidence": float, "reasoning": "...", "remediation": "..."}`

// Triage classifies a finding as TP/FP and returns remediation guidance.
func (e *Engine) Triage(ctx context.Context, f scanner.Finding) (TriageVerdict, error) {
	if e == nil || e.P == nil {
		return TriageVerdict{Finding: f, IsTrueHit: true, Confidence: 0.5, Reasoning: "AI disabled"}, nil
	}
	buf, _ := json.Marshal(f)
	resp, err := e.P.Complete(ctx, triageSystem, string(buf))
	if err != nil {
		return TriageVerdict{Finding: f}, err
	}
	var v TriageVerdict
	v.Finding = f
	resp = extractJSON(resp)
	if err := json.Unmarshal([]byte(resp), &v); err != nil {
		// Best-effort: pass back raw reasoning, conservative defaults.
		v.IsTrueHit = !strings.Contains(strings.ToLower(resp), "false positive")
		v.Confidence = 0.5
		v.Reasoning = resp
	}
	return v, nil
}

// ExploitChain proposes a chained attack across multiple findings.
type ExploitChain struct {
	Title    string   `json:"title"`
	Steps    []string `json:"steps"`
	Impact   string   `json:"impact"`
	Findings []string `json:"finding_ids"`
}

const chainSystem = `Given a list of vulnerability findings, identify chained-attack paths that combine multiple findings
to escalate impact (e.g., open-redirect + cookie leak -> account takeover). Return JSON: [{"title","steps","impact","finding_ids"}].
Only propose chains that are plausible from the inputs.`

func (e *Engine) ExploitChain(ctx context.Context, findings []scanner.Finding) ([]ExploitChain, error) {
	if e == nil || e.P == nil || len(findings) == 0 {
		return nil, nil
	}
	buf, _ := json.Marshal(findings)
	resp, err := e.P.Complete(ctx, chainSystem, string(buf))
	if err != nil {
		return nil, err
	}
	resp = extractJSON(resp)
	var chains []ExploitChain
	_ = json.Unmarshal([]byte(resp), &chains)
	return chains, nil
}

// ExecutiveSummary returns a non-technical paragraph for leadership.
const execSystem = `Write a 3-5 sentence non-technical executive summary of these security findings for a CTO.
Focus on business risk, regulatory exposure, and the top 3 actions. No jargon.`

func (e *Engine) ExecutiveSummary(ctx context.Context, findings []scanner.Finding) (string, error) {
	if e == nil || e.P == nil {
		return fallbackExecutiveSummary(findings), nil
	}
	buf, _ := json.Marshal(findings)
	return e.P.Complete(ctx, execSystem, string(buf))
}

// ScanQuery is the schema we ask the LLM to fill from a natural-language target description.
type ScanQuery struct {
	Targets []string `json:"targets"`
	Scanners []string `json:"scanners"`
	Excludes []string `json:"excludes"`
	Notes    string   `json:"notes"`
}

const nlSystem = `Convert this natural language description of a security scan request into a JSON object:
{"targets":["url"],"scanners":["sqli","xss",...],"excludes":[],"notes":"..."}
Valid scanner names: sqli, xss, ssrf, ssti, xxe, idor, lfi, rce, jwt, oauth, cors, headers, secrets, deserialization, graphql, race, mass_assign, ldap, xpath, cache_poison, cache_deception, smuggling, host_header, exposed_endpoints, dependency_check.`

func (e *Engine) NLQuery(ctx context.Context, prompt string) (ScanQuery, error) {
	var q ScanQuery
	if e == nil || e.P == nil {
		return q, fmt.Errorf("AI provider not configured")
	}
	resp, err := e.P.Complete(ctx, nlSystem, prompt)
	if err != nil {
		return q, err
	}
	resp = extractJSON(resp)
	if err := json.Unmarshal([]byte(resp), &q); err != nil {
		return q, fmt.Errorf("parse response: %w", err)
	}
	return q, nil
}

// extractJSON tolerates LLMs that wrap their answer in markdown fences.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	// First and last brace
	first := strings.IndexAny(s, "[{")
	last := strings.LastIndexAny(s, "]}")
	if first >= 0 && last > first {
		return s[first : last+1]
	}
	return s
}

func fallbackExecutiveSummary(findings []scanner.Finding) string {
	counts := map[scanner.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return fmt.Sprintf("Temren detected %d issues (%d critical, %d high). Highest-priority items affect data integrity and access control; remediate critical findings within 7 days and rotate any exposed credentials immediately. AI-generated narrative is unavailable — configure an LLM provider for richer summaries.",
		len(findings), counts[scanner.SeverityCritical], counts[scanner.SeverityHigh])
}
