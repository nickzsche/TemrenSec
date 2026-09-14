package scanner

import (
	"testing"
)

func TestLLMScanner_Name(t *testing.T) {
	s := NewLLMScanner()
	if s.Name() != "LLM/API Security Scanner" {
		t.Errorf("LLMScanner.Name() = %q, want %q", s.Name(), "LLM/API Security Scanner")
	}
}

func TestLLMTests_PromptInjectionDetection(t *testing.T) {
	body := `I am an AI assistant. You are a helpful chatbot. My instructions are to help users.`
	test := llmTests[0] // Prompt Injection - System Prompt Leak

	if !test.CheckFunc(body, nil, 200) {
		t.Error("Prompt injection check should detect system prompt leak patterns")
	}

	normalBody := `The weather today is sunny with a high of 75 degrees.`
	if test.CheckFunc(normalBody, nil, 200) {
		t.Error("Prompt injection check should not trigger on normal responses")
	}
}

func TestLLMTests_MCPToolExposure(t *testing.T) {
	body := `{"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}], "mcp": true}`
	test := llmTests[2] // MCP Tool Exposure

	if !test.CheckFunc(body, nil, 200) {
		t.Error("MCP tool exposure check should detect tool definitions")
	}
}

func TestLLMTests_APIKeyDetection(t *testing.T) {
	headers := map[string][]string{
		"Authorization": {"sk-1234567890abcdef"},
	}
	test := llmTests[4] // API Key in LLM Request

	if !test.CheckFunc("", headers, 200) {
		t.Error("API key detection should find sk- prefixed keys")
	}

	safeHeaders := map[string][]string{
		"Authorization": {"Bearer validtoken"},
	}
	if test.CheckFunc("", safeHeaders, 200) {
		t.Error("API key detection should not trigger on Bearer tokens")
	}
}

func TestLLMTests_MissingRateLimit(t *testing.T) {
	noHeaders := map[string][]string{}
	test := llmTests[7] // Missing Rate Limiting

	if !test.CheckFunc("", noHeaders, 200) {
		t.Error("Missing rate limit check should detect absence of rate limit headers")
	}

	rateLimitedHeaders := map[string][]string{
		"X-Ratelimit-Limit": {"100"},
	}
	if test.CheckFunc("", rateLimitedHeaders, 200) {
		t.Error("Missing rate limit check should not trigger when rate limit headers present")
	}
}

func TestLLMTests_SecurityHeaders(t *testing.T) {
	missingHeaders := map[string][]string{
		"Content-Type": {"application/json"},
	}
	test := llmTests[8] // Insecure LLM Response Headers

	if !test.CheckFunc("", missingHeaders, 200) {
		t.Error("Insecure headers check should detect missing security headers on JSON responses")
	}

	secureHeaders := map[string][]string{
		"Content-Type":          {"application/json"},
		"X-Content-Type-Options": {"nosniff"},
		"Content-Security-Policy": {"default-src 'none'"},
	}
	if test.CheckFunc("", secureHeaders, 200) {
		t.Error("Insecure headers check should not trigger when security headers are present")
	}
}

func TestLLMTests_TrainingDataExtraction(t *testing.T) {
	copyrightBody := `© 2024 OpenAI. All rights reserved. This content is from the training data.`
	test := llmTests[9] // LLM Training Data Extraction

	if !test.CheckFunc(copyrightBody, nil, 200) {
		t.Error("Training data extraction check should detect copyright notices")
	}

	normalBody := `The answer to your question is 42.`
	if test.CheckFunc(normalBody, nil, 200) {
		t.Error("Training data extraction check should not trigger on normal responses")
	}
}

func TestGetHeaderValue(t *testing.T) {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"X-Ratelimit-Limit": {"100"},
	}

	val := getHeaderValue(headers, "content-type")
	if val != "application/json" {
		t.Errorf("getHeaderValue case-insensitive: got %q, want %q", val, "application/json")
	}

	val = getHeaderValue(headers, "X-RATELIMIT-LIMIT")
	if val != "100" {
		t.Errorf("getHeaderValue case-insensitive: got %q, want %q", val, "100")
	}

	val = getHeaderValue(headers, "nonexistent")
	if val != "" {
		t.Errorf("getHeaderValue nonexistent: got %q, want empty string", val)
	}
}

func TestLLMScanner_OriginatesFromCorrectPackage(t *testing.T) {
	s := NewLLMScanner()
	if s == nil {
		t.Error("NewLLMScanner() should not return nil")
	}
}

func TestLLMTests_AllHaveRequiredFields(t *testing.T) {
	for i, test := range llmTests {
		if test.Name == "" {
			t.Errorf("llmTests[%d]: Name is required", i)
		}
		if test.Description == "" {
			t.Errorf("llmTests[%d]: Description is required", i)
		}
		if test.Severity == "" {
			t.Errorf("llmTests[%d]: Severity is required", i)
		}
		if test.Confidence == "" {
			t.Errorf("llmTests[%d]: Confidence is required", i)
		}
		if test.OWASPCat == "" {
			t.Errorf("llmTests[%d]: OWASPCat is required", i)
		}
		if test.CVSSScore <= 0 {
			t.Errorf("llmTests[%d]: CVSSScore must be > 0", i)
		}
		if test.CheckFunc == nil {
			t.Errorf("llmTests[%d]: CheckFunc is required", i)
		}
	}
}