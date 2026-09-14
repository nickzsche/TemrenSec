package ai

import "os"

// ResolveAnthropicModel returns the Anthropic model name Temren will use
// without instantiating a provider. Resolution order matches
// NewAnthropicProvider: TEMREN_ANTHROPIC_MODEL env > DefaultAnthropicModel.
//
// Useful for the MLBOM endpoint, which lists *configured* providers even
// when none is actively wired into aiEngine yet.
func ResolveAnthropicModel() string {
	if model := os.Getenv("TEMREN_ANTHROPIC_MODEL"); model != "" {
		return model
	}
	return DefaultAnthropicModel
}

// ResolveOpenAIModel — same idea, OpenAI side.
func ResolveOpenAIModel() string {
	if model := os.Getenv("TEMREN_OPENAI_MODEL"); model != "" {
		return model
	}
	return DefaultOpenAIModel
}

// ResolveOllamaModel — same idea, Ollama side.
func ResolveOllamaModel() string {
	if model := os.Getenv("TEMREN_OLLAMA_MODEL"); model != "" {
		return model
	}
	return DefaultOllamaModel
}
