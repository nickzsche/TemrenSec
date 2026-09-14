package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteMLBOM_Shape(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMLBOM(&buf, []MLModelComponent{
		AIModelFromProvider("anthropic", "claude-opus-4-7", "triage"),
		AIModelFromProvider("openai", "gpt-4o-mini", "summarization"),
	})
	if err != nil {
		t.Fatalf("WriteMLBOM: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", doc["specVersion"])
	}

	components, ok := doc["components"].([]any)
	if !ok || len(components) != 2 {
		t.Fatalf("expected 2 components, got %#v", doc["components"])
	}

	output := buf.String()
	if !strings.Contains(output, "machine-learning-model") {
		t.Error("component type machine-learning-model missing")
	}
	if !strings.Contains(output, "claude-opus-4-7") {
		t.Error("model id claude-opus-4-7 missing")
	}
	if !strings.Contains(output, "temren:provider") {
		t.Error("temren:provider property missing")
	}
	if !strings.Contains(output, "modelCard") {
		t.Error("modelCard stanza missing")
	}
}

func TestAIModelFromProvider_DefaultsBomRef(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMLBOM(&buf, []MLModelComponent{AIModelFromProvider("ollama", "llama3", "local-inference")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"bom-ref": "ml-model-1"`) {
		t.Errorf("expected auto bom-ref ml-model-1 in output:\n%s", buf.String())
	}
}
