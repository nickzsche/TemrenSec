package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MLModelComponent describes a single AI / ML model dependency in CycloneDX 1.6
// ML-BOM form. CycloneDX 1.6 added the "machine-learning-model" component type
// plus a "modelCard" stanza; this struct is the subset Temren produces (provider,
// model id, deployment surface, intended use). It is intentionally hand-rolled
// JSON rather than tied to a full CycloneDX schema library to keep deps minimal.
type MLModelComponent struct {
	BomRef     string            `json:"bom-ref"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Provider   string            `json:"-"`
	Purpose    string            `json:"-"`
	Properties []ModelProperty   `json:"properties,omitempty"`
	ModelCard  *ModelCard        `json:"modelCard,omitempty"`
}

type ModelProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ModelCard struct {
	BomRef            string            `json:"bom-ref"`
	ModelParameters   *ModelParameters  `json:"modelParameters,omitempty"`
	QuantitativeAnaly map[string]any    `json:"quantitativeAnalysis,omitempty"`
	Considerations    *Considerations   `json:"considerations,omitempty"`
}

type ModelParameters struct {
	Approach           map[string]string `json:"approach,omitempty"`
	Task               string            `json:"task,omitempty"`
	ArchitectureFamily string            `json:"architectureFamily,omitempty"`
	ModelArchitecture  string            `json:"modelArchitecture,omitempty"`
}

type Considerations struct {
	IntendedUse      []string `json:"users,omitempty"`
	UseCases         []string `json:"useCases,omitempty"`
	TechnicalLimits  []string `json:"technicalLimitations,omitempty"`
	EthicalConsider  []string `json:"ethicalConsiderations,omitempty"`
}

// MLBOMDoc is the top-level CycloneDX 1.6 document with ML-BOM components.
type MLBOMDoc struct {
	BomFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	Metadata     map[string]any     `json:"metadata"`
	Components   []MLModelComponent `json:"components"`
}

// WriteMLBOM serializes a CycloneDX 1.6 ML-BOM that catalogues every AI model
// Temren itself called during a scan. The provider/model pairs come from
// pkg/ai (Anthropic / OpenAI / Ollama) and are passed in by the caller because
// pkg/sbom must not import pkg/ai (would create a cycle).
func WriteMLBOM(w io.Writer, models []MLModelComponent) error {
	for i := range models {
		if models[i].BomRef == "" {
			models[i].BomRef = fmt.Sprintf("ml-model-%d", i+1)
		}
		if models[i].Type == "" {
			models[i].Type = "machine-learning-model"
		}
		if models[i].Provider != "" {
			models[i].Properties = append(models[i].Properties, ModelProperty{
				Name:  "temren:provider",
				Value: models[i].Provider,
			})
		}
		if models[i].Purpose != "" {
			models[i].Properties = append(models[i].Properties, ModelProperty{
				Name:  "temren:purpose",
				Value: models[i].Purpose,
			})
		}
	}

	doc := MLBOMDoc{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]string{
				{"vendor": "temren", "name": "temren", "version": "1.0.0"},
			},
		},
		Components: models,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// AIModelFromProvider builds an MLModelComponent from a (providerName, modelID)
// pair. Caller passes these in from pkg/ai so this package stays leaf-level.
func AIModelFromProvider(providerName, modelID, purpose string) MLModelComponent {
	return MLModelComponent{
		Type:     "machine-learning-model",
		Name:     modelID,
		Provider: providerName,
		Purpose:  purpose,
		ModelCard: &ModelCard{
			BomRef: "model-card-" + strings.ReplaceAll(modelID, ":", "-"),
			ModelParameters: &ModelParameters{
				Task:               "text-generation",
				ArchitectureFamily: "transformer",
			},
			Considerations: &Considerations{
				IntendedUse: []string{"security-analyst"},
				UseCases:    []string{"vulnerability triage", "exploit reasoning", "remediation drafting"},
				TechnicalLimits: []string{
					"non-deterministic output (temperature > 0 in non-triage paths)",
					"context window varies by provider",
					"may hallucinate CVE IDs — always cross-reference with NVD",
				},
				EthicalConsider: []string{
					"findings sent to provider as scan evidence — review your AI provider's data retention policy before enabling on production scans",
				},
			},
		},
	}
}
