package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/temren/pkg/scanner"
)

// sarifLog represents the top-level SARIF v2.1.0 structure.
type sarifLog struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	HelpURI string `json:"helpUri"`
}

type sarifResult struct {
	RuleID       string              `json:"ruleId"`
	RuleIndex    int                 `json:"ruleIndex"`
	Level        string              `json:"level"`
	Message      sarifMessage        `json:"message"`
	Locations    []sarifLocation     `json:"locations"`
	Fingerprints map[string]string  `json:"fingerprints,omitempty"`
	Properties   *sarifProperties    `json:"properties,omitempty"`
}

type sarifProperties struct {
	Confidence string `json:"confidence"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// severityToSARIFLevel maps Temren severity to SARIF level.
func severityToSARIFLevel(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium, scanner.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

// scannerToRuleID converts a scanner name to a stable rule identifier.
func scannerToRuleID(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	return "temren/" + s
}

// GenerateSARIF produces a SARIF v2.1.0 JSON string from the report findings.
func (r *Report) GenerateSARIF() string {
	ruleMap := make(map[string]int)
	var rules []sarifRule
	var results []sarifResult

	for _, f := range r.Findings {
		ruleID := scannerToRuleID(f.Scanner)

		if _, exists := ruleMap[ruleID]; !exists {
			rule := sarifRule{
				ID:   ruleID,
				Name: f.Scanner,
			}
			rule.ShortDescription.Text = f.Title
			rule.FullDescription.Text = f.Description
			rule.HelpURI = "https://owasp.org/Top10/"
			ruleMap[ruleID] = len(rules)
			rules = append(rules, rule)
		}

		msg := f.Title
		if f.Description != "" {
			msg = f.Description
		}
		if f.Evidence != "" {
			msg = msg + " Evidence: " + f.Evidence
		}

		result := sarifResult{
			RuleID:    ruleID,
			RuleIndex: ruleMap[ruleID],
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msg},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.URL,
						},
					},
				},
			},
		}

		if f.Confidence != "" {
			result.Properties = &sarifProperties{
				Confidence: string(f.Confidence),
			}
		}

		if f.Parameter != "" || f.Payload != "" {
			fp := fmt.Sprintf("%s/%s/%s", f.URL, f.Scanner, f.Parameter)
			if f.Parameter == "" {
				fp = fmt.Sprintf("%s/%s/%s", f.URL, f.Scanner, f.Payload)
			}
			result.Fingerprints = map[string]string{
				"primaryLocationLineHash": fp,
			}
		}

		results = append(results, result)
	}

	log := sarifLog{
		Schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "TemrenSec",
						Version:        "1.0.0",
						InformationURI: "https://github.com/nickzsche/TemrenSec",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to generate SARIF: %s"}`, err.Error())
	}
	return string(data)
}

// SaveSARIF writes the SARIF report to a file.
func (r *Report) SaveSARIF(filename string) error {
	sarif := r.GenerateSARIF()
	return writeFile(filename, []byte(sarif))
}