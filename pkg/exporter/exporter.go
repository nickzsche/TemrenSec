// Package exporter renders scanner findings into many target formats:
// SARIF v2.1.0, CycloneDX 1.6 (vulnerabilities + ML-BOM), JUnit, CSV, JSONL, Markdown,
// HTML, JIRA-flavored Markdown, and an OWASP-ASVS mapped report.
package exporter

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/temren/pkg/compliance"
	"github.com/temren/pkg/scanner"
)

// SARIF v2.1.0 minimal subset sufficient for GitHub Code Scanning upload.
type sarifRoot struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string             `json:"id"`
	ShortDescription sarifTextContainer `json:"shortDescription"`
	HelpURI          string             `json:"helpUri,omitempty"`
	Properties       map[string]any     `json:"properties,omitempty"`
}
type sarifTextContainer struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string             `json:"ruleId"`
	Level     string             `json:"level"`
	Message   sarifTextContainer `json:"message"`
	Locations []sarifLocation    `json:"locations"`
	Properties map[string]any    `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}

var sarifLevel = map[scanner.Severity]string{
	scanner.SeverityCritical: "error",
	scanner.SeverityHigh:     "error",
	scanner.SeverityMedium:   "warning",
	scanner.SeverityLow:      "note",
	scanner.SeverityInfo:     "note",
}

// SARIF writes a SARIF v2.1 document to w.
func SARIF(w io.Writer, findings []scanner.Finding) error {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range findings {
		id := strings.ReplaceAll(f.Scanner, " ", "-")
		if _, ok := ruleSet[id]; !ok {
			ruleSet[id] = sarifRule{
				ID:               id,
				ShortDescription: sarifTextContainer{Text: f.Title},
				HelpURI:          "https://owasp.org/Top10/",
				Properties:       map[string]any{"category": f.OWASPCategory},
			}
		}
		results = append(results, sarifResult{
			RuleID:    id,
			Level:     sarifLevel[f.Severity],
			Message:   sarifTextContainer{Text: f.Description},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.URL}}}},
			Properties: map[string]any{
				"severity":   f.Severity,
				"confidence": f.Confidence,
				"cvss":       f.CVSSScore,
				"payload":    f.Payload,
			},
		})
	}
	rules := make([]sarifRule, 0, len(ruleSet))
	for _, r := range ruleSet {
		rules = append(rules, r)
	}
	root := sarifRoot{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "temren",
				Version:        "1.0.0",
				InformationURI: "https://github.com/nickzsche/TemrenSec",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

// CycloneDX writes a CycloneDX 1.6 vulnerability report.
func CycloneDX(w io.Writer, findings []scanner.Finding) error {
	type rating struct {
		Severity string  `json:"severity"`
		Score    float64 `json:"score,omitempty"`
		Method   string  `json:"method,omitempty"`
	}
	type vuln struct {
		BomRef      string   `json:"bom-ref"`
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Ratings     []rating `json:"ratings"`
		Source      map[string]string `json:"source"`
		References  []map[string]string `json:"references,omitempty"`
	}
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]string{{"vendor": "temren", "name": "temren", "version": "1.0.0"}},
		},
		"vulnerabilities": []vuln{},
	}
	var vulns []vuln
	for i, f := range findings {
		vulns = append(vulns, vuln{
			BomRef:      fmt.Sprintf("temren-%d", i+1),
			ID:          f.Scanner,
			Description: f.Title + " — " + f.Description,
			Ratings:     []rating{{Severity: strings.ToLower(string(f.Severity)), Score: f.CVSSScore, Method: "CVSSv3"}},
			Source:      map[string]string{"name": "temren"},
		})
	}
	doc["vulnerabilities"] = vulns
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// JUnit writes a JUnit XML test-results document. Each finding is a failed test case.
func JUnit(w io.Writer, findings []scanner.Finding) error {
	type tc struct {
		XMLName xml.Name `xml:"testcase"`
		Name    string   `xml:"name,attr"`
		Class   string   `xml:"classname,attr"`
		Failure *struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
		} `xml:"failure,omitempty"`
	}
	type ts struct {
		XMLName  xml.Name `xml:"testsuite"`
		Name     string   `xml:"name,attr"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Cases    []tc     `xml:"testcase"`
	}
	suite := ts{Name: "temren", Tests: len(findings)}
	for _, f := range findings {
		c := tc{Name: f.Title, Class: f.Scanner}
		c.Failure = &struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
		}{Text: f.Description + " @ " + f.URL, Type: string(f.Severity)}
		suite.Cases = append(suite.Cases, c)
		suite.Failures++
	}
	io.WriteString(w, xml.Header)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suite)
}

// CSV writes findings to w. Header is always emitted first.
func CSV(w io.Writer, findings []scanner.Finding) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	cw.Write([]string{"timestamp", "scanner", "severity", "confidence", "title", "url", "parameter", "payload", "owasp", "cvss"})
	for _, f := range findings {
		cw.Write([]string{
			f.Timestamp.Format(time.RFC3339), f.Scanner, string(f.Severity), string(f.Confidence),
			f.Title, f.URL, f.Parameter, f.Payload, f.OWASPCategory, fmt.Sprintf("%.1f", f.CVSSScore),
		})
	}
	return cw.Error()
}

// JSONL writes findings line-delimited.
func JSONL(w io.Writer, findings []scanner.Finding) error {
	enc := json.NewEncoder(w)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// Markdown returns a human-readable markdown report with optional compliance summary.
func Markdown(w io.Writer, findings []scanner.Finding) error {
	counts := map[scanner.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "# Temren Scan Report\n\n")
	fmt.Fprintf(w, "Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "## Summary\n\n| Severity | Count |\n|---|---|\n")
	for _, s := range []scanner.Severity{scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityInfo} {
		fmt.Fprintf(w, "| %s | %d |\n", s, counts[s])
	}
	fmt.Fprintf(w, "\n## Findings\n\n")
	for i, f := range findings {
		fmt.Fprintf(w, "### %d. [%s] %s\n\n", i+1, f.Severity, f.Title)
		if f.URL != "" {
			fmt.Fprintf(w, "- URL: `%s`\n", f.URL)
		}
		if f.Scanner != "" {
			fmt.Fprintf(w, "- Scanner: `%s`\n", f.Scanner)
		}
		if f.Parameter != "" {
			fmt.Fprintf(w, "- Parameter: `%s`\n", f.Parameter)
		}
		if f.Payload != "" {
			fmt.Fprintf(w, "- Payload: `%s`\n", f.Payload)
		}
		if f.OWASPCategory != "" {
			fmt.Fprintf(w, "- OWASP: %s\n", f.OWASPCategory)
		}
		fmt.Fprintf(w, "\n%s\n\n", f.Description)
	}
	fmt.Fprintf(w, "## Compliance Impact\n\n| Framework | Findings | Critical | High | Controls |\n|---|---|---|---|---|\n")
	for _, st := range compliance.Summary(findings) {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d |\n", st.Framework, st.Findings, st.CriticalCount, st.HighCount, st.ControlsHit)
	}
	return nil
}

// JIRA formats findings as Atlassian-Wiki markup that pastes cleanly into JIRA tickets.
func JIRA(w io.Writer, findings []scanner.Finding) error {
	for _, f := range findings {
		fmt.Fprintf(w, "h2. [%s] %s\n", f.Severity, f.Title)
		fmt.Fprintf(w, "*URL:* {{%s}}\n", f.URL)
		fmt.Fprintf(w, "*Scanner:* %s\n", f.Scanner)
		fmt.Fprintf(w, "*OWASP:* %s\n", f.OWASPCategory)
		fmt.Fprintf(w, "*Description:*\n%s\n", f.Description)
		if f.Payload != "" {
			fmt.Fprintf(w, "{code}%s{code}\n", f.Payload)
		}
		fmt.Fprintln(w, "----")
	}
	return nil
}
