package exporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/temren/pkg/scanner"
)

func sample() []scanner.Finding {
	return []scanner.Finding{
		{Title: "SQL Injection", Scanner: "sqli", URL: "https://x/api", Severity: scanner.SeverityCritical, Confidence: scanner.ConfidenceHigh, Payload: "'OR'1", OWASPCategory: "A03:2021-Injection", CVSSScore: 9.8, Timestamp: time.Now(), Description: "boom"},
		{Title: "Missing HSTS", Scanner: "headers", URL: "https://x", Severity: scanner.SeverityMedium, Confidence: scanner.ConfidenceHigh, OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 5.3, Timestamp: time.Now(), Description: "no HSTS"},
	}
}

func TestSARIFRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != "2.1.0" {
		t.Errorf("bad version: %v", got["version"])
	}
}

func TestCycloneDXShape(t *testing.T) {
	var buf bytes.Buffer
	if err := CycloneDX(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CycloneDX") || !strings.Contains(buf.String(), "1.6") {
		t.Errorf("missing markers")
	}
}

func TestJUnitContainsFailures(t *testing.T) {
	var buf bytes.Buffer
	if err := JUnit(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<failure") {
		t.Errorf("expected failure tag")
	}
}

func TestCSVHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if !strings.HasPrefix(lines[0], "timestamp,") || len(lines) != 3 {
		t.Errorf("bad csv: %d lines, first=%q", len(lines), lines[0])
	}
}

func TestMarkdownIncludesCompliance(t *testing.T) {
	var buf bytes.Buffer
	if err := Markdown(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Compliance Impact") {
		t.Errorf("missing compliance section")
	}
	if !strings.Contains(out, "SQL Injection") {
		t.Errorf("missing finding")
	}
}

func TestJIRAFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := JIRA(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "h2.") {
		t.Errorf("missing JIRA heading")
	}
}

func TestJSONLOneLinePerFinding(t *testing.T) {
	var buf bytes.Buffer
	JSONL(&buf, sample())
	if c := strings.Count(buf.String(), "\n"); c != 2 {
		t.Errorf("expected 2 lines, got %d", c)
	}
}
