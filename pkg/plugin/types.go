// Package plugin provides a Lua-based plugin system for custom scanners
package plugin

import (
	"context"
	"time"

	"github.com/temren/pkg/scanner"
)

// Finding represents a vulnerability finding from a plugin
type Finding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Payload     string `json:"payload,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// PluginInfo holds metadata about a loaded plugin
type PluginInfo struct {
	Name string
	Path string
}

// ToScannerFinding converts a plugin Finding to a scanner.Finding
func (f *Finding) ToScannerFinding(pluginName string) scanner.Finding {
	severity := scanner.SeverityMedium
	switch f.Severity {
	case "CRITICAL":
		severity = scanner.SeverityCritical
	case "HIGH":
		severity = scanner.SeverityHigh
	case "MEDIUM":
		severity = scanner.SeverityMedium
	case "LOW":
		severity = scanner.SeverityLow
	case "INFO":
		severity = scanner.SeverityInfo
	}

	return scanner.Finding{
		Title:       f.Title,
		Severity:    severity,
		Description: f.Description,
		URL:         f.URL,
		Payload:     f.Payload,
		Evidence:    f.Evidence,
		Scanner:     pluginName,
		Timestamp:   time.Now(),
	}
}

// PluginRunner is the interface for executing plugins
type PluginRunner interface {
	// Info returns metadata about the plugin
	Info() PluginInfo
	// Run executes the plugin scan against the given target
	Run(ctx context.Context, target string, responseBody string, responseHeaders map[string]string) ([]Finding, error)
	// Close cleans up plugin resources
	Close()
}
