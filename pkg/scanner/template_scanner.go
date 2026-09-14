package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/templates"
)

// TemplateScanner runs the Nuclei-style YAML template engine as a first-class
// scanner. It ships with a bundled template set and also loads user templates
// from ~/.temren/templates, so detections can be added without recompiling.
type TemplateScanner struct {
	engine *templates.Engine
}

func NewTemplateScanner() *TemplateScanner {
	dir := ""
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir = filepath.Join(home, ".temren", "templates")
	}
	return &TemplateScanner{engine: templates.New(dir)}
}

func (s *TemplateScanner) Name() string { return "Template Engine (YAML)" }

// TemplateCount exposes how many templates are loaded (bundled + user).
func (s *TemplateScanner) TemplateCount() int { return s.engine.Count() }

func (s *TemplateScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	matches := s.engine.Run(ctx, target, client)
	out := make([]Finding, 0, len(matches))
	for _, m := range matches {
		desc := m.Description
		if len(m.References) > 0 {
			desc += "\n\nKaynaklar:\n- " + strings.Join(m.References, "\n- ")
		}
		out = append(out, Finding{
			URL:           m.URL,
			Title:         m.Name,
			Description:   desc,
			Severity:      severityFromString(m.Severity),
			Confidence:    ConfidenceHigh,
			Scanner:       s.Name(),
			Evidence:      m.Evidence,
			OWASPCategory: owaspOr(m.OWASP, "A05:2021"),
		})
	}
	return out, nil
}

func severityFromString(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func owaspOr(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}
