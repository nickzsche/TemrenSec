package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// StorybookExposureScanner finds Storybook / Swagger UI / Mock Service Worker installs left exposed.
type StorybookExposureScanner struct{}

func NewStorybookExposureScanner() *StorybookExposureScanner { return &StorybookExposureScanner{} }

func (s *StorybookExposureScanner) Name() string { return "Dev-tool Exposure (Storybook / MSW)" }

var devToolPaths = []struct {
	path     string
	contains string
	title    string
	sev      Severity
}{
	{"/storybook/", "Storybook", "Storybook exposed", SeverityMedium},
	{"/storybook/iframe.html", "Storybook", "Storybook iframe exposed", SeverityMedium},
	{"/_next/static/chunks/", "webpackChunk", "Next.js static chunks listable", SeverityLow},
	{"/mockServiceWorker.js", "MSW", "Mock Service Worker shipped to prod", SeverityMedium},
	{"/__cypress/", "cypress", "Cypress test runner exposed", SeverityHigh},
	{"/__webpack_hmr", "webpack", "Webpack HMR endpoint exposed", SeverityLow},
	{"/__inspect", "DevTools", "Node inspector reachable", SeverityHigh},
}

func (s *StorybookExposureScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	target = strings.TrimRight(target, "/")
	var findings []Finding
	for _, d := range devToolPaths {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+d.path, nil)
		resp, err := client.Do(ctx, req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		if resp.StatusCode == 200 && strings.Contains(strings.ToLower(string(body)), strings.ToLower(d.contains)) {
			findings = append(findings, Finding{
				URL: target + d.path, Title: d.title,
				Description: "Development tooling reachable in production. Components may leak internal API names, fixtures, or credentials.",
				Severity: d.sev, Confidence: ConfidenceHigh, Scanner: s.Name(),
				Timestamp: time.Now(), OWASPCategory: "A05:2021-Security Misconfiguration",
			})
		}
	}
	return findings, nil
}
