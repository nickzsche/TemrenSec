package scanner

import (
	"context"
	"github.com/temren/pkg/httpengine"
	"strings"
	"time"
)

// SoftwareSupplyChainScanner detects software supply chain vulnerabilities (OWASP 2025 A03)
type SoftwareSupplyChainScanner struct{}

func NewSoftwareSupplyChainScanner() *SoftwareSupplyChainScanner {
	return &SoftwareSupplyChainScanner{}
}

func (s *SoftwareSupplyChainScanner) Name() string {
	return "Software Supply Chain Failures"
}

func (s *SoftwareSupplyChainScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	// Build artifacts (minified JS, CSS, fonts, ...) routinely contain
	// substrings like ".env" or "package.json" inside chunk maps and
	// path tables. Substring-matching those produces 100% false positives.
	if IsStaticAssetURL(target) {
		return nil, nil
	}

	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}

	body, _ := readBody(resp)
	resp.Body.Close()

	bodyStr := string(body)

	supplyChainPatterns := []struct {
		pattern  string
		name     string
		severity Severity
	}{
		{"package.json", "npm package.json exposed", SeverityMedium},
		{"package-lock.json", "npm lock file exposed", SeverityMedium},
		{"yarn.lock", "Yarn lock file exposed", SeverityMedium},
		{"requirements.txt", "Python requirements exposed", SeverityMedium},
		{"Pipfile", "Python Pipfile exposed", SeverityMedium},
		{"poetry.lock", "Python Poetry lock exposed", SeverityMedium},
		{"composer.json", "PHP Composer dependencies exposed", SeverityMedium},
		{"Gemfile", "Ruby Gemfile exposed", SeverityMedium},
		{"Gemfile.lock", "Ruby lock file exposed", SeverityMedium},
		{"Cargo.toml", "Rust Cargo.toml exposed", SeverityMedium},
		{"go.mod", "Go module exposed", SeverityMedium},
		{"pom.xml", "Maven POM exposed", SeverityMedium},
		{"build.gradle", "Gradle build exposed", SeverityMedium},
		{"webpack.config.js", "Webpack config exposed", SeverityLow},
		{".env", "Environment file exposed", SeverityCritical},
		{".env.local", "Local env file exposed", SeverityCritical},
		{".git/config", "Git config exposed", SeverityMedium},
		{".git/HEAD", "Git repository exposed", SeverityHigh},
		{".svn", "SVN exposed", SeverityMedium},
		{"Dockerfile", "Dockerfile exposed", SeverityMedium},
		{"docker-compose.yml", "Docker Compose exposed", SeverityMedium},
		{".dockerignore", "Docker ignore exposed", SeverityLow},
		{"Jenkinsfile", "Jenkins pipeline exposed", SeverityMedium},
		{".github/workflows", "GitHub Actions exposed", SeverityMedium},
		{"swagger.json", "Swagger API exposed", SeverityMedium},
		{"openapi.json", "OpenAPI spec exposed", SeverityMedium},
		{"tsconfig.json", "TypeScript config exposed", SeverityLow},
		{".npmrc", "npm config exposed", SeverityMedium},
		{"yarnrc", "Yarn config exposed", SeverityMedium},
	}

	for _, p := range supplyChainPatterns {
		if !strings.Contains(bodyStr, p.pattern) {
			continue
		}
		// Critical-severity patterns (.env, .env.local) demand more than
		// "the filename appears in the body" — that hits docs/blog posts
		// and SPA HTML. Require the response to actually look like the
		// claimed file before firing critical.
		if p.severity == SeverityCritical && !looksLikeSupplyChainFile(p.pattern, bodyStr) {
			continue
		}
		findings = append(findings, Finding{
			URL:         target,
			Title:       "Software Supply Chain: " + p.name,
			Description: "Sensitive file exposed that may reveal dependency or configuration information",
			Severity:    p.severity,
			Confidence:  ConfidenceMedium,
			Payload:     p.pattern,
			Evidence:    "Sensitive file pattern detected: " + p.pattern,
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

// looksLikeSupplyChainFile checks the body shape against the claimed file
// type. Reuses envLineRe from exposed_endpoints.go.
func looksLikeSupplyChainFile(pattern, body string) bool {
	switch pattern {
	case ".env", ".env.local":
		return envLineRe.MatchString(body)
	}
	return true
}

