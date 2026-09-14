package sbom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/scanner"
)

func TestDetectFromHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.24.0")
	headers.Set("X-Powered-By", "Express")

	seen := make(map[string]bool)
	components := detectFromHeaders(headers, seen)

	if len(components) < 2 {
		t.Fatalf("expected at least 2 components from headers, got %d", len(components))
	}

	foundNginx := false
	foundExpress := false
	for _, c := range components {
		if c.Name == "nginx" {
			foundNginx = true
			if c.Version != "1.24.0" {
				t.Errorf("expected nginx version 1.24.0, got %s", c.Version)
			}
		}
		if c.Name == "Express" {
			foundExpress = true
		}
	}

	if !foundNginx {
		t.Error("expected to find nginx component")
	}
	if !foundExpress {
		t.Error("expected to find Express component")
	}
}

func TestDetectFromHTML(t *testing.T) {
	html := `
	<html>
	<head>
		<script src="https://cdn.example.com/react.18.2.0.min.js"></script>
		<link href="https://cdn.example.com/bootstrap.5.3.0.min.css" rel="stylesheet">
		<meta name="generator" content="WordPress 6.4.2">
	</head>
	<body></body>
	</html>`

	seen := make(map[string]bool)
	components := detectFromHTML(html, seen)

	foundReact := false
	foundBootstrap := false
	foundWP := false
	for _, c := range components {
		if c.Name == "react" {
			foundReact = true
		}
		if c.Name == "bootstrap" {
			foundBootstrap = true
		}
		if c.Name == "WordPress" {
			foundWP = true
		}
	}

	if !foundReact {
		t.Error("expected to find react component from script tag")
	}
	if !foundBootstrap {
		t.Error("expected to find bootstrap component from link tag")
	}
	if !foundWP {
		t.Error("expected to find WordPress component from meta generator")
	}
}

func TestGenerateCycloneDX(t *testing.T) {
	bom := &SBOM{
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:test-123",
		Metadata: Metadata{
			Timestamp: "2024-01-01T00:00:00Z",
			Tools:     []Tool{{Name: "TemrenSec", Version: "1.0.0"}},
			Authors:   []Author{{Name: "TemrenSec Scanner"}},
			Component: Component{
				Name:    "example.com",
				Version: "unknown",
				Type:    "application",
				PURL:    "pkg:application/example.com",
			},
		},
		Components: []Component{
			{Name: "react", Version: "18.2.0", Type: "library", PURL: "pkg:npm/react@18.2.0"},
			{Name: "nginx", Version: "1.24.0", Type: "framework", PURL: "pkg:framework/nginx@1.24.0"},
		},
	}

	gen := &Generator{}
	xml, err := gen.GenerateCycloneDX(bom)
	if err != nil {
		t.Fatalf("GenerateCycloneDX returned error: %v", err)
	}

	if !strings.Contains(xml, `xmlns="http://cyclonedx.org/schema/bom/1.6"`) {
		t.Error("CycloneDX XML missing required namespace")
	}
	if !strings.Contains(xml, "react") {
		t.Error("CycloneDX XML missing react component")
	}
	if !strings.Contains(xml, "nginx") {
		t.Error("CycloneDX XML missing nginx component")
	}
	if !strings.Contains(xml, "TemrenSec") {
		t.Error("CycloneDX XML missing tool name")
	}
	if !strings.Contains(xml, `serialNumber="urn:uuid:test-123"`) {
		t.Error("CycloneDX XML missing serial number")
	}
	if !strings.Contains(xml, `<?xml`) {
		t.Error("CycloneDX XML missing XML declaration")
	}
}

func TestCorrelateWithFindings(t *testing.T) {
	bom := &SBOM{
		Components: []Component{
			{Name: "nginx", Version: "1.24.0", Type: "framework", PURL: "pkg:framework/nginx@1.24.0"},
			{Name: "react", Version: "18.2.0", Type: "library", PURL: "pkg:npm/react@18.2.0"},
		},
	}

	findings := []scanner.Finding{
		{
			Title:       "Vulnerable nginx version detected",
			Scanner:     "Vulnerable Components Scanner",
			Severity:    scanner.SeverityHigh,
			Description: "nginx 1.24.0 has known vulnerabilities",
		},
		{
			Title:       "React XSS vulnerability",
			Scanner:     "XSS Scanner",
			Severity:    scanner.SeverityCritical,
			Description: "React 18.2.0 is vulnerable to XSS",
		},
	}

	matches := CorrelateWithFindings(bom, findings)

	if len(matches) == 0 {
		t.Fatal("expected at least one vulnerability match")
	}

	foundNginxMatch := false
	for _, m := range matches {
		if m.Component.Name == "nginx" {
			foundNginxMatch = true
			if len(m.Findings) == 0 {
				t.Error("nginx match should have findings")
			}
		}
	}
	if !foundNginxMatch {
		t.Error("expected nginx vulnerability match")
	}
}

func TestGenerateWithHTTPServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx/1.24.0")
			w.Header().Set("X-Powered-By", "Express")
			w.Write([]byte(`<html><script src="/react.18.2.0.min.js"></script></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cfg := httpengine.DefaultConfig()
	client := httpengine.NewClient(cfg)

	gen := NewGenerator(ts.URL, client)
	bom, err := gen.Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if bom.SpecVersion != "1.6" {
		t.Errorf("expected spec version 1.6, got %s", bom.SpecVersion)
	}

	if len(bom.Components) == 0 {
		t.Error("expected at least one detected component")
	}

	xml, err := gen.GenerateCycloneDX(bom)
	if err != nil {
		t.Fatalf("GenerateCycloneDX returned error: %v", err)
	}
	if !strings.Contains(xml, "nginx") {
		t.Error("CycloneDX XML should contain nginx")
	}
}

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		pkgType string
		name    string
		version string
		want    string
	}{
		{"npm", "react", "18.2.0", "pkg:npm/react@18.2.0"},
		{"npm", "lodash", "", "pkg:npm/lodash"},
		{"composer", "laravel/framework", "10.0", "pkg:composer/laravel/framework@10.0"},
	}

	for _, tt := range tests {
		got := buildPURL(tt.pkgType, tt.name, tt.version)
		if got != tt.want {
			t.Errorf("buildPURL(%q, %q, %q) = %q, want %q", tt.pkgType, tt.name, tt.version, got, tt.want)
		}
	}
}

func TestParseServerHeader(t *testing.T) {
	name, version := parseServerHeader("nginx/1.24.0")
	if name != "nginx" || version != "1.24.0" {
		t.Errorf("parseServerHeader(nginx/1.24.0) = (%q, %q), want (nginx, 1.24.0)", name, version)
	}

	name, version = parseServerHeader("Apache")
	if name != "Apache" || version != "" {
		t.Errorf("parseServerHeader(Apache) = (%q, %q), want (Apache, '')", name, version)
	}
}

func TestExtractHost(t *testing.T) {
	got := extractHost("https://example.com/path")
	if got != "example.com" {
		t.Errorf("extractHost = %q, want example.com", got)
	}

	got = extractHost("http://test.org:8080")
	if got != "test.org:8080" {
		t.Errorf("extractHost = %q, want test.org:8080", got)
	}
}