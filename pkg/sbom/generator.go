package sbom

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
	"github.com/temren/pkg/scanner"
	"github.com/google/uuid"
)

type Component struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Type    string            `json:"type"`
	PURL    string            `json:"purl"`
	License string            `json:"license"`
	Hashes  map[string]string `json:"hashes,omitempty"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Author struct {
	Name string `json:"name"`
}

type Metadata struct {
	Timestamp string   `json:"timestamp"`
	Tools     []Tool   `json:"tools"`
	Authors   []Author `json:"authors"`
	Component Component `json:"component"`
}

type SBOM struct {
	SpecVersion  string       `json:"specVersion"`
	Version      int          `json:"version"`
	SerialNumber string       `json:"serialNumber"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

type VulnerabilityMatch struct {
	Component   Component         `json:"component"`
	Findings     []scanner.Finding `json:"findings"`
	Severity     scanner.Severity  `json:"severity"`
	Description string            `json:"description"`
}

type Generator struct {
	targetURL string
	client    *httpengine.Client
}

func NewGenerator(targetURL string, client *httpengine.Client) *Generator {
	return &Generator{
		targetURL: targetURL,
		client:    client,
	}
}

func (g *Generator) Generate(ctx context.Context) (*SBOM, error) {
	components, err := g.DetectComponents(ctx)
	if err != nil {
		return nil, fmt.Errorf("detect components: %w", err)
	}

	bom := &SBOM{
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{Name: "TemrenSec", Version: "1.0.0"},
			},
			Authors: []Author{
				{Name: "TemrenSec Scanner"},
			},
			Component: Component{
				Name:    extractHost(g.targetURL),
				Version: "unknown",
				Type:    "application",
				PURL:    "pkg:application/" + extractHost(g.targetURL),
			},
		},
		Components:   components,
		Dependencies: []Dependency{},
	}

	return bom, nil
}

func (g *Generator) DetectComponents(ctx context.Context) ([]Component, error) {
	var components []Component
	seen := make(map[string]bool)

	resp, err := g.client.Get(ctx, g.targetURL)
	if err != nil {
		return nil, fmt.Errorf("fetch target: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	bodyStr := string(body)

	components = append(components, detectFromHeaders(resp.Header, seen)...)
	components = append(components, detectFromHTML(bodyStr, seen)...)

	probePaths := []string{"/package.json", "/composer.json", "/Gemfile.lock", "/requirements.txt"}
	for _, path := range probePaths {
		probeURL := strings.TrimRight(g.targetURL, "/") + path
		probeResp, err := g.client.Get(ctx, probeURL)
		if err != nil || probeResp.StatusCode != http.StatusOK {
			if probeResp != nil {
				probeResp.Body.Close()
			}
			continue
		}
		probeBody, err := io.ReadAll(probeResp.Body)
		probeResp.Body.Close()
		if err != nil {
			continue
		}
		components = append(components, detectFromProbe(path, string(probeBody), seen)...)
	}

	return components, nil
}

func detectFromHeaders(headers http.Header, seen map[string]bool) []Component {
	var components []Component

	server := headers.Get("Server")
	if server != "" && !seen["server:"+server] {
		name, version := parseServerHeader(server)
		seen["server:"+server] = true
		components = append(components, Component{
			Name:    name,
			Version: version,
			Type:    "framework",
			PURL:    buildPURL("framework", name, version),
		})
	}

	xPoweredBy := headers.Get("X-Powered-By")
	if xPoweredBy != "" && !seen["x-powered-by:"+xPoweredBy] {
		name, version := parseServerHeader(xPoweredBy)
		seen["x-powered-by:"+xPoweredBy] = true
		components = append(components, Component{
			Name:    name,
			Version: version,
			Type:    "framework",
			PURL:    buildPURL("framework", name, version),
		})
	}

	return components
}

func detectFromHTML(body string, seen map[string]bool) []Component {
	var components []Component

	scriptSrcRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptSrcRe.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		src := m[1]
		name, version := extractLibFromURL(src)
		if name == "" || seen["js:"+name] {
			continue
		}
		seen["js:"+name] = true
		components = append(components, Component{
			Name:    name,
			Version: version,
			Type:    "library",
			PURL:    buildPURL("npm", name, version),
		})
	}

	linkHrefRe := regexp.MustCompile(`<link[^>]+href=["']([^"']*\.css[^"']*)["']`)
	cssMatches := linkHrefRe.FindAllStringSubmatch(body, -1)
	for _, m := range cssMatches {
		if len(m) < 2 {
			continue
		}
		href := m[1]
		name, version := extractCSSLibFromURL(href)
		if name == "" || seen["css:"+name] {
			continue
		}
		seen["css:"+name] = true
		components = append(components, Component{
			Name:    name,
			Version: version,
			Type:    "library",
			PURL:    buildPURL("npm", name, version),
		})
	}

	metaGeneratorRe := regexp.MustCompile(`<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	genMatches := metaGeneratorRe.FindAllStringSubmatch(body, -1)
	for _, m := range genMatches {
		if len(m) < 2 {
			continue
		}
		content := m[1]
		name, version := parseServerHeader(content)
		key := "generator:" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		components = append(components, Component{
			Name:    name,
			Version: version,
			Type:    "framework",
			PURL:    buildPURL("framework", name, version),
		})
	}

	return components
}

func detectFromProbe(path, body string, seen map[string]bool) []Component {
	var components []Component

	switch path {
	case "/package.json":
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := parseJSON(body, &pkg); err != nil {
			return nil
		}
		for name, version := range pkg.Dependencies {
			key := "npm:" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			components = append(components, Component{
				Name:    name,
				Version: version,
				Type:    "library",
				PURL:    buildPURL("npm", name, version),
			})
		}
		for name, version := range pkg.DevDependencies {
			key := "npm:" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			components = append(components, Component{
				Name:    name,
				Version: version,
				Type:    "library",
				PURL:    buildPURL("npm", name, version),
			})
		}

	case "/composer.json":
		var pkg struct {
			Require map[string]string `json:"require"`
		}
		if err := parseJSON(body, &pkg); err != nil {
			return nil
		}
		for name, version := range pkg.Require {
			key := "composer:" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			components = append(components, Component{
				Name:    name,
				Version: version,
				Type:    "library",
				PURL:    buildPURL("composer", name, version),
			})
		}

	case "/requirements.txt":
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "==", 2)
			name := strings.TrimSpace(parts[0])
			version := ""
			if len(parts) > 1 {
				version = strings.TrimSpace(parts[1])
			}
			key := "pypi:" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			components = append(components, Component{
				Name:    name,
				Version: version,
				Type:    "library",
				PURL:    buildPURL("pypi", name, version),
			})
		}

	case "/Gemfile.lock":
		re := regexp.MustCompile(`^\s{4}(\S+)\s+\(([^)]+)\)`)
		for _, line := range strings.Split(body, "\n") {
			m := re.FindStringSubmatch(line)
			if len(m) == 3 {
				name := m[1]
				version := m[2]
				key := "gem:" + name
				if seen[key] {
					continue
				}
				seen[key] = true
				components = append(components, Component{
					Name:    name,
					Version: version,
					Type:    "library",
					PURL:    buildPURL("gem", name, version),
				})
			}
		}
	}

	return components
}

func (g *Generator) GenerateCycloneDX(sbom *SBOM) (string, error) {
	bom := cycloneDXBOM{
		XMLNS:        "http://cyclonedx.org/schema/bom/1.6",
		Version:      sbom.Version,
		SerialNumber: sbom.SerialNumber,
		Metadata: cycloneDXMetadata{
			Timestamp: sbom.Metadata.Timestamp,
			Tools: cycloneDXTools{
				Tool: []cycloneDXTool{
					{Name: "TemrenSec", Version: "1.0.0"},
				},
			},
			Component: cycloneDXComponent{
				Type:    sbom.Metadata.Component.Type,
				Name:    sbom.Metadata.Component.Name,
				Version: sbom.Metadata.Component.Version,
			},
		},
	}

	for _, c := range sbom.Components {
		bom.Components = append(bom.Components, cycloneDXComponent{
			Type:    c.Type,
			Name:    c.Name,
			Version: c.Version,
			PURL:    c.PURL,
			License: c.License,
		})
	}

	output, err := xml.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal cyclonedx: %w", err)
	}

	return xml.Header + "\n" + string(output), nil
}

func CorrelateWithFindings(sbom *SBOM, findings []scanner.Finding) []VulnerabilityMatch {
	var matches []VulnerabilityMatch

	for _, f := range findings {
		for _, c := range sbom.Components {
			if componentMatchesFinding(c, f) {
				var existing *VulnerabilityMatch
				for i := range matches {
					if matches[i].Component.PURL == c.PURL {
						existing = &matches[i]
						break
					}
				}
				if existing != nil {
					existing.Findings = append(existing.Findings, f)
					if severityRank(f.Severity) > severityRank(existing.Severity) {
						existing.Severity = f.Severity
					}
				} else {
					matches = append(matches, VulnerabilityMatch{
						Component:   c,
						Findings:     []scanner.Finding{f},
						Severity:     f.Severity,
						Description: fmt.Sprintf("Vulnerability in %s: %s", c.Name, f.Title),
					})
				}
			}
		}
	}

	return matches
}

func componentMatchesFinding(c Component, f scanner.Finding) bool {
	findingLower := strings.ToLower(f.Title + " " + f.Scanner + " " + f.Description)
	nameLower := strings.ToLower(c.Name)

	if strings.Contains(findingLower, nameLower) {
		return true
	}

	if strings.Contains(strings.ToLower(f.Scanner), "vulnerable component") {
		return true
	}

	if strings.Contains(strings.ToLower(f.Scanner), "technology") {
		return strings.Contains(findingLower, nameLower)
	}

	return false
}

func severityRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 4
	case scanner.SeverityHigh:
		return 3
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityLow:
		return 1
	default:
		return 0
	}
}

func extractHost(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	parts := strings.SplitN(urlStr, "/", 2)
	return parts[0]
}

func parseServerHeader(header string) (name, version string) {
	for _, sep := range []string{"/", " "} {
		parts := strings.SplitN(header, sep, 2)
		if len(parts) == 2 {
			candidate := strings.TrimSpace(parts[1])
			if regexp.MustCompile(`^\d`).MatchString(candidate) {
				name = strings.TrimSpace(parts[0])
				version = candidate
				return
			}
		}
	}
	name = strings.TrimSpace(header)
	return
}

func extractLibFromURL(src string) (name, version string) {
	re := regexp.MustCompile(`([a-zA-Z0-9_-]+)[.-](\d+(?:\.\d+)*)`)
	matches := re.FindStringSubmatch(src)
	if len(matches) >= 3 {
		return matches[1], matches[2]
	}

	knownLibs := map[string][2]string{
		"jquery":        {"jquery", ""},
		"react":         {"react", ""},
		"vue":           {"vue", ""},
		"angular":       {"angular", ""},
		"bootstrap":     {"bootstrap", ""},
		"tailwind":      {"tailwindcss", ""},
		"font-awesome":  {"font-awesome", ""},
		"fontawesome":   {"font-awesome", ""},
	}
	for key, val := range knownLibs {
		if strings.Contains(strings.ToLower(src), key) {
			return val[0], val[1]
		}
	}
	return "", ""
}

func extractCSSLibFromURL(href string) (name, version string) {
	knownCSS := map[string][2]string{
		"bootstrap": {"bootstrap", ""},
		"tailwind": {"tailwindcss", ""},
		"foundation": {"foundation-sites", ""},
		"bulma":     {"bulma", ""},
	}
	for key, val := range knownCSS {
		if strings.Contains(strings.ToLower(href), key) {
			return val[0], val[1]
		}
	}
	return "", ""
}

func buildPURL(pkgType, name, version string) string {
	purl := fmt.Sprintf("pkg:%s/%s", pkgType, name)
	if version != "" {
		purl += "@" + version
	}
	return purl
}

func parseJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

type cycloneDXBOM struct {
	XMLName      xml.Name              `xml:"bom"`
	XMLNS        string                `xml:"xmlns,attr"`
	Version      int                   `xml:"version,attr"`
	SerialNumber string                `xml:"serialNumber,attr"`
	Metadata     cycloneDXMetadata     `xml:"metadata"`
	Components   []cycloneDXComponent  `xml:"components>component"`
}

type cycloneDXMetadata struct {
	Timestamp string             `xml:"timestamp"`
	Tools     cycloneDXTools     `xml:"tools"`
	Component cycloneDXComponent `xml:"component"`
}

type cycloneDXTools struct {
	Tool []cycloneDXTool `xml:"tool"`
}

type cycloneDXTool struct {
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

type cycloneDXComponent struct {
	Type    string `xml:"type,attr"`
	Name    string `xml:"name"`
	Version string `xml:"version,omitempty"`
	PURL    string `xml:"purl,omitempty"`
	License string `xml:"license,omitempty"`
}