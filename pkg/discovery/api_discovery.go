// Package discovery discovers API endpoints from source code and running applications.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/temren/pkg/httpengine"
)

// DiscoveryConfig configures the API discovery process.
type DiscoveryConfig struct {
	// TargetURL is the base URL to scan for remote API documentation.
	TargetURL string
	// SpecURLs are direct URLs to OpenAPI/Swagger specs.
	SpecURLs []string
	// LocalPath is a local directory to parse for API endpoints.
	LocalPath string
	// AutoDiscover enables probing common API documentation paths.
	AutoDiscover bool
	// DiscoverDepth controls how deep to crawl for API discovery (default: 2).
	DiscoverDepth int
}

// APIEndpoint represents a discovered API endpoint.
type APIEndpoint struct {
	Method       string             `json:"method"`
	Path         string             `json:"path"`
	Description  string             `json:"description"`
	Parameters   []APIParameter     `json:"parameters"`
	RequestBody  *RequestBody      `json:"requestBody,omitempty"`
	Responses    map[int]ResponseSpec `json:"responses"`
	Tags         []string           `json:"tags"`
	Security     []string           `json:"security"`
	SeverityHint string             `json:"severity_hint"`
}

// APIParameter represents a parameter for an API endpoint.
type APIParameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// RequestBody describes a request body schema.
type RequestBody struct {
	ContentType string `json:"contentType"`
	Schema      string `json:"schema"`
}

// ResponseSpec describes a response specification.
type ResponseSpec struct {
	Description string `json:"description"`
}

// DiscoveryResult holds the results of API discovery.
type DiscoveryResult struct {
	Endpoints   []APIEndpoint `json:"endpoints"`
	SpecURLs    []string      `json:"spec_urls"`
	OpenAPISpec string        `json:"openapi_spec"`
}

// APIDiscoverer discovers API endpoints from source code and running applications.
type APIDiscoverer struct {
	config *DiscoveryConfig
	client *httpengine.Client
}

// NewAPIDiscoverer creates a new API discoverer.
func NewAPIDiscoverer(config *DiscoveryConfig, client *httpengine.Client) *APIDiscoverer {
	if config.DiscoverDepth == 0 {
		config.DiscoverDepth = 2
	}
	return &APIDiscoverer{
		config: config,
		client: client,
	}
}

// Common API documentation paths to probe.
var apiSpecPaths = []string{
	"/swagger.json", "/swagger.yaml",
	"/openapi.json", "/openapi.yaml",
	"/api-docs", "/api/docs", "/api/swagger",
	"/v1/swagger.json", "/v2/swagger.json",
	"/v1/openapi.json", "/v2/openapi.json",
	"/swagger-ui.html", "/swagger-ui/",
	"/swagger-resources", "/swagger-resources/configuration/ui",
	"/graphql", "/graphiql",
	"/api-gateway", "/gateway",
	"/api", "/api/v1", "/api/v2",
	"/v1", "/v2",
	"/health", "/healthz", "/.well-known",
	"/info", "/version", "/status",
	"/api.raml", "/apiary",
}

// Discover runs the full API discovery pipeline.
func (d *APIDiscoverer) Discover(ctx context.Context) (*DiscoveryResult, error) {
	result := &DiscoveryResult{}
	var allEndpoints []APIEndpoint
	var allSpecURLs []string
	seen := make(map[string]bool)

	// Discover from explicit spec URLs first.
	for _, specURL := range d.config.SpecURLs {
		endpoints, err := d.parseSpecURL(ctx, specURL)
		if err != nil {
			continue
		}
		for _, ep := range endpoints {
			key := ep.Method + " " + ep.Path
			if !seen[key] {
				seen[key] = true
				allEndpoints = append(allEndpoints, ep)
			}
		}
		allSpecURLs = append(allSpecURLs, specURL)
	}

	// Discover from remote URL probing.
	if d.config.TargetURL != "" && d.config.AutoDiscover {
		endpoints, specURLs, err := d.DiscoverFromURL(ctx)
		if err == nil {
			for _, ep := range endpoints {
				key := ep.Method + " " + ep.Path
				if !seen[key] {
					seen[key] = true
					allEndpoints = append(allEndpoints, ep)
				}
			}
			for _, su := range specURLs {
				allSpecURLs = append(allSpecURLs, su)
			}
		}
	}

	// Discover from local source code.
	if d.config.LocalPath != "" {
		endpoints, err := d.DiscoverFromSource(ctx)
		if err == nil {
			for _, ep := range endpoints {
				key := ep.Method + " " + ep.Path
				if !seen[key] {
					seen[key] = true
					allEndpoints = append(allEndpoints, ep)
				}
			}
		}
	}

	result.Endpoints = allEndpoints
	result.SpecURLs = allSpecURLs

	// Generate OpenAPI spec from discovered endpoints.
	if len(allEndpoints) > 0 {
		serverURL := d.config.TargetURL
		if serverURL == "" {
			serverURL = "http://localhost"
		}
		result.OpenAPISpec = GenerateOpenAPISpec(allEndpoints, "Discovered API", "1.0.0", serverURL)
	}

	return result, nil
}

// DiscoverFromURL probes the target application for common API documentation paths.
func (d *APIDiscoverer) DiscoverFromURL(ctx context.Context) ([]APIEndpoint, []string, error) {
	var endpoints []APIEndpoint
	var specURLs []string
	var mu sync.Mutex

	baseURL := strings.TrimRight(d.config.TargetURL, "/")

	type result struct {
		endpoints []APIEndpoint
		specURL   string
	}

	ch := make(chan result, len(apiSpecPaths))

	for _, path := range apiSpecPaths {
		go func(p string) {
			testURL := baseURL + p
			resp, err := d.client.Get(ctx, testURL)
			if err != nil {
				ch <- result{}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				ch <- result{}
				return
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			if err != nil {
				ch <- result{}
				return
			}

			bodyStr := string(body)
			contentType := resp.Header.Get("Content-Type")

			// Check if this looks like an API spec.
			if isAPISpec(bodyStr, contentType) {
				eps, err := parseSpecContent(body)
				if err == nil && len(eps) > 0 {
					ch <- result{endpoints: eps, specURL: testURL}
					return
				}
				// Even if we can't parse it fully, record the spec URL.
				ch <- result{specURL: testURL}
				return
			}

			// Check for GraphQL introspection.
			if strings.Contains(p, "graphql") && isGraphQLResponse(bodyStr) {
				ep := APIEndpoint{
					Method:      "POST",
					Path:        p,
					Description: "GraphQL endpoint discovered",
					Tags:        []string{"graphql"},
				}
				ch <- result{endpoints: []APIEndpoint{ep}, specURL: testURL}
				return
			}

			// Check for generic API endpoints (health, version, etc.).
			if isGenericAPIEndpoint(p, bodyStr, contentType) {
				method := "GET"
				ep := APIEndpoint{
					Method:      method,
					Path:        p,
					Description: "API endpoint discovered at " + p,
					Tags:        []string{"discovered"},
				}
				ch <- result{endpoints: []APIEndpoint{ep}}
				return
			}

			ch <- result{}
		}(path)
	}

	for range apiSpecPaths {
		r := <-ch
		mu.Lock()
		if len(r.endpoints) > 0 {
			endpoints = append(endpoints, r.endpoints...)
		}
		if r.specURL != "" {
			specURLs = append(specURLs, r.specURL)
		}
		mu.Unlock()
	}

	return endpoints, specURLs, nil
}

// DiscoverFromSource parses local source code files to discover API endpoints.
func (d *APIDiscoverer) DiscoverFromSource(ctx context.Context) ([]APIEndpoint, error) {
	if d.config.LocalPath == "" {
		return nil, nil
	}
	return ParseDirectory(d.config.LocalPath)
}

// parseSpecURL fetches and parses an OpenAPI spec from a URL.
func (d *APIDiscoverer) parseSpecURL(ctx context.Context, specURL string) ([]APIEndpoint, error) {
	resp, err := d.client.Get(ctx, specURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch spec: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("spec URL returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read spec body: %w", err)
	}

	return parseSpecContent(body)
}

// isAPISpec checks if a response body looks like an API specification.
func isAPISpec(body, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(ct, "yaml") {
		lower := strings.ToLower(body)
		return strings.Contains(lower, "swagger") ||
			strings.Contains(lower, "openapi") ||
			strings.Contains(lower, "\"paths\"") ||
			strings.Contains(lower, "\"host\"")
	}
	return false
}

// isGraphQLResponse checks if a response looks like a GraphQL endpoint.
func isGraphQLResponse(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "data") ||
		strings.Contains(lower, "errors") ||
		strings.Contains(lower, "__schema")
}

// isGenericAPIEndpoint checks if a path/response looks like a valid API endpoint.
func isGenericAPIEndpoint(path, body, contentType string) bool {
	// Health, version, status endpoints typically return JSON.
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") {
		return true
	}
	// Check for common API path patterns.
	apiPaths := []string{"/health", "/healthz", "/version", "/status", "/info", "/.well-known"}
	for _, p := range apiPaths {
		if path == p {
			return true
		}
	}
	return false
}

// parseSpecContent parses an OpenAPI/Swagger specification (JSON) and extracts endpoints.
func parseSpecContent(data []byte) ([]APIEndpoint, error) {
	var spec struct {
		Paths map[string]map[string]struct {
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Tags        []string `json:"tags"`
		} `json:"paths"`
	}

	if err := json.Unmarshal(data, &spec); err != nil {
		// Try Swagger 2.0 format
		var swagger2 struct {
			Paths map[string]map[string]struct {
				Summary     string `json:"summary"`
				Description string `json:"description"`
				Tags        []string `json:"tags"`
			} `json:"paths"`
		}
		if err2 := json.Unmarshal(data, &swagger2); err2 != nil {
			return nil, fmt.Errorf("not a valid OpenAPI/Swagger spec: %w", err)
		}
		spec.Paths = swagger2.Paths
	}

	var endpoints []APIEndpoint
	for path, methods := range spec.Paths {
		for method, op := range methods {
			ep := APIEndpoint{
				Method:      strings.ToUpper(method),
				Path:        path,
				Description: op.Summary,
				Tags:        op.Tags,
				Responses:   make(map[int]ResponseSpec),
			}
			if ep.Description == "" {
				ep.Description = op.Description
			}
			if ep.Tags == nil {
				ep.Tags = []string{"api"}
			}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}