package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// APISecurityScanner parses OpenAPI specs and tests API endpoints for security issues.
type APISecurityScanner struct {
	SpecURL     string
	AutoDiscover bool
}

// NewAPISecurityScanner creates a new API security scanner.
// specURL is an optional path or URL to an OpenAPI spec.
// autoDiscover enables automatic discovery of API specs.
func NewAPISecurityScanner(specURL string, autoDiscover bool) *APISecurityScanner {
	return &APISecurityScanner{
		SpecURL:      specURL,
		AutoDiscover: autoDiscover,
	}
}

func (s *APISecurityScanner) Name() string {
	return "API Security"
}

func (s *APISecurityScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return findings, nil
	}

	baseURL := u.Scheme + "://" + u.Host

	// Step 1: Get the spec content
	specData, specSource, err := s.getSpecContent(ctx, baseURL, client)
	if err != nil || specData == nil {
		return findings, nil
	}

	// Step 2: Parse the spec
	endpoints, err := parseOpenAPISpec(specData)
	if err != nil || len(endpoints) == 0 {
		return findings, nil
	}

	findings = append(findings, Finding{
		URL:         specSource,
		Title:       fmt.Sprintf("API Spec Discovered (%d endpoints)", len(endpoints)),
		Description: "OpenAPI/Swagger specification found exposing API structure",
		Severity:    SeverityInfo,
		Evidence:    fmt.Sprintf("Spec at %s contains %d endpoints", specSource, len(endpoints)),
		Scanner:     s.Name(),
		Timestamp:   time.Now(),
	})

	// Step 3: Test each endpoint
	for _, ep := range endpoints {
		epFindings := s.testEndpoint(ctx, baseURL, ep, client)
		findings = append(findings, epFindings...)
	}

	return findings, nil
}

// getSpecContent retrieves the OpenAPI spec from the provided URL or by auto-discovery.
func (s *APISecurityScanner) getSpecContent(ctx context.Context, baseURL string, client *httpengine.Client) (map[string]interface{}, string, error) {
	// If a spec URL is provided, try it first
	if s.SpecURL != "" {
		data, err := s.fetchSpec(ctx, s.SpecURL, client)
		if err == nil && data != nil {
			return data, s.SpecURL, nil
		}
	}

	// Auto-discover
	if !s.AutoDiscover {
		return nil, "", fmt.Errorf("no spec URL provided and auto-discover disabled")
	}

	discoveryPaths := []string{
		"/swagger.json",
		"/swagger.yaml",
		"/openapi.json",
		"/openapi.yaml",
		"/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/api/swagger.json",
		"/api/v1/swagger.json",
		"/docs/json",
		"/api/docs",
		"/swagger/v1/swagger.json",
		"/swagger-ui.html",
	}

	for _, path := range discoveryPaths {
		testURL := baseURL + path
		data, err := s.fetchSpec(ctx, testURL, client)
		if err == nil && data != nil {
			return data, testURL, nil
		}
	}

	return nil, "", fmt.Errorf("no API spec found")
}

// fetchSpec fetches and parses a spec from a URL.
func (s *APISecurityScanner) fetchSpec(ctx context.Context, specURL string, client *httpengine.Client) (map[string]interface{}, error) {
	resp, err := client.Get(ctx, specURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseSpecContent(body)
}

// parseSpecContent tries to parse spec content as JSON, then YAML.
func parseSpecContent(body []byte) (map[string]interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err == nil {
		return data, nil
	}
	// Simple YAML-like detection: try JSON first, then return nil for YAML
	// (full YAML parsing would require a dependency; we handle JSON specs robustly)
	return nil, fmt.Errorf("content is not valid JSON; YAML parsing not supported without dependency")
}

// APIEndpoint represents a single API endpoint extracted from a spec.
type APIEndpoint struct {
	Path       string
	Method     string
	Parameters []APIParam
	Auth       bool
}

// APIParam represents an API parameter.
type APIParam struct {
	Name     string
	In       string // query, path, header, cookie
	Required bool
	Type     string
}

// parseOpenAPISpec extracts endpoints from a parsed OpenAPI spec.
func parseOpenAPISpec(spec map[string]interface{}) ([]APIEndpoint, error) {
	var endpoints []APIEndpoint

	// Handle OpenAPI 3.x and Swagger 2.x
	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no paths found in spec")
	}

	for path, pathItem := range paths {
		pathMethods, ok := pathItem.(map[string]interface{})
		if !ok {
			continue
		}

		for method, operation := range pathMethods {
			method = strings.ToUpper(method)
			if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
				continue
			}

			op, ok := operation.(map[string]interface{})
			if !ok {
				continue
			}

			ep := APIEndpoint{
				Path:   path,
				Method: method,
			}

			// Extract parameters
			if params, ok := op["parameters"].([]interface{}); ok {
				for _, p := range params {
					param, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					apiParam := APIParam{
						Name:     getStringField(param, "name"),
						In:       getStringField(param, "in"),
						Required: getBoolField(param, "required"),
						Type:     getStringType(param),
					}
					ep.Parameters = append(ep.Parameters, apiParam)
				}
			}

			// Check for security requirement
			if security, ok := op["security"].([]interface{}); ok && len(security) > 0 {
				ep.Auth = true
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints, nil
}

// testEndpoint tests a single API endpoint for security issues.
func (s *APISecurityScanner) testEndpoint(ctx context.Context, baseURL string, ep APIEndpoint, client *httpengine.Client) []Finding {
	var findings []Finding

	fullURL := baseURL + ep.Path

	// Replace path parameters with test values
	testURL := replacePathParams(fullURL)

	// Test 1: Missing authentication on endpoint
	if !ep.Auth {
		findings = append(findings, Finding{
			URL:         testURL,
			Title:       "Missing Authentication on API Endpoint",
			Description: fmt.Sprintf("Endpoint %s %s has no security requirement defined", ep.Method, ep.Path),
			Severity:    SeverityMedium,
			Evidence:    "No security scheme defined in OpenAPI spec for this endpoint",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
			OWASPCategory: "API1:2023 Broken Object Level Authorization",
		})
	}

	// Test 2: Test parameters with fuzz payloads
	for _, param := range ep.Parameters {
		paramFindings := s.testParameter(ctx, testURL, ep, param, client)
		findings = append(findings, paramFindings...)
	}

	// Test 3: Mass assignment - try sending extra fields
	if ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH" {
		findings = append(findings, s.testMassAssignment(ctx, testURL, ep, client)...)
	}

	// Test 4: Rate limiting check on auth-related endpoints
	if isAuthEndpoint(ep.Path) {
		findings = append(findings, s.testRateLimiting(ctx, testURL, ep, client)...)
	}

	// Test 5: API version disclosure
	findings = append(findings, s.testVersionDisclosure(ctx, testURL, ep, client)...)

	return findings
}

// testParameter fuzzes a single parameter with appropriate payloads.
func (s *APISecurityScanner) testParameter(ctx context.Context, testURL string, ep APIEndpoint, param APIParam, client *httpengine.Client) []Finding {
	var findings []Finding

	// SQL injection payloads for query/path params
	if param.In == "query" || param.In == "path" {
		for _, payload := range []string{"' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd"} {
			var resp *http.Response
			var err error

			if param.In == "query" {
				fuzzedURL := testURL + "?" + param.Name + "=" + payload
				resp, err = client.Get(ctx, fuzzedURL)
			} else {
				// Path params already replaced
				continue
			}

			if err != nil {
				continue
			}
			body, _ := readBody(resp)
			resp.Body.Close()
			bodyStr := string(body)

			// Check for SQL error patterns
			if containsAny(bodyStr, "SQL syntax", "mysql_", "pg_query", "ORA-", "SQLITE_ERROR", "unclosed quotation mark") {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "SQL Injection in API Parameter",
					Description: fmt.Sprintf("Parameter '%s' in %s %s is vulnerable to SQL injection", param.Name, ep.Method, ep.Path),
					Severity:    SeverityCritical,
					Payload:     payload,
					Evidence:    "SQL error pattern detected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
					Parameter:  param.Name,
					OWASPCategory: "API8:2023 Security Misconfiguration",
				})
				break
			}

			// Check for XSS reflection
			if strings.Contains(bodyStr, payload) && strings.Contains(payload, "<script>") {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "XSS in API Parameter",
					Description: fmt.Sprintf("Parameter '%s' in %s %s reflects input without sanitization", param.Name, ep.Method, ep.Path),
					Severity:    SeverityHigh,
					Payload:     payload,
					Evidence:    "Payload reflected in response body",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
					Parameter:  param.Name,
					OWASPCategory: "API8:2023 Security Misconfiguration",
				})
			}
		}
	}

	// Test for excessive data exposure - check if response contains too many fields
	if ep.Method == "GET" && (param.In == "query" || param.In == "path" || len(ep.Parameters) == 0) {
		resp, err := client.Get(ctx, testURL)
		if err == nil {
			body, _ := readBody(resp)
			resp.Body.Close()

			// Check for sensitive data patterns in response
			sensitivePatterns := []string{"password", "secret", "token", "api_key", "private_key", "ssn", "credit_card"}
			bodyStr := strings.ToLower(string(body))
			for _, pattern := range sensitivePatterns {
				if strings.Contains(bodyStr, pattern) {
					findings = append(findings, Finding{
						URL:         testURL,
						Title:       "Excessive Data Exposure in API Response",
						Description: fmt.Sprintf("API response at %s %s may expose sensitive field: %s", ep.Method, ep.Path, pattern),
						Severity:    SeverityHigh,
						Evidence:    fmt.Sprintf("Sensitive pattern '%s' found in response", pattern),
						Scanner:     s.Name(),
						Timestamp:   time.Now(),
						OWASPCategory: "API3:2023 Broken Object Property Level Authorization",
					})
					break
				}
			}
		}
	}

	return findings
}

// testMassAssignment tests for mass assignment vulnerabilities.
func (s *APISecurityScanner) testMassAssignment(ctx context.Context, testURL string, ep APIEndpoint, client *httpengine.Client) []Finding {
	var findings []Finding

	// Try sending requests with extra privileged fields
	extraFields := map[string]string{
		"role":      "admin",
		"is_admin":  "true",
		"admin":     "true",
		"is_staff":  "true",
		"is_superuser": "true",
	}

	jsonBody := buildJSONBody(ep.Parameters, extraFields)
	resp, err := client.Post(ctx, testURL, "application/json", strings.NewReader(jsonBody))
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	// If the server accepts the request with extra fields, it may be vulnerable
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, _ := readBody(resp)
		bodyStr := strings.ToLower(string(body))

		// Check if any of the extra fields appear in the response
		for field := range extraFields {
			if strings.Contains(bodyStr, field) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Mass Assignment Vulnerability",
					Description: fmt.Sprintf("Endpoint %s %s accepts extra field '%s' that may grant elevated privileges", ep.Method, ep.Path, field),
					Severity:    SeverityHigh,
					Payload:     jsonBody,
					Evidence:    fmt.Sprintf("Field '%s' reflected in response after being set in request", field),
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
					OWASPCategory: "API3:2023 Broken Object Property Level Authorization",
				})
				break
			}
		}
	}

	return findings
}

// testRateLimiting checks if auth endpoints have rate limiting.
func (s *APISecurityScanner) testRateLimiting(ctx context.Context, testURL string, ep APIEndpoint, client *httpengine.Client) []Finding {
	var findings []Finding

	// Send multiple rapid requests and check for rate limiting headers
	hasRateLimit := false
	for i := 0; i < 5; i++ {
		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check for rate limiting headers
		rateLimitHeaders := []string{
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-Ratelimit-Limit",
			"Retry-After",
			"RateLimit-Limit",
		}
		for _, h := range rateLimitHeaders {
			if resp.Header.Get(h) != "" {
				hasRateLimit = true
				break
			}
		}
		if hasRateLimit {
			break
		}
	}

	if !hasRateLimit {
		findings = append(findings, Finding{
			URL:         testURL,
			Title:       "Missing Rate Limiting on Auth Endpoint",
			Description: fmt.Sprintf("Authentication endpoint %s %s lacks rate limiting headers", ep.Method, ep.Path),
			Severity:    SeverityMedium,
			Evidence:    "No rate limiting headers (X-RateLimit-*, Retry-After) detected after 5 rapid requests",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
			OWASPCategory: "API4:2023 Unrestricted Resource Consumption",
		})
	}

	return findings
}

// testVersionDisclosure checks for API version information leakage.
func (s *APISecurityScanner) testVersionDisclosure(ctx context.Context, testURL string, ep APIEndpoint, client *httpengine.Client) []Finding {
	var findings []Finding

	resp, err := client.Get(ctx, testURL)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	// Check response headers for version disclosure
	versionHeaders := []string{"X-API-Version", "X-Version", "Server"}
	for _, h := range versionHeaders {
		val := resp.Header.Get(h)
		if val != "" && (strings.Contains(strings.ToLower(val), "version") ||
			strings.Contains(strings.ToLower(val), "v1") ||
			strings.Contains(strings.ToLower(val), "v2") ||
			strings.Contains(strings.ToLower(val), "v3")) {
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "API Version Disclosure",
				Description: fmt.Sprintf("API version information exposed via %s header: %s", h, val),
				Severity:    SeverityLow,
				Evidence:    fmt.Sprintf("Header %s: %s", h, val),
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
				OWASPCategory: "API8:2023 Security Misconfiguration",
			})
		}
	}

	return findings
}

// Helper functions

func replacePathParams(path string) string {
	result := path
	for strings.Contains(result, "{") {
		start := strings.Index(result, "{")
		end := strings.Index(result, "}")
		if end <= start {
			break
		}
		result = result[:start] + "1" + result[end+1:]
	}
	return result
}

func isAuthEndpoint(path string) bool {
	authPaths := []string{"/login", "/auth", "/signin", "/token", "/oauth", "/session"}
	lower := strings.ToLower(path)
	for _, p := range authPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func buildJSONBody(params []APIParam, extraFields map[string]string) string {
	body := make(map[string]string)
	for _, p := range params {
		if p.In == "query" || p.In == "path" {
			continue
		}
		body[p.Name] = "test"
	}
	for k, v := range extraFields {
		body[k] = v
	}
	data, _ := json.Marshal(body)
	return string(data)
}

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBoolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getStringType(m map[string]interface{}) string {
	if schema, ok := m["schema"].(map[string]interface{}); ok {
		if t, ok := schema["type"].(string); ok {
			return t
		}
	}
	if t, ok := m["type"].(string); ok {
		return t
	}
	return "string"
}

func containsAny(s string, patterns ...string) bool {
	lower := strings.ToLower(s)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}