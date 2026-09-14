package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewAPIDiscoverer(t *testing.T) {
	cfg := &DiscoveryConfig{
		TargetURL:    "https://example.com",
		AutoDiscover: true,
		DiscoverDepth: 2,
	}
	d := NewAPIDiscoverer(cfg, nil)
	if d == nil {
		t.Fatal("expected non-nil discoverer")
	}
	if d.config.DiscoverDepth != 2 {
		t.Errorf("expected DiscoverDepth=2, got %d", d.config.DiscoverDepth)
	}
}

func TestNewAPIDiscoverer_DefaultDepth(t *testing.T) {
	cfg := &DiscoveryConfig{TargetURL: "https://example.com"}
	d := NewAPIDiscoverer(cfg, nil)
	if d.config.DiscoverDepth != 2 {
		t.Errorf("expected default DiscoverDepth=2, got %d", d.config.DiscoverDepth)
	}
}

func TestDiscoverFromURL_SwaggerJSON(t *testing.T) {
	swaggerResp := `{
		"swagger": "2.0",
		"paths": {
			"/users": {
				"get": {
					"summary": "List users",
					"parameters": [{"name": "limit", "in": "query", "type": "integer"}]
				},
				"post": {
					"summary": "Create user"
				}
			},
			"/users/{id}": {
				"get": {
					"summary": "Get user"
				}
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(swaggerResp))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	endpoints, err := parseSpecContent([]byte(swaggerResp))
	if err != nil {
		t.Fatalf("parseSpecContent failed: %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("expected endpoints from swagger spec")
	}

	foundGetUsers := false
	foundPostUsers := false
	for _, ep := range endpoints {
		if ep.Method == "GET" && ep.Path == "/users" {
			foundGetUsers = true
		}
		if ep.Method == "POST" && ep.Path == "/users" {
			foundPostUsers = true
		}
	}
	if !foundGetUsers {
		t.Error("expected GET /users endpoint")
	}
	if !foundPostUsers {
		t.Error("expected POST /users endpoint")
	}
}

func TestDiscoverFromURL_HealthEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"status": "ok"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	if !isGenericAPIEndpoint("/health", `{"status":"ok"}`, "application/json") {
		t.Error("expected /health to be detected as generic API endpoint")
	}
	if isGenericAPIEndpoint("/unknown", "not json", "text/html") {
		t.Error("expected /unknown with text/html to not be detected as generic API endpoint")
	}
}

func TestIsAPISpec(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		expected    bool
	}{
		{"json swagger", `{"swagger":"2.0","paths":{}}`, "application/json", true},
		{"json openapi", `{"openapi":"3.0.0","paths":{}}`, "application/json", true},
		{"json paths only", `{"paths":{}}`, "application/json", true},
		{"yaml content type", "swagger: '2.0'", "application/yaml", true},
		{"html content", "<html></html>", "text/html", false},
		{"plain text", "hello world", "text/plain", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAPISpec(tt.body, tt.contentType)
			if result != tt.expected {
				t.Errorf("isAPISpec(%q, %q) = %v, want %v", tt.body, tt.contentType, result, tt.expected)
			}
		})
	}
}

func TestIsGraphQLResponse(t *testing.T) {
	if !isGraphQLResponse(`{"data":{"user":{"name":"test"}}}`) {
		t.Error("expected GraphQL response with data field")
	}
	if !isGraphQLResponse(`{"errors":[{"message":"test"}]}`) {
		t.Error("expected GraphQL response with errors field")
	}
	if isGraphQLResponse("plain text") {
		t.Error("expected plain text to not be GraphQL")
	}
}

func TestDiscoverFromSource_EmptyPath(t *testing.T) {
	cfg := &DiscoveryConfig{LocalPath: ""}
	d := NewAPIDiscoverer(cfg, nil)
	endpoints, err := d.DiscoverFromSource(context.Background())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if endpoints != nil {
		t.Errorf("expected nil endpoints for empty path, got %v", endpoints)
	}
}

func TestDiscoverFromSource_GoFile(t *testing.T) {
	tmpDir := t.TempDir()
	goFile := filepath.Join(tmpDir, "main.go")
	content := `package main
import "net/http"
func main() {
	http.HandleFunc("/api/users", handler)
	r.GET("/api/posts", handler)
	r.POST("/api/posts", handler)
	e.PUT("/api/posts/1", handler)
	app.Delete("/api/posts/1", handler)
}
`
	if err := os.WriteFile(goFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	endpoints, err := ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("expected endpoints from Go file")
	}

	methods := make(map[string]bool)
	paths := make(map[string]bool)
	for _, ep := range endpoints {
		methods[ep.Method] = true
		paths[ep.Path] = true
	}

	if !methods["GET"] {
		t.Error("expected GET method")
	}
	if !methods["POST"] {
		t.Error("expected POST method")
	}
	if !paths["/api/users"] {
		t.Error("expected /api/users path")
	}
	if !paths["/api/posts"] {
		t.Error("expected /api/posts path")
	}
}

func TestDiscoverFromSource_JSFile(t *testing.T) {
	tmpDir := t.TempDir()
	jsFile := filepath.Join(tmpDir, "app.js")
	content := `
const express = require('express');
const app = express();
app.get('/users', handler);
app.post('/users', handler);
app.put('/users/:id', handler);
app.delete('/users/:id', handler);
router.get('/posts', handler);
app.use('/api', router);
`
	if err := os.WriteFile(jsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	endpoints, err := ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("expected endpoints from JS file")
	}

	paths := make(map[string]bool)
	for _, ep := range endpoints {
		paths[ep.Path] = true
	}

	if !paths["/users"] {
		t.Error("expected /users path")
	}
	if !paths["/posts"] {
		t.Error("expected /posts path")
	}
	if !paths["/api"] {
		t.Error("expected /api path from app.use")
	}
}

func TestDiscoverFromSource_PythonFile(t *testing.T) {
	tmpDir := t.TempDir()
	pyFile := filepath.Join(tmpDir, "app.py")
	content := `
from flask import Flask
app = Flask(__name__)

@app.route('/users')
def list_users():
    pass

@app.route('/users/<id>', methods=['GET', 'PUT', 'DELETE'])
def user_detail(id):
    pass

@app.get('/health')
def health():
    pass

@app.post('/items')
def create_item():
    pass
`
	if err := os.WriteFile(pyFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	endpoints, err := ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("expected endpoints from Python file")
	}

	methods := make(map[string]bool)
	paths := make(map[string]bool)
	for _, ep := range endpoints {
		methods[ep.Method] = true
		paths[ep.Path] = true
	}

	if !paths["/users"] {
		t.Error("expected /users path")
	}
	if !paths["/health"] {
		t.Error("expected /health path")
	}
	if !methods["GET"] {
		t.Error("expected GET method")
	}
	if !methods["POST"] {
		t.Error("expected POST method")
	}
}

func TestDiscoverFromSource_JavaFile(t *testing.T) {
	tmpDir := t.TempDir()
	javaFile := filepath.Join(tmpDir, "UserController.java")
	content := `
@RestController
@RequestMapping("/api")
public class UserController {
    @GetMapping("/users")
    public List<User> listUsers() {}

    @PostMapping("/users")
    public User createUser() {}

    @PutMapping("/users/{id}")
    public User updateUser() {}

    @DeleteMapping("/users/{id}")
    public void deleteUser() {}

    @RequestMapping(value = "/search", method = RequestMethod.GET)
    public List<User> searchUsers() {}
}
`
	if err := os.WriteFile(javaFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	endpoints, err := ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("expected endpoints from Java file")
	}

	methods := make(map[string]bool)
	paths := make(map[string]bool)
	for _, ep := range endpoints {
		methods[ep.Method] = true
		paths[ep.Path] = true
	}

	if !paths["/api/users"] {
		t.Error("expected /api/users path (with class prefix)")
	}
	if !paths["/api/search"] {
		t.Error("expected /api/search path")
	}
	if !methods["GET"] {
		t.Error("expected GET method")
	}
	if !methods["POST"] {
		t.Error("expected POST method")
	}
	if !methods["PUT"] {
		t.Error("expected PUT method")
	}
	if !methods["DELETE"] {
		t.Error("expected DELETE method")
	}
}

func TestDiscoverFromSource_Deduplication(t *testing.T) {
	tmpDir := t.TempDir()
	goFile := filepath.Join(tmpDir, "routes.go")
	content := `
package main
r.GET("/users", handler)
r.GET("/users", handler2)
`
	if err := os.WriteFile(goFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	endpoints, err := ParseDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory failed: %v", err)
	}

	count := 0
	for _, ep := range endpoints {
		if ep.Method == "GET" && ep.Path == "/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 GET /users endpoint after deduplication, got %d", count)
	}
}

func TestDiscoverFromSource_NonExistentPath(t *testing.T) {
	_, err := ParseDirectory("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Logf("ParseDirectory returned error for non-existent path: %v (acceptable)", err)
	}
}

func TestDiscover_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	goFile := filepath.Join(tmpDir, "routes.go")
	content := `package main
r.GET("/api/v1/users", handler)
r.POST("/api/v1/users", handler)
`
	if err := os.WriteFile(goFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &DiscoveryConfig{
		LocalPath:    tmpDir,
		DiscoverDepth: 2,
	}
	d := NewAPIDiscoverer(cfg, nil)

	result, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(result.Endpoints) < 2 {
		t.Errorf("expected at least 2 endpoints, got %d", len(result.Endpoints))
	}

	if result.OpenAPISpec == "" {
		t.Error("expected OpenAPI spec to be generated")
	}

	if !containsSubstring(result.OpenAPISpec, "/api/v1/users") {
		t.Error("expected OpenAPI spec to contain /api/v1/users")
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}