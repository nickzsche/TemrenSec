package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/scanner"
)

func TestNewClient(t *testing.T) {
	cfg := &Config{
		Token:   "test-token",
		Project: "group/project",
	}
	client := NewClient(cfg)

	if client.config.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %s", client.config.Token)
	}
	if client.config.BaseURL != "https://gitlab.com/api/v4" {
		t.Errorf("expected default base URL, got %s", client.config.BaseURL)
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", client.httpClient.Timeout)
	}
}

func TestNewClientCustomBaseURL(t *testing.T) {
	cfg := &Config{
		Token:   "test-token",
		Project: "group/project",
		BaseURL: "https://gitlab.enterprise.com/api/v4",
	}
	client := NewClient(cfg)

	if client.config.BaseURL != "https://gitlab.enterprise.com/api/v4" {
		t.Errorf("expected custom base URL, got %s", client.config.BaseURL)
	}
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		sev      scanner.Severity
		expected string
	}{
		{scanner.SeverityCritical, "security-critical"},
		{scanner.SeverityHigh, "security-high"},
		{scanner.SeverityMedium, "security-medium"},
		{scanner.SeverityLow, "security-low"},
		{scanner.SeverityInfo, "security-info"},
	}

	for _, tt := range tests {
		result := severityLabel(tt.sev)
		if result != tt.expected {
			t.Errorf("severityLabel(%s) = %s, want %s", tt.sev, result, tt.expected)
		}
	}
}

func TestBuildIssueTitle(t *testing.T) {
	f := scanner.Finding{
		Title:    "SQL Injection",
		Severity: scanner.SeverityCritical,
	}
	title := buildIssueTitle(f)
	expected := "[Temren] [CRITICAL] SQL Injection"
	if title != expected {
		t.Errorf("buildIssueTitle() = %q, want %q", title, expected)
	}
}

func TestBuildIssueBody(t *testing.T) {
	f := scanner.Finding{
		Title:         "SQL Injection",
		Severity:      scanner.SeverityCritical,
		Scanner:       "sqli",
		URL:           "https://example.com/api/users",
		Confidence:    scanner.ConfidenceHigh,
		Description:   "A SQL injection vulnerability was found",
		Evidence:      "MySQL error detected",
		Payload:       "' OR 1=1 --",
		OWASPCategory: "A03:2021-Injection",
		Timestamp:     time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	body := buildIssueBody(f)

	if !containsStr(body, "CRITICAL") {
		t.Error("body should contain severity badge")
	}
	if !containsStr(body, "sqli") {
		t.Error("body should contain scanner name")
	}
	if !containsStr(body, "https://example.com/api/users") {
		t.Error("body should contain URL")
	}
	if !containsStr(body, "A03:2021-Injection") {
		t.Error("body should contain OWASP category")
	}
}

func TestCreateIssue(t *testing.T) {
	var createReq struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Labels      string `json:"labels"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/issues" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/issues" && r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"iid":     42,
				"web_url": "https://gitlab.com/group/project/-/issues/42",
				"state":   "opened",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Project: "group/project",
		BaseURL: server.URL + "/api/v4",
	})

	finding := scanner.Finding{
		Title:    "SQL Injection",
		Severity: scanner.SeverityCritical,
		Scanner:  "sqli",
		URL:      "https://example.com/api/users",
	}

	result, err := client.CreateIssue(context.Background(), finding)
	if err != nil {
		t.Fatalf("CreateIssue() error: %v", err)
	}

	if result.IID != 42 {
		t.Errorf("expected issue IID 42, got %d", result.IID)
	}
	if createReq.Title != "[Temren] [CRITICAL] SQL Injection" {
		t.Errorf("unexpected title: %s", createReq.Title)
	}
}

func TestCreateIssueDeduplication(t *testing.T) {
	var putCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/issues" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{
				map[string]interface{}{
					"iid":     10,
					"title":   "[Temren] [CRITICAL] SQL Injection",
					"state":   "opened",
					"web_url": "https://gitlab.com/group/project/-/issues/10",
				},
			})
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/issues/10" && r.Method == http.MethodPut:
			putCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"iid":     10,
				"web_url": "https://gitlab.com/group/project/-/issues/10",
				"state":   "opened",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Project: "group/project",
		BaseURL: server.URL + "/api/v4",
	})

	finding := scanner.Finding{
		Title:    "SQL Injection",
		Severity: scanner.SeverityCritical,
		Scanner:  "sqli",
	}

	result, err := client.CreateIssue(context.Background(), finding)
	if err != nil {
		t.Fatalf("CreateIssue() error: %v", err)
	}

	if !putCalled {
		t.Error("expected existing issue to be updated (PUT), but it was not")
	}
	if result.IID != 10 {
		t.Errorf("expected issue IID 10, got %d", result.IID)
	}
}

func TestCreateIssues(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/issues" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/issues" && r.Method == http.MethodPost:
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"iid":     callCount,
				"web_url": "https://gitlab.com/group/project/-/issues/" + string(rune('0'+callCount)),
				"state":   "opened",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Project: "group/project",
		BaseURL: server.URL + "/api/v4",
	})

	findings := []scanner.Finding{
		{Title: "SQL Injection", Severity: scanner.SeverityCritical, Scanner: "sqli"},
		{Title: "XSS", Severity: scanner.SeverityHigh, Scanner: "xss"},
	}

	results, err := client.CreateIssues(context.Background(), findings)
	if err != nil {
		t.Fatalf("CreateIssues() error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestPostMRComment(t *testing.T) {
	var commentBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() == "/api/v4/projects/group%2Fproject/merge_requests/5/notes" && r.Method == http.MethodPost {
			var payload map[string]string
			json.NewDecoder(r.Body).Decode(&payload)
			commentBody = payload["body"]
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1,
			})
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Project: "group/project",
		BaseURL: server.URL + "/api/v4",
	})

	findings := []scanner.Finding{
		{Title: "SQL Injection", Severity: scanner.SeverityCritical, URL: "https://example.com/api/users"},
		{Title: "XSS", Severity: scanner.SeverityHigh, URL: "https://example.com/search"},
		{Title: "Info Disclosure", Severity: scanner.SeverityInfo, URL: "https://example.com/info"},
	}

	err := client.PostMRComment(context.Background(), 5, findings)
	if err != nil {
		t.Fatalf("PostMRComment() error: %v", err)
	}

	if !containsStr(commentBody, "🔒 Temren Security Scan Results") {
		t.Error("comment should contain header")
	}
	if !containsStr(commentBody, "Critical") {
		t.Error("comment should contain Critical count")
	}
}

func TestRateLimitHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Project: "group/project",
		BaseURL: server.URL + "/api/v4",
	})

	finding := scanner.Finding{
		Title:    "SQL Injection",
		Severity: scanner.SeverityCritical,
		Scanner:  "sqli",
	}

	_, err := client.CreateIssue(context.Background(), finding)
	if err == nil {
		t.Error("expected rate limit error, got nil")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}