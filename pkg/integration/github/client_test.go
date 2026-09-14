package github

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
		Token: "test-token",
		Owner: "testowner",
		Repo:  "testrepo",
	}
	client := NewClient(cfg)

	if client.config.Token != "test-token" {
		t.Errorf("expected token 'test-token', got %s", client.config.Token)
	}
	if client.config.BaseURL != "https://api.github.com" {
		t.Errorf("expected default base URL, got %s", client.config.BaseURL)
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", client.httpClient.Timeout)
	}
}

func TestNewClientCustomBaseURL(t *testing.T) {
	cfg := &Config{
		Token:   "test-token",
		Owner:   "testowner",
		Repo:    "testrepo",
		BaseURL: "https://github.enterprise.com/api/v3",
	}
	client := NewClient(cfg)

	if client.config.BaseURL != "https://github.enterprise.com/api/v3" {
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

func TestSeverityBadge(t *testing.T) {
	tests := []struct {
		sev      scanner.Severity
		contains string
	}{
		{scanner.SeverityCritical, "CRITICAL"},
		{scanner.SeverityHigh, "HIGH"},
		{scanner.SeverityMedium, "MEDIUM"},
		{scanner.SeverityLow, "LOW"},
		{scanner.SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		result := severityBadge(tt.sev)
		if !containsStr(result, tt.contains) {
			t.Errorf("severityBadge(%s) = %s, want to contain %s", tt.sev, result, tt.contains)
		}
	}
}

func TestTruncate(t *testing.T) {
	short := "hello"
	if result := truncate(short, 10); result != short {
		t.Errorf("truncate short string: got %q, want %q", result, short)
	}

	long := "this is a very long string that should be truncated"
	result := truncate(long, 10)
	if len(result) != 10+3 { // 10 chars + "..."
		t.Errorf("truncate long string: got len %d, want %d", len(result), 13)
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
	if !containsStr(body, "HIGH") {
		t.Error("body should contain confidence")
	}
	if !containsStr(body, "A03:2021-Injection") {
		t.Error("body should contain OWASP category")
	}
	if !containsStr(body, "' OR 1=1 --") {
		t.Error("body should contain payload")
	}
}

func TestCreateIssue(t *testing.T) {
	var createReq struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search/issues":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []interface{}{},
			})
		case r.URL.Path == "/repos/testowner/testrepo/labels":
			w.WriteHeader(http.StatusUnprocessableEntity)
		case r.URL.Path == "/repos/testowner/testrepo/issues" && r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
				t.Errorf("decode create request: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"number":   42,
				"html_url": "https://github.com/testowner/testrepo/issues/42",
				"state":    "open",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Owner:   "testowner",
		Repo:    "testrepo",
		BaseURL: server.URL,
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

	if result.IssueNumber != 42 {
		t.Errorf("expected issue number 42, got %d", result.IssueNumber)
	}
	if createReq.Title != "[Temren] [CRITICAL] SQL Injection" {
		t.Errorf("unexpected title: %s", createReq.Title)
	}
	if len(createReq.Labels) != 1 || createReq.Labels[0] != "security-critical" {
		t.Errorf("unexpected labels: %v", createReq.Labels)
	}
}

func TestCreateIssueDeduplication(t *testing.T) {
	var patchCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search/issues":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []interface{}{
					map[string]interface{}{
						"number":  10,
						"title":   "[Temren] [CRITICAL] SQL Injection",
						"state":   "open",
						"html_url": "https://github.com/testowner/testrepo/issues/10",
					},
				},
			})
		case r.URL.Path == "/repos/testowner/testrepo/issues/10" && r.Method == http.MethodPatch:
			patchCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"number":   10,
				"html_url": "https://github.com/testowner/testrepo/issues/10",
				"state":    "open",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Owner:   "testowner",
		Repo:    "testrepo",
		BaseURL: server.URL,
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

	if !patchCalled {
		t.Error("expected existing issue to be updated (PATCH), but it was not")
	}
	if result.IssueNumber != 10 {
		t.Errorf("expected issue number 10, got %d", result.IssueNumber)
	}
}

func TestCreateIssues(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search/issues":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"items": []interface{}{},
			})
		case r.URL.Path == "/repos/testowner/testrepo/labels":
			w.WriteHeader(http.StatusUnprocessableEntity)
		case r.URL.Path == "/repos/testowner/testrepo/issues" && r.Method == http.MethodPost:
			callCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"number":   callCount,
				"html_url": "https://github.com/testowner/testrepo/issues/" + string(rune('0'+callCount)),
				"state":    "open",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Owner:   "testowner",
		Repo:    "testrepo",
		BaseURL: server.URL,
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

func TestPostPRComment(t *testing.T) {
	var commentBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/testowner/testrepo/issues/5/comments" && r.Method == http.MethodPost {
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
		Owner:   "testowner",
		Repo:    "testrepo",
		BaseURL: server.URL,
	})

	findings := []scanner.Finding{
		{Title: "SQL Injection", Severity: scanner.SeverityCritical, URL: "https://example.com/api/users"},
		{Title: "XSS", Severity: scanner.SeverityHigh, URL: "https://example.com/search"},
		{Title: "Info Disclosure", Severity: scanner.SeverityInfo, URL: "https://example.com/info"},
	}

	err := client.PostPRComment(context.Background(), 5, findings)
	if err != nil {
		t.Fatalf("PostPRComment() error: %v", err)
	}

	if !containsStr(commentBody, "🔒 Temren Security Scan Results") {
		t.Error("comment should contain header")
	}
	if !containsStr(commentBody, "Critical") {
		t.Error("comment should contain Critical count")
	}
	if !containsStr(commentBody, "SQL Injection") {
		t.Error("comment should list critical/high findings")
	}
}

func TestRateLimitHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(&Config{
		Token:   "test-token",
		Owner:   "testowner",
		Repo:    "testrepo",
		BaseURL: server.URL,
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
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStrHelper(s, substr))
}

func containsStrHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}