package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/scanner"
)

type Config struct {
	Token   string // GitLab personal access token
	Project string // Project ID or path (e.g., "group/project")
	BaseURL string // Custom GitLab URL (default: https://gitlab.com/api/v4)
}

type Client struct {
	config     *Config
	httpClient *http.Client
}

type IssueResult struct {
	IID   int    `json:"iid"`
	URL   string `json:"web_url"`
	State string `json:"state"`
}

func NewClient(config *Config) *Client {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://gitlab.com/api/v4"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		config: &Config{
			Token:   config.Token,
			Project: config.Project,
			BaseURL: baseURL,
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func severityLabel(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "security-critical"
	case scanner.SeverityHigh:
		return "security-high"
	case scanner.SeverityMedium:
		return "security-medium"
	case scanner.SeverityLow:
		return "security-low"
	default:
		return "security-info"
	}
}

func severityBadge(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "🔴 **CRITICAL**"
	case scanner.SeverityHigh:
		return "🟠 **HIGH**"
	case scanner.SeverityMedium:
		return "🟡 **MEDIUM**"
	case scanner.SeverityLow:
		return "🔵 **LOW**"
	default:
		return "⚪ **INFO**"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func buildIssueTitle(f scanner.Finding) string {
	return fmt.Sprintf("[Temren] [%s] %s", strings.ToUpper(string(f.Severity)), f.Title)
}

func buildIssueBody(f scanner.Finding) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("**Severity**: %s\n\n", severityBadge(f.Severity)))
	sb.WriteString(fmt.Sprintf("**Scanner**: %s\n\n", f.Scanner))

	if f.URL != "" {
		sb.WriteString(fmt.Sprintf("**URL**: %s\n\n", f.URL))
	}
	if f.Confidence != "" {
		sb.WriteString(fmt.Sprintf("**Confidence**: %s\n\n", f.Confidence))
	}
	if f.Description != "" {
		sb.WriteString(fmt.Sprintf("**Description**: %s\n\n", f.Description))
	}
	if f.Evidence != "" {
		sb.WriteString(fmt.Sprintf("**Evidence**: %s\n\n", truncate(f.Evidence, 500)))
	}
	if f.Payload != "" {
		sb.WriteString(fmt.Sprintf("**Payload**:\n```\n%s\n```\n\n", f.Payload))
	}
	if f.OWASPCategory != "" {
		sb.WriteString(fmt.Sprintf("**OWASP Category**: %s\n\n", f.OWASPCategory))
	}
	if !f.Timestamp.IsZero() {
		sb.WriteString(fmt.Sprintf("**Timestamp**: %s\n\n", f.Timestamp.Format(time.RFC3339)))
	}

	return sb.String()
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(data)
	}

	url := fmt.Sprintf("%s%s", c.config.BaseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.config.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		return nil, fmt.Errorf("gitlab api rate limit exceeded (429)")
	}

	return resp, nil
}

func (c *Client) projectPath() string {
	return strings.ReplaceAll(c.config.Project, "/", "%2F")
}

func (c *Client) searchExistingIssue(ctx context.Context, title string) (*IssueResult, error) {
	path := fmt.Sprintf("/projects/%s/issues?state=opened&search=%s", c.projectPath(), urlEncode(title))

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search issues returned %d: %s", resp.StatusCode, string(body))
	}

	var issues []struct {
		IID   int    `json:"iid"`
		Title string `json:"title"`
		State string `json:"state"`
		URL   string `json:"web_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		return nil, fmt.Errorf("decode search result: %w", err)
	}

	for _, issue := range issues {
		if issue.Title == title {
			return &IssueResult{
				IID:   issue.IID,
				URL:   issue.URL,
				State: issue.State,
			}, nil
		}
	}

	return nil, nil
}

func (c *Client) CreateIssue(ctx context.Context, finding scanner.Finding) (*IssueResult, error) {
	title := buildIssueTitle(finding)
	label := severityLabel(finding.Severity)

	existing, err := c.searchExistingIssue(ctx, title)
	if err != nil {
		return nil, fmt.Errorf("search existing issue: %w", err)
	}

	if existing != nil {
		path := fmt.Sprintf("/projects/%s/issues/%d", c.projectPath(), existing.IID)
		payload := map[string]interface{}{
			"description": buildIssueBody(finding),
		}

		resp, err := c.doRequest(ctx, http.MethodPut, path, payload)
		if err != nil {
			return nil, fmt.Errorf("update existing issue: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("update issue returned %d: %s", resp.StatusCode, string(body))
		}

		var updated IssueResult
		if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
			return nil, fmt.Errorf("decode updated issue: %w", err)
		}
		return &updated, nil
	}

	path := fmt.Sprintf("/projects/%s/issues", c.projectPath())
	payload := map[string]interface{}{
		"title":       title,
		"description": buildIssueBody(finding),
		"labels":      label,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, fmt.Errorf("create issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create issue returned %d: %s", resp.StatusCode, string(body))
	}

	var result IssueResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode created issue: %w", err)
	}

	return &result, nil
}

func (c *Client) CreateIssues(ctx context.Context, findings []scanner.Finding) ([]IssueResult, error) {
	results := make([]IssueResult, 0, len(findings))
	for _, f := range findings {
		result, err := c.CreateIssue(ctx, f)
		if err != nil {
			return results, fmt.Errorf("create issue for %q: %w", f.Title, err)
		}
		results = append(results, *result)
	}
	return results, nil
}

func (c *Client) PostMRComment(ctx context.Context, mrIID int, findings []scanner.Finding) error {
	counts := make(map[scanner.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	var sb strings.Builder
	sb.WriteString("## 🔒 Temren Security Scan Results\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", counts[scanner.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", counts[scanner.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", counts[scanner.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("| 🔵 Low | %d |\n", counts[scanner.SeverityLow]))
	sb.WriteString(fmt.Sprintf("| ⚪ Info | %d |\n", counts[scanner.SeverityInfo]))

	var criticalHigh []scanner.Finding
	for _, f := range findings {
		if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
			criticalHigh = append(criticalHigh, f)
		}
	}

	if len(criticalHigh) > 0 {
		sb.WriteString("\n### Critical/High Findings:\n")
		for _, f := range criticalHigh {
			sb.WriteString(fmt.Sprintf("- **[%s] %s** — %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.URL))
		}
	}

	path := fmt.Sprintf("/projects/%s/merge_requests/%d/notes", c.projectPath(), mrIID)
	payload := map[string]string{
		"body": sb.String(),
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return fmt.Errorf("post MR comment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("post MR comment returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func urlEncode(s string) string {
	s = strings.ReplaceAll(s, " ", "+")
	s = strings.ReplaceAll(s, "[", "%5B")
	s = strings.ReplaceAll(s, "]", "%5D")
	return s
}