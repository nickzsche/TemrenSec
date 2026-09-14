package github

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

// Config holds GitHub client configuration.
type Config struct {
	Token   string // GitHub personal access token
	Owner   string // Repository owner/organization
	Repo    string // Repository name
	BaseURL string // Custom GitHub Enterprise URL (default: https://api.github.com)
}

// Client is a GitHub API client for creating issues and posting PR comments.
type Client struct {
	config     *Config
	httpClient *http.Client
}

// IssueResult represents the result of creating a GitHub issue.
type IssueResult struct {
	IssueNumber int    `json:"number"`
	URL         string `json:"html_url"`
	State       string `json:"state"`
}

// NewClient creates a new GitHub client with the given configuration.
func NewClient(config *Config) *Client {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		config: &Config{
			Token:   config.Token,
			Owner:   config.Owner,
			Repo:    config.Repo,
			BaseURL: baseURL,
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// severityLabel maps scanner severity to a GitHub label name.
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

// severityBadge returns a colored markdown badge for the severity level.
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

// truncate limits a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// buildIssueBody generates the markdown body for a GitHub issue from a finding.
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

// buildIssueTitle generates the title for a GitHub issue from a finding.
func buildIssueTitle(f scanner.Finding) string {
	return fmt.Sprintf("[Temren] [%s] %s", strings.ToUpper(string(f.Severity)), f.Title)
}

// doRequest performs an HTTP request with authentication and rate-limit handling.
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

	req.Header.Set("Authorization", "token "+c.config.Token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(respBody), "rate limit") {
			return nil, fmt.Errorf("github api rate limit exceeded")
		}
		return nil, fmt.Errorf("forbidden: %s", string(respBody))
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		return nil, fmt.Errorf("github api rate limit exceeded (429)")
	}

	return resp, nil
}

// searchExistingIssue searches for an open issue with the given title.
func (c *Client) searchExistingIssue(ctx context.Context, title string) (*IssueResult, error) {
	path := fmt.Sprintf("/search/issues?q=repo:%s/%s+is:issue+is:open+in:title:%s",
		c.config.Owner, c.config.Repo, urlEncode(title))

	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search issues returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Items []struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
			State  string `json:"state"`
			URL    string `json:"html_url"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode search result: %w", err)
	}

	for _, item := range result.Items {
		if item.Title == title {
			return &IssueResult{
				IssueNumber: item.Number,
				URL:         item.URL,
				State:       item.State,
			}, nil
		}
	}

	return nil, nil
}

// ensureLabel creates a label if it does not exist, then returns its name.
func (c *Client) ensureLabel(ctx context.Context, name, color string) error {
	path := fmt.Sprintf("/repos/%s/%s/labels", c.config.Owner, c.config.Repo)

	payload := map[string]string{
		"name":  name,
		"color": color,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusUnprocessableEntity {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create label returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateIssue creates a GitHub issue from a finding, deduplicating if an open issue with the same title exists.
func (c *Client) CreateIssue(ctx context.Context, finding scanner.Finding) (*IssueResult, error) {
	title := buildIssueTitle(finding)
	label := severityLabel(finding.Severity)

	labelColors := map[string]string{
		"security-critical": "e74c3c",
		"security-high":     "e67e22",
		"security-medium":   "f1c40f",
		"security-low":      "2ecc71",
		"security-info":      "3498db",
	}
	if color, ok := labelColors[label]; ok {
		_ = c.ensureLabel(ctx, label, color)
	}

	existing, err := c.searchExistingIssue(ctx, title)
	if err != nil {
		return nil, fmt.Errorf("search existing issue: %w", err)
	}

	if existing != nil {
		path := fmt.Sprintf("/repos/%s/%s/issues/%d", c.config.Owner, c.config.Repo, existing.IssueNumber)
		payload := map[string]interface{}{
			"body": buildIssueBody(finding),
		}

		resp, err := c.doRequest(ctx, http.MethodPatch, path, payload)
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

	path := fmt.Sprintf("/repos/%s/%s/issues", c.config.Owner, c.config.Repo)
	payload := map[string]interface{}{
		"title":  title,
		"body":   buildIssueBody(finding),
		"labels": []string{label},
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

// CreateIssues creates GitHub issues for multiple findings.
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

// PostPRComment posts a summary comment on a pull request with findings.
func (c *Client) PostPRComment(ctx context.Context, prNumber int, findings []scanner.Finding) error {
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

	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", c.config.Owner, c.config.Repo, prNumber)
	payload := map[string]string{
		"body": sb.String(),
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return fmt.Errorf("post PR comment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("post PR comment returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// urlEncode percent-encodes special characters for URL query parameters.
func urlEncode(s string) string {
	s = strings.ReplaceAll(s, " ", "+")
	s = strings.ReplaceAll(s, "[", "%5B")
	s = strings.ReplaceAll(s, "]", "%5D")
	return s
}