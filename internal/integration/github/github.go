package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/temren/internal/model"
)

type Config struct {
	Token      string
	Owner      string
	Repository string
}

type Client struct {
	config     *Config
	httpClient *http.Client
}

type Issue struct {
	ID          int64  `json:"id,omitempty"`
	Number      int    `json:"number,omitempty"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	State       string `json:"state,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Assignees   []string `json:"assignees,omitempty"`
}

func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) CreateIssue(vuln *model.Vulnerability, targetURL string) (*Issue, error) {
	issue := &Issue{
		Title:  fmt.Sprintf("[%s] %s", vuln.Severity, vuln.Title),
		Body:   c.buildBody(vuln, targetURL),
		Labels: c.mapSeverityToLabels(vuln.Severity),
	}

	payload, err := json.Marshal(issue)
	if err != nil {
		return nil, fmt.Errorf("marshal issue: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", c.config.Owner, c.config.Repository)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var created Issue
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &created, nil
}

func (c *Client) TestConnection() error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", c.config.Owner, c.config.Repository)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) buildBody(vuln *model.Vulnerability, targetURL string) string {
	body := fmt.Sprintf(`## Security Vulnerability Detected

**Target:** %s
**Severity:** %s
**OWASP Category:** %s

### Description
%s
`, targetURL, vuln.Severity, vuln.OWASPCategory, vuln.Description)

	if vuln.URL != "" {
		body += fmt.Sprintf("\n### Affected URL\n%s\n", vuln.URL)
	}

	if vuln.Payload != "" {
		body += fmt.Sprintf("\n### Payload\n```\n%s\n```\n", vuln.Payload)
	}

	if vuln.Evidence != "" {
		body += fmt.Sprintf("\n### Evidence\n```\n%s\n```\n", vuln.Evidence)
	}

	if vuln.FixRecommendation != "" {
		body += fmt.Sprintf("\n### Fix Recommendation\n%s\n", vuln.FixRecommendation)
	}

	body += "\n---\n*This issue was automatically created by Temren Security Scanner*"

	return body
}

func (c *Client) mapSeverityToLabels(severity string) []string {
	labels := []string{"security", "temren"}

	mapping := map[string]string{
		"CRITICAL": "critical",
		"HIGH":     "high",
		"MEDIUM":   "medium",
		"LOW":      "low",
		"INFO":     "info",
	}

	if l, ok := mapping[severity]; ok {
		labels = append(labels, l)
	}

	return labels
}
