package jira

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/temren/internal/model"
)

type Config struct {
	BaseURL  string
	Username string
	APIToken string
	Project  string
}

type Client struct {
	config     *Config
	httpClient *http.Client
}

type Issue struct {
	ID          string `json:"id,omitempty"`
	Key         string `json:"key,omitempty"`
	Self        string `json:"self,omitempty"`
	Fields      Fields `json:"fields"`
}

type Fields struct {
	Project     Project     `json:"project"`
	Summary     string      `json:"summary"`
	Description Description `json:"description"`
	Issuetype   Issuetype   `json:"issuetype"`
	Priority    *Priority   `json:"priority,omitempty"`
	Labels      []string    `json:"labels,omitempty"`
}

type Project struct {
	Key string `json:"key"`
}

type Issuetype struct {
	Name string `json:"name"`
}

type Priority struct {
	Name string `json:"name"`
}

type Description struct {
	Type    string   `json:"type"`
	Version int      `json:"version"`
	Content []DocNode `json:"content"`
}

type DocNode struct {
	Type    string    `json:"type"`
	Content []TextNode `json:"content,omitempty"`
	Text    string    `json:"text,omitempty"`
	Attrs   map[string]interface{} `json:"attrs,omitempty"`
}

type TextNode struct {
	Type string `json:"type"`
	Text string `json:"text"`
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
		Fields: Fields{
			Project: Project{Key: c.config.Project},
			Summary: fmt.Sprintf("[%s] %s", vuln.Severity, vuln.Title),
			Description: c.buildDescription(vuln, targetURL),
			Issuetype: Issuetype{Name: "Bug"},
			Priority:  c.mapSeverityToPriority(vuln.Severity),
			Labels:    []string{"temren-security", vuln.OWASPCategory},
		},
	}

	payload, err := json.Marshal(issue)
	if err != nil {
		return nil, fmt.Errorf("marshal issue: %w", err)
	}

	url := fmt.Sprintf("%s/rest/api/3/issue", c.config.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.basicAuth())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("jira api returned %d", resp.StatusCode)
	}

	var created Issue
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &created, nil
}

func (c *Client) TestConnection() error {
	url := fmt.Sprintf("%s/rest/api/3/project/%s", c.config.BaseURL, c.config.Project)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", c.basicAuth())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jira api returned %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) basicAuth() string {
	auth := c.config.Username + ":" + c.config.APIToken
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *Client) buildDescription(vuln *model.Vulnerability, targetURL string) Description {
	content := []DocNode{
		{
			Type: "paragraph",
			Content: []TextNode{
				{Type: "text", Text: fmt.Sprintf("A security vulnerability was detected on %s", targetURL)},
			},
		},
		{
			Type: "paragraph",
			Content: []TextNode{
				{Type: "text", Text: "Severity: " + vuln.Severity},
			},
		},
		{
			Type: "paragraph",
			Content: []TextNode{
				{Type: "text", Text: "OWASP Category: " + vuln.OWASPCategory},
			},
		},
		{
			Type: "paragraph",
			Content: []TextNode{
				{Type: "text", Text: vuln.Description},
			},
		},
	}

	if vuln.URL != "" {
		content = append(content, DocNode{
			Type: "paragraph",
			Content: []TextNode{
				{Type: "text", Text: "Affected URL: " + vuln.URL},
			},
		})
	}

	if vuln.FixRecommendation != "" {
		content = append(content, DocNode{
			Type: "paragraph",
			Content: []TextNode{
				{Type: "text", Text: "Fix Recommendation: " + vuln.FixRecommendation},
			},
		})
	}

	return Description{
		Type:    "doc",
		Version: 1,
		Content: content,
	}
}

func (c *Client) mapSeverityToPriority(severity string) *Priority {
	mapping := map[string]string{
		"CRITICAL": "Highest",
		"HIGH":     "High",
		"MEDIUM":   "Medium",
		"LOW":      "Low",
		"INFO":     "Lowest",
	}

	if p, ok := mapping[severity]; ok {
		return &Priority{Name: p}
	}
	return &Priority{Name: "Medium"}
}
