package defectdojo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/scanner"
)

type Config struct {
	BaseURL string
	APIToken string
	ProductName string
	EngagementName string
}

type Client struct {
	config     *Config
	httpClient *http.Client
}

func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *Client) TestConnection() error {
	url := strings.TrimRight(c.config.BaseURL, "/") + "/api/v2/user/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Token "+c.config.APIToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect to defectdojo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("defectdojo api returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *Client) ImportFindings(findings []scanner.Finding, targetURL string) (*ImportResult, error) {
	productID, err := c.ensureProduct()
	if err != nil {
		return nil, fmt.Errorf("ensure product: %w", err)
	}

	engagementID, err := c.ensureEngagement(productID)
	if err != nil {
		return nil, fmt.Errorf("ensure engagement: %w", err)
	}

	scanData, err := c.buildScanFile(findings, targetURL)
	if err != nil {
		return nil, fmt.Errorf("build scan file: %w", err)
	}

	result, err := c.importScan(engagementID, scanData)
	if err != nil {
		return nil, fmt.Errorf("import scan: %w", err)
	}

	return result, nil
}

type ImportResult struct {
	ScanID       int `json:"scan"`
	FindingsNew  int `json:"new_findings"`
	FindingsClosed int `json:"closed_findings"`
	FindingsReactivated int `json:"reactivated_findings"`
}

func (c *Client) ensureProduct() (int, error) {
	url := strings.TrimRight(c.config.BaseURL, "/") + "/api/v2/products/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Token "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var list struct {
		Results []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return 0, fmt.Errorf("decode products: %w", err)
	}

	for _, p := range list.Results {
		if p.Name == c.config.ProductName {
			return p.ID, nil
		}
	}

	return c.createProduct()
}

func (c *Client) createProduct() (int, error) {
	url := strings.TrimRight(c.config.BaseURL, "/") + "/api/v2/products/"
	payload := map[string]interface{}{
		"name":        c.config.ProductName,
		"description": "Product managed by Temren Security Scanner",
		"prod_type":   1,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Token "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("create product returned %d: %s", resp.StatusCode, string(respBody))
	}

	var created struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(bytes.NewReader(func() []byte {
		respBody, _ := io.ReadAll(resp.Body)
		return respBody
	}())).Decode(&created); err != nil {
		return 0, fmt.Errorf("decode created product: %w", err)
	}

	return created.ID, nil
}

func (c *Client) ensureEngagement(productID int) (int, error) {
	engName := c.config.EngagementName
	if engName == "" {
		engName = "Temren Scan - " + time.Now().Format("2006-01-02")
	}

	url := fmt.Sprintf("%s/api/v2/engagements/?product=%d", strings.TrimRight(c.config.BaseURL, "/"), productID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Token "+c.config.APIToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var list struct {
		Results []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return 0, fmt.Errorf("decode engagements: %w", err)
	}

	for _, e := range list.Results {
		if e.Name == engName {
			return e.ID, nil
		}
	}

	return c.createEngagement(productID, engName)
}

func (c *Client) createEngagement(productID int, name string) (int, error) {
	url := strings.TrimRight(c.config.BaseURL, "/") + "/api/v2/engagements/"
	now := time.Now()
	payload := map[string]interface{}{
		"name":         name,
		"product":      productID,
		"target_start": now.Format("2006-01-02"),
		"target_end":   now.AddDate(0, 0, 7).Format("2006-01-02"),
		"status":       "In Progress",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Token "+c.config.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("create engagement returned %d: %s", resp.StatusCode, string(respBody))
	}

	var created struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return 0, fmt.Errorf("decode created engagement: %w", err)
	}

	return created.ID, nil
}

func (c *Client) buildScanFile(findings []scanner.Finding, targetURL string) ([]byte, error) {
	ddFindings := make([]defectDojoFinding, 0, len(findings))
	for _, f := range findings {
		ddFindings = append(ddFindings, defectDojoFinding{
			Title:       f.Title,
			Severity:    severityToDefectDojo(f.Severity),
			Description: f.Description,
			URL:         f.URL,
			Param:       f.Parameter,
			Payload:     f.Payload,
			Evidence:    f.Evidence,
			Scanner:     f.Scanner,
		})
	}

	scanResult := defectDojoScan{
		Findings:  ddFindings,
		TargetURL: targetURL,
		Scanner:   "TemrenSec",
	}

	data, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}

	return data, nil
}

func (c *Client) importScan(engagementID int, scanData []byte) (*ImportResult, error) {
	url := strings.TrimRight(c.config.BaseURL, "/") + "/api/v2/import-scan/"

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", "temren-scan.json")
	if err != nil {
		return nil, fmt.Errorf("create form file: %w", err)
	}
	if _, err := part.Write(scanData); err != nil {
		return nil, fmt.Errorf("write scan data: %w", err)
	}

	fields := map[string]string{
		"scan_date":       time.Now().Format("2006-01-02"),
		"engagement":      fmt.Sprintf("%d", engagementID),
		"scan_type":       "Temren Scan",
		"minimum_severity": "Info",
		"active":          "true",
		"verified":        "true",
	}

	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("write field %s: %w", key, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Token "+c.config.APIToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("import-scan returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result ImportResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode import result: %w", err)
	}

	return &result, nil
}

type defectDojoFinding struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Param       string `json:"param,omitempty"`
	Payload     string `json:"payload,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Scanner     string `json:"scanner"`
}

type defectDojoScan struct {
	Findings  []defectDojoFinding `json:"findings"`
	TargetURL string              `json:"target_url"`
	Scanner   string              `json:"scanner"`
}

func severityToDefectDojo(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical:
		return "Critical"
	case scanner.SeverityHigh:
		return "High"
	case scanner.SeverityMedium:
		return "Medium"
	case scanner.SeverityLow:
		return "Low"
	default:
		return "Info"
	}
}
