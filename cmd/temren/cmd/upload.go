package cmd

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

type uploadResult struct {
	ScanID        string `json:"scan_id"`
	TotalFindings int    `json:"total_findings"`
}

// uploadScanResults posts findings to a Temren API (POST /api/v1/cli/scan-results)
// authenticated with an API key, creating a completed scan on targetID.
func uploadScanResults(ctx context.Context, apiURL, apiKey, targetID string, findings []scanner.Finding, pagesCrawled int, duration time.Duration) (*uploadResult, error) {
	payload := map[string]interface{}{
		"target_id":     targetID,
		"pages_crawled": pagesCrawled,
		"duration_sec":  int(duration.Seconds()),
	}
	rows := make([]map[string]string, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, map[string]string{
			"title":          f.Title,
			"severity":       string(f.Severity),
			"description":    f.Description,
			"url":            f.URL,
			"parameter":      f.Parameter,
			"payload":        f.Payload,
			"evidence":       f.Evidence,
			"owasp_category": f.OWASPCategory,
			"proof":          f.Proof,
		})
	}
	payload["findings"] = rows

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(apiURL, "/") + "/api/v1/cli/scan-results"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out uploadResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
