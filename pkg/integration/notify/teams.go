package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type TeamsConfig struct {
	WebhookURL string
}

type TeamsNotifier struct {
	config TeamsConfig
}

func NewTeamsNotifier(config TeamsConfig) *TeamsNotifier {
	return &TeamsNotifier{config: config}
}

func (t *TeamsNotifier) Name() string {
	return "teams"
}

func (t *TeamsNotifier) Send(ctx context.Context, result ScanResult) error {
	payload := t.buildPayload(result)

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal teams payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.config.WebhookURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send teams notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("teams webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *TeamsNotifier) buildPayload(result ScanResult) map[string]interface{} {
	facts := []map[string]string{
		{"title": "Critical", "value": fmt.Sprintf("%d", result.SeverityCount.Critical)},
		{"title": "High", "value": fmt.Sprintf("%d", result.SeverityCount.High)},
		{"title": "Medium", "value": fmt.Sprintf("%d", result.SeverityCount.Medium)},
		{"title": "Low", "value": fmt.Sprintf("%d", result.SeverityCount.Low)},
		{"title": "Info", "value": fmt.Sprintf("%d", result.SeverityCount.Info)},
	}

	bodyItems := []map[string]interface{}{
		{
			"type":   "TextBlock",
			"text":   "🔒 Temren Security Scan Complete",
			"weight": "Bolder",
			"size":   "Large",
		},
		{
			"type": "TextBlock",
			"text": fmt.Sprintf("Target: %s\nTotal Findings: %d", result.Target, result.TotalFindings),
			"wrap": true,
		},
		{
			"type":  "FactSet",
			"facts": facts,
		},
	}

	if len(result.TopFindings) > 0 {
		var findingLines string
		for i, f := range result.TopFindings {
			findingLines += fmt.Sprintf("%d. [%s] %s — %s\n", i+1, f.Severity, f.Title, f.URL)
		}
		bodyItems = append(bodyItems, map[string]interface{}{
			"type": "TextBlock",
			"text": fmt.Sprintf("**Top Critical/High Findings:**\n%s", findingLines),
			"wrap": true,
		})
	}

	adaptiveCard := map[string]interface{}{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body": []map[string]interface{}{
			{
				"type":  "Container",
				"items": bodyItems,
			},
		},
	}

	payload := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content":     adaptiveCard,
			},
		},
	}

	return payload
}