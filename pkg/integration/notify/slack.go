package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type SlackConfig struct {
	WebhookURL string
	Channel    string // optional, uses webhook default if empty
	Username   string // default: "Temren Security Scanner"
}

type SlackNotifier struct {
	config SlackConfig
}

func NewSlackNotifier(config SlackConfig) *SlackNotifier {
	if config.Username == "" {
		config.Username = "Temren Security Scanner"
	}
	return &SlackNotifier{config: config}
}

func (s *SlackNotifier) Name() string {
	return "slack"
}

func (s *SlackNotifier) Send(ctx context.Context, result ScanResult) error {
	payload := s.buildPayload(result)

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.WebhookURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *SlackNotifier) buildPayload(result ScanResult) map[string]interface{} {
	var fields []map[string]interface{}

	fields = append(fields, map[string]interface{}{
		"type": "mrkdwn",
		"text": fmt.Sprintf("*Target:* %s", result.Target),
	})
	fields = append(fields, map[string]interface{}{
		"type": "mrkdwn",
		"text": fmt.Sprintf("*Total Findings:* %d", result.TotalFindings),
	})

	severityText := fmt.Sprintf("*Severity Breakdown:*\n🔴 Critical: %d\n🟠 High: %d\n🟡 Medium: %d\n🔵 Low: %d\n⚪ Info: %d",
		result.SeverityCount.Critical,
		result.SeverityCount.High,
		result.SeverityCount.Medium,
		result.SeverityCount.Low,
		result.SeverityCount.Info,
	)

	var blocks []map[string]interface{}

	blocks = append(blocks, map[string]interface{}{
		"type": "header",
		"text": map[string]string{
			"type":  "plain_text",
			"text":  "🔒 Temren Security Scan Complete",
			"emoji": "true",
		},
	})

	blocks = append(blocks, map[string]interface{}{
		"type":    "section",
		"fields":  fields,
	})

	blocks = append(blocks, map[string]interface{}{
		"type": "section",
		"text": map[string]string{
			"type": "mrkdwn",
			"text": severityText,
		},
	})

	blocks = append(blocks, map[string]interface{}{
		"type": "divider",
	})

	if len(result.TopFindings) > 0 {
		var findingLines []string
		for i, f := range result.TopFindings {
			findingLines = append(findingLines, fmt.Sprintf("%d. [%s] %s — %s", i+1, strings.ToUpper(string(f.Severity)), f.Title, f.URL))
		}

		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Top Critical/High Findings:*\n%s", strings.Join(findingLines, "\n")),
			},
		})
	}

	payload := map[string]interface{}{
		"blocks": blocks,
	}

	if s.config.Username != "" {
		payload["username"] = s.config.Username
	}
	if s.config.Channel != "" {
		payload["channel"] = s.config.Channel
	}

	return payload
}