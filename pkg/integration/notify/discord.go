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

type DiscordConfig struct {
	WebhookURL string
	Username   string
}

type DiscordNotifier struct {
	config DiscordConfig
}

func NewDiscordNotifier(config DiscordConfig) *DiscordNotifier {
	if config.Username == "" {
		config.Username = "Temren Security Scanner"
	}
	return &DiscordNotifier{config: config}
}

func (d *DiscordNotifier) Name() string {
	return "discord"
}

func (d *DiscordNotifier) Send(ctx context.Context, result ScanResult) error {
	payload := d.buildPayload(result)

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.config.WebhookURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send discord notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func highestSeverityColor(sc SeverityCount) int {
	switch {
	case sc.Critical > 0:
		return 16711680 // red
	case sc.High > 0:
		return 16741632 // orange
	case sc.Medium > 0:
		return 16776960 // yellow
	case sc.Low > 0:
		return 255 // blue
	default:
		return 8421504 // gray
	}
}

func (d *DiscordNotifier) buildPayload(result ScanResult) map[string]interface{} {
	embedFields := []map[string]interface{}{
		{
			"name":   "Target",
			"value":  result.Target,
			"inline": true,
		},
		{
			"name":   "Total Findings",
			"value":  fmt.Sprintf("%d", result.TotalFindings),
			"inline": true,
		},
		{
			"name":   "🔴 Critical",
			"value":  fmt.Sprintf("%d", result.SeverityCount.Critical),
			"inline": true,
		},
		{
			"name":   "🟠 High",
			"value":  fmt.Sprintf("%d", result.SeverityCount.High),
			"inline": true,
		},
		{
			"name":   "🟡 Medium",
			"value":  fmt.Sprintf("%d", result.SeverityCount.Medium),
			"inline": true,
		},
		{
			"name":   "🔵 Low",
			"value":  fmt.Sprintf("%d", result.SeverityCount.Low),
			"inline": true,
		},
		{
			"name":   "⚪ Info",
			"value":  fmt.Sprintf("%d", result.SeverityCount.Info),
			"inline": true,
		},
	}

	if len(result.TopFindings) > 0 {
		var findingLines []string
		for i, f := range result.TopFindings {
			findingLines = append(findingLines, fmt.Sprintf("%d. [%s] %s — %s", i+1, strings.ToUpper(string(f.Severity)), f.Title, f.URL))
		}
		embedFields = append(embedFields, map[string]interface{}{
			"name":   "Top Critical/High Findings",
			"value":  strings.Join(findingLines, "\n"),
			"inline": false,
		})
	}

	embed := map[string]interface{}{
		"title":  "🔒 Security Scan Complete",
		"color":  highestSeverityColor(result.SeverityCount),
		"fields": embedFields,
		"footer": map[string]string{
			"text": "Temren Security Scanner",
		},
		"timestamp": result.Timestamp,
	}

	payload := map[string]interface{}{
		"username": d.config.Username,
		"embeds":   []map[string]interface{}{embed},
	}

	return payload
}