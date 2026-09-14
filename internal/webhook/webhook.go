package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/temren/internal/config"
	"github.com/temren/internal/model"
)

type WebhookPayload struct {
	Event     string      `json:"event"`
	Timestamp string      `json:"timestamp"`
	Scan      *model.Scan `json:"scan,omitempty"`
	Target    *model.Target `json:"target,omitempty"`
	UserID    string      `json:"user_id,omitempty"`
}

type SlackMessage struct {
	Text        string            `json:"text"`
	Blocks      []SlackBlock      `json:"blocks,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackBlock struct {
	Type string `json:"type"`
	Text *SlackText `json:"text,omitempty"`
}

type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type SlackAttachment struct {
	Color  string `json:"color"`
	Blocks []SlackBlock `json:"blocks,omitempty"`
}

type DiscordEmbed struct {
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Color       int     `json:"color"`
	Fields      []DiscordField `json:"fields,omitempty"`
	Timestamp   string  `json:"timestamp"`
}

type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type DiscordPayload struct {
	Username string        `json:"username"`
	Embeds   []DiscordEmbed `json:"embeds,omitempty"`
}

func SendScanCompleteNotification(ctx context.Context, scan *model.Scan, target *model.Target, userID string) error {
	cfg := config.AppConfig
	
	webhookURLs := getWebhookURLs(cfg)
	if len(webhookURLs) == 0 {
		return nil
	}

	payload := WebhookPayload{
		Event:     "scan.complete",
		Timestamp: time.Now().Format(time.RFC3339),
		Scan:      scan,
		Target:    target,
		UserID:    userID,
	}

	for _, webhookURL := range webhookURLs {
		if err := sendWebhook(ctx, webhookURL, payload); err != nil {
			return err
		}
	}

	return nil
}

func SendSlackNotification(scan *model.Scan, targetURL string) error {
	cfg := config.AppConfig
	if cfg.SlackWebhookURL == "" {
		return nil
	}

	color := "green"
	if scan.CriticalCount > 0 || scan.HighCount > 0 {
		color = "red"
	} else if scan.MediumCount > 0 {
		color = "yellow"
	}

	message := SlackMessage{
		Text: fmt.Sprintf("Scan completed for %s", targetURL),
		Attachments: []SlackAttachment{
			{
				Color: color,
				Blocks: []SlackBlock{
					{
						Type: "section",
						Text: &SlackText{
							Type: "mrkdwn",
							Text: fmt.Sprintf("*Scan Complete*\nTarget: %s", targetURL),
						},
					},
					{
						Type: "section",
						Text: &SlackText{
							Type: "mrkdwn",
							Text: fmt.Sprintf("*Findings:* %d total\n• Critical: %d\n• High: %d\n• Medium: %d\n• Low: %d",
								scan.TotalFindings,
								scan.CriticalCount,
								scan.HighCount,
								scan.MediumCount,
								scan.LowCount),
						},
					},
				},
			},
		},
	}

	body, err := json.Marshal(message)
	if err != nil {
		return err
	}

	resp, err := http.Post(cfg.SlackWebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack webhook returned status: %d", resp.StatusCode)
	}

	return nil
}

func SendDiscordNotification(scan *model.Scan, targetURL string) error {
	cfg := config.AppConfig
	if cfg.DiscordWebhookURL == "" {
		return nil
	}

	color := 0x00ff00
	if scan.CriticalCount > 0 || scan.HighCount > 0 {
		color = 0xff0000
	} else if scan.MediumCount > 0 {
		color = 0xffaa00
	}

	embed := DiscordEmbed{
		Title:       "Temren Scan Complete",
		Description: fmt.Sprintf("Scan completed for %s", targetURL),
		Color:       color,
		Fields: []DiscordField{
			{Name: "Total Findings", Value: fmt.Sprintf("%d", scan.TotalFindings), Inline: true},
			{Name: "Critical", Value: fmt.Sprintf("%d", scan.CriticalCount), Inline: true},
			{Name: "High", Value: fmt.Sprintf("%d", scan.HighCount), Inline: true},
			{Name: "Medium", Value: fmt.Sprintf("%d", scan.MediumCount), Inline: true},
			{Name: "Low", Value: fmt.Sprintf("%d", scan.LowCount), Inline: true},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	payload := DiscordPayload{
		Username: "Temren Security Scanner",
		Embeds:   []DiscordEmbed{embed},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(cfg.DiscordWebhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("discord webhook returned status: %d", resp.StatusCode)
	}

	return nil
}

func sendWebhook(ctx context.Context, url string, payload WebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("webhook returned status: %d", resp.StatusCode)
	}

	return nil
}

func getWebhookURLs(cfg *config.Config) []string {
	var urls []string
	if cfg.SlackWebhookURL != "" {
		urls = append(urls, cfg.SlackWebhookURL)
	}
	if cfg.DiscordWebhookURL != "" {
		urls = append(urls, cfg.DiscordWebhookURL)
	}
	return urls
}
