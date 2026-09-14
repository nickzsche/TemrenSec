package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Discord delivers via incoming webhook.
type Discord struct {
	HTTP       *http.Client
	WebhookURL string
}

func NewDiscord(url string) *Discord { return &Discord{HTTP: http.DefaultClient, WebhookURL: url} }
func (d *Discord) Name() string      { return "discord" }

var discordColors = map[Severity]int{
	SeverityCritical: 0xDC2626,
	SeverityHigh:     0xEA580C,
	SeverityMedium:   0xCA8A04,
	SeverityLow:      0x2563EB,
	SeverityInfo:     0x6B7280,
}

func (d *Discord) Send(ctx context.Context, e Event) error {
	payload := map[string]any{
		"embeds": []map[string]any{{
			"title":       fmt.Sprintf("[%s] %s", e.Severity, e.Title),
			"description": e.Description,
			"url":         e.URL,
			"color":       discordColors[e.Severity],
			"fields": []map[string]any{
				{"name": "Scanner", "value": e.Scanner, "inline": true},
				{"name": "Severity", "value": string(e.Severity), "inline": true},
			},
		}},
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord %d", resp.StatusCode)
	}
	return nil
}
