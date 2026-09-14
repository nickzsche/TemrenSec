package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Mattermost incoming webhook.
type Mattermost struct {
	HTTP       *http.Client
	WebhookURL string
	Channel    string
	Username   string
}

func NewMattermost(url string) *Mattermost {
	return &Mattermost{HTTP: http.DefaultClient, WebhookURL: url}
}

func (m *Mattermost) Name() string { return "mattermost" }

var mmEmoji = map[Severity]string{
	SeverityCritical: ":rotating_light:",
	SeverityHigh:     ":warning:",
	SeverityMedium:   ":large_orange_diamond:",
	SeverityLow:      ":small_blue_diamond:",
	SeverityInfo:     ":information_source:",
}

func (m *Mattermost) Send(ctx context.Context, e Event) error {
	text := fmt.Sprintf("%s **[%s]** %s\n> %s\n%s — *%s*", mmEmoji[e.Severity], e.Severity, e.Title, e.Description, e.URL, e.Scanner)
	body := map[string]any{"text": text}
	if m.Channel != "" {
		body["channel"] = m.Channel
	}
	if m.Username != "" {
		body["username"] = m.Username
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, m.WebhookURL, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mattermost %d", resp.StatusCode)
	}
	return nil
}
