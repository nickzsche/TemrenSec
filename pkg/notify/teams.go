package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Teams delivers via Microsoft Teams incoming webhook (MessageCard format).
type Teams struct {
	HTTP       *http.Client
	WebhookURL string
}

func NewTeams(url string) *Teams { return &Teams{HTTP: http.DefaultClient, WebhookURL: url} }
func (t *Teams) Name() string    { return "teams" }

var teamsColors = map[Severity]string{
	SeverityCritical: "DC2626",
	SeverityHigh:     "EA580C",
	SeverityMedium:   "CA8A04",
	SeverityLow:      "2563EB",
	SeverityInfo:     "6B7280",
}

func (t *Teams) Send(ctx context.Context, e Event) error {
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    e.Title,
		"themeColor": teamsColors[e.Severity],
		"title":      fmt.Sprintf("[%s] %s", e.Severity, e.Title),
		"text":       e.Description,
		"sections": []map[string]any{{
			"facts": []map[string]string{
				{"name": "URL", "value": e.URL},
				{"name": "Scanner", "value": e.Scanner},
				{"name": "Severity", "value": string(e.Severity)},
			},
		}},
	}
	buf, _ := json.Marshal(card)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, t.WebhookURL, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams %d", resp.StatusCode)
	}
	return nil
}
