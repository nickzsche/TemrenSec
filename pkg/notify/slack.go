package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Slack delivers via an incoming webhook URL.
type Slack struct {
	HTTP       *http.Client
	WebhookURL string
}

func NewSlack(url string) *Slack { return &Slack{HTTP: http.DefaultClient, WebhookURL: url} }
func (s *Slack) Name() string    { return "slack" }

var slackColors = map[Severity]string{
	SeverityCritical: "#dc2626",
	SeverityHigh:     "#ea580c",
	SeverityMedium:   "#ca8a04",
	SeverityLow:      "#2563eb",
	SeverityInfo:     "#6b7280",
}

func (s *Slack) Send(ctx context.Context, e Event) error {
	payload := map[string]any{
		"text": fmt.Sprintf("*[%s] %s*", e.Severity, e.Title),
		"attachments": []map[string]any{{
			"color": slackColors[e.Severity],
			"fields": []map[string]any{
				{"title": "URL", "value": e.URL, "short": false},
				{"title": "Scanner", "value": e.Scanner, "short": true},
				{"title": "Severity", "value": string(e.Severity), "short": true},
			},
			"text": e.Description,
		}},
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack %d", resp.StatusCode)
	}
	return nil
}
