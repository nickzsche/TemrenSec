package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// RocketChat incoming webhook.
type RocketChat struct {
	HTTP       *http.Client
	WebhookURL string
	Channel    string
}

func NewRocketChat(url string) *RocketChat {
	return &RocketChat{HTTP: http.DefaultClient, WebhookURL: url}
}

func (r *RocketChat) Name() string { return "rocketchat" }

var rcColors = map[Severity]string{
	SeverityCritical: "#e74c3c",
	SeverityHigh:     "#e67e22",
	SeverityMedium:   "#f1c40f",
	SeverityLow:      "#3498db",
	SeverityInfo:     "#95a5a6",
}

func (r *RocketChat) Send(ctx context.Context, e Event) error {
	att := map[string]any{
		"title":      e.Title,
		"text":       e.Description,
		"color":      rcColors[e.Severity],
		"fields": []map[string]any{
			{"title": "Severity", "value": e.Severity, "short": true},
			{"title": "Scanner", "value": e.Scanner, "short": true},
			{"title": "URL", "value": e.URL, "short": false},
		},
	}
	body := map[string]any{
		"attachments": []map[string]any{att},
	}
	if r.Channel != "" {
		body["channel"] = r.Channel
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.WebhookURL, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("rocketchat %d", resp.StatusCode)
	}
	return nil
}
