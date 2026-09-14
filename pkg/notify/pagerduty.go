package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PagerDuty Events API v2.
type PagerDuty struct {
	HTTP       *http.Client
	RoutingKey string
}

func NewPagerDuty(routingKey string) *PagerDuty {
	return &PagerDuty{HTTP: http.DefaultClient, RoutingKey: routingKey}
}

func (p *PagerDuty) Name() string { return "pagerduty" }

var pdSeverity = map[Severity]string{
	SeverityCritical: "critical",
	SeverityHigh:     "error",
	SeverityMedium:   "warning",
	SeverityLow:      "info",
	SeverityInfo:     "info",
}

func (p *PagerDuty) Send(ctx context.Context, e Event) error {
	payload := map[string]any{
		"routing_key":  p.RoutingKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":  e.Title,
			"source":   e.URL,
			"severity": pdSeverity[e.Severity],
			"component": e.Scanner,
			"custom_details": map[string]any{
				"description": e.Description,
				"timestamp":   e.Timestamp,
				"tags":        e.Tags,
			},
		},
	}
	buf, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("pagerduty %d", resp.StatusCode)
	}
	return nil
}
