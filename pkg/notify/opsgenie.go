package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// OpsGenie Alert API.
type OpsGenie struct {
	HTTP   *http.Client
	APIKey string
	Team   string
	EUInstance bool
}

func NewOpsGenie(apiKey string) *OpsGenie {
	return &OpsGenie{HTTP: http.DefaultClient, APIKey: apiKey}
}

func (o *OpsGenie) Name() string { return "opsgenie" }

var ogPriority = map[Severity]string{
	SeverityCritical: "P1",
	SeverityHigh:     "P2",
	SeverityMedium:   "P3",
	SeverityLow:      "P4",
	SeverityInfo:     "P5",
}

func (o *OpsGenie) Send(ctx context.Context, e Event) error {
	endpoint := "https://api.opsgenie.com/v2/alerts"
	if o.EUInstance {
		endpoint = "https://api.eu.opsgenie.com/v2/alerts"
	}
	body := map[string]any{
		"message":     e.Title,
		"description": e.Description + "\n\nURL: " + e.URL + "\nScanner: " + e.Scanner,
		"priority":    ogPriority[e.Severity],
		"tags":        append([]string{string(e.Severity), e.Scanner}, e.Tags...),
	}
	if o.Team != "" {
		body["responders"] = []map[string]string{{"name": o.Team, "type": "team"}}
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "GenieKey "+o.APIKey)
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("opsgenie %d", resp.StatusCode)
	}
	return nil
}
