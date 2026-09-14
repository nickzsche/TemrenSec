package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Ntfy delivers events to a ntfy.sh-compatible server (https://ntfy.sh).
type Ntfy struct {
	HTTP    *http.Client
	BaseURL string // e.g. https://ntfy.zerosixlab.com
	Topic   string
	Token   string // optional bearer token
}

func NewNtfy(baseURL, topic string) *Ntfy {
	return &Ntfy{HTTP: http.DefaultClient, BaseURL: strings.TrimRight(baseURL, "/"), Topic: topic}
}

func (n *Ntfy) Name() string { return "ntfy" }

var ntfyPriority = map[Severity]string{
	SeverityCritical: "5",
	SeverityHigh:     "4",
	SeverityMedium:   "3",
	SeverityLow:      "2",
	SeverityInfo:     "1",
}

func (n *Ntfy) Send(ctx context.Context, e Event) error {
	body := strings.NewReader(fmt.Sprintf("%s\n\nSeverity: %s\nScanner: %s\nURL: %s", e.Description, e.Severity, e.Scanner, e.URL))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.BaseURL+"/"+n.Topic, body)
	if err != nil {
		return err
	}
	req.Header.Set("Title", e.Title)
	req.Header.Set("Priority", ntfyPriority[e.Severity])
	tags := append([]string{string(e.Severity)}, e.Tags...)
	if len(tags) > 0 {
		req.Header.Set("Tags", strings.Join(tags, ","))
	}
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("ntfy %d: %s", resp.StatusCode, string(out))
	}
	return nil
}
