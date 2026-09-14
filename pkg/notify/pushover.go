package notify

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Pushover https://pushover.net/
type Pushover struct {
	HTTP   *http.Client
	Token  string
	User   string
	Device string
}

func NewPushover(token, user string) *Pushover {
	return &Pushover{HTTP: http.DefaultClient, Token: token, User: user}
}

func (p *Pushover) Name() string { return "pushover" }

var pushoverPriority = map[Severity]string{
	SeverityCritical: "2",
	SeverityHigh:     "1",
	SeverityMedium:   "0",
	SeverityLow:      "-1",
	SeverityInfo:     "-2",
}

func (p *Pushover) Send(ctx context.Context, e Event) error {
	form := url.Values{}
	form.Set("token", p.Token)
	form.Set("user", p.User)
	form.Set("title", e.Title)
	form.Set("message", fmt.Sprintf("%s\n%s (%s)", e.Description, e.URL, e.Scanner))
	form.Set("priority", pushoverPriority[e.Severity])
	if pushoverPriority[e.Severity] == "2" {
		form.Set("retry", "60")
		form.Set("expire", "3600")
	}
	if p.Device != "" {
		form.Set("device", p.Device)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("pushover %d", resp.StatusCode)
	}
	return nil
}
