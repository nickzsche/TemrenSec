package notify

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Twilio SMS.
type Twilio struct {
	HTTP       *http.Client
	AccountSID string
	AuthToken  string
	From       string
	To         string
}

func NewTwilio(sid, token, from, to string) *Twilio {
	return &Twilio{HTTP: http.DefaultClient, AccountSID: sid, AuthToken: token, From: from, To: to}
}

func (t *Twilio) Name() string { return "twilio" }

func (t *Twilio) Send(ctx context.Context, e Event) error {
	body := fmt.Sprintf("[%s] %s — %s", e.Severity, e.Title, e.URL)
	if len(body) > 1500 {
		body = body[:1500]
	}
	form := url.Values{}
	form.Set("From", t.From)
	form.Set("To", t.To)
	form.Set("Body", body)
	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.AccountSID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.SetBasicAuth(t.AccountSID, t.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("twilio %d", resp.StatusCode)
	}
	return nil
}
