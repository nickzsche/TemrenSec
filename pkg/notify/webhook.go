package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"
)

// Webhook posts to a generic HTTP endpoint. If Template is set, it is rendered
// with the Event and posted as JSON; otherwise the Event itself is posted.
// If Secret is set, payload is signed with HMAC-SHA256 in the X-Temren-Signature header.
type Webhook struct {
	HTTP     *http.Client
	URL      string
	Secret   string
	Template string // optional Go text/template
}

func NewWebhook(url string) *Webhook {
	return &Webhook{HTTP: http.DefaultClient, URL: url}
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, e Event) error {
	var payload []byte
	if w.Template != "" {
		t, err := template.New("body").Parse(w.Template)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, e); err != nil {
			return err
		}
		payload = buf.Bytes()
	} else {
		var err error
		payload, err = json.Marshal(e)
		if err != nil {
			return err
		}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "temren/notify")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(payload)
		req.Header.Set("X-Temren-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %d", resp.StatusCode)
	}
	return nil
}
