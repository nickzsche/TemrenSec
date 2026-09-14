package notify

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Telegram delivers via Bot API. Token format "123:ABC" from BotFather.
type Telegram struct {
	HTTP   *http.Client
	Token  string
	ChatID string
}

func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{HTTP: http.DefaultClient, Token: token, ChatID: chatID}
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, e Event) error {
	text := fmt.Sprintf("*%s*\n_%s_\n\n%s\n\nURL: %s\nScanner: %s", e.Title, e.Severity, e.Description, e.URL, e.Scanner)
	form := url.Values{}
	form.Set("chat_id", t.ChatID)
	form.Set("text", text)
	form.Set("parse_mode", "Markdown")
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.Token)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram %d", resp.StatusCode)
	}
	return nil
}
