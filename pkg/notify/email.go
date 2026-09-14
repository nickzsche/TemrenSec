package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

// Email sends via SMTP. For Gmail / Office 365, use STARTTLS on port 587.
type Email struct {
	Host     string
	Port     int
	User     string
	Pass     string
	From     string
	To       []string
	UseTLS   bool
	StartTLS bool
}

func NewEmail(host string, port int, user, pass, from string, to []string) *Email {
	return &Email{Host: host, Port: port, User: user, Pass: pass, From: from, To: to, StartTLS: true}
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(ctx context.Context, ev Event) error {
	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)
	subject := fmt.Sprintf("[Temren %s] %s", ev.Severity, ev.Title)
	body := fmt.Sprintf(`From: %s
To: %s
Subject: %s
Content-Type: text/html; charset=UTF-8

<h2>%s</h2>
<p><strong>Severity:</strong> %s</p>
<p><strong>URL:</strong> <a href="%s">%s</a></p>
<p><strong>Scanner:</strong> %s</p>
<hr>
<p>%s</p>
`, e.From, strings.Join(e.To, ", "), subject, ev.Title, ev.Severity, ev.URL, ev.URL, ev.Scanner, ev.Description)

	auth := smtp.PlainAuth("", e.User, e.Pass, e.Host)
	if e.UseTLS {
		// implicit TLS — use crypto/tls dial
		tlsCfg := &tls.Config{ServerName: e.Host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
		defer conn.Close()
		c, err := smtp.NewClient(conn, e.Host)
		if err != nil {
			return err
		}
		defer c.Quit()
		if err := c.Auth(auth); err != nil {
			return err
		}
		if err := c.Mail(e.From); err != nil {
			return err
		}
		for _, to := range e.To {
			if err := c.Rcpt(to); err != nil {
				return err
			}
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		w.Write([]byte(body))
		return w.Close()
	}
	// STARTTLS path (default 587)
	return smtp.SendMail(addr, auth, e.From, e.To, []byte(body))
}
