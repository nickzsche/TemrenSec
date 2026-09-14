package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/temren/internal/config"
)

func SendAlert(to, subject, body string) error {
	cfg := config.AppConfig
	if cfg.SMTPHost == "" || cfg.SMTPUser == "" {
		return fmt.Errorf("smtp not configured")
	}

	from := cfg.SMTPFrom
	if from == "" {
		from = cfg.SMTPUser
	}

	msg := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=\"utf-8\"",
		"",
		body,
	}, "\r\n")

	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)

	conn, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if ok, _ := conn.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: cfg.SMTPHost}
		if err := conn.StartTLS(config); err != nil {
			return err
		}
	}

	if err := conn.Auth(auth); err != nil {
		return err
	}

	if err := conn.Mail(from); err != nil {
		return err
	}

	if err := conn.Rcpt(to); err != nil {
		return err
	}

	w, err := conn.Data()
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(w, msg)
	if err != nil {
		return err
	}

	return w.Close()
}

func SendCriticalAlert(to, targetURL string, criticalCount, highCount int) error {
	subject := fmt.Sprintf("[Temren] Critical Vulnerabilities Found - %s", targetURL)
	body := fmt.Sprintf(`
	<html>
	<body style="font-family: Arial, sans-serif; padding: 20px;">
		<div style="max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 8px;">
			<div style="background: #dc2626; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
				<h1>Security Alert</h1>
			</div>
			<div style="padding: 20px;">
				<p><strong>Target:</strong> %s</p>
				<p><strong>Critical:</strong> %d</p>
				<p><strong>High:</strong> %d</p>
				<p style="color: #dc2626; font-weight: bold;">
					Immediate action recommended!
				</p>
				<a href="#" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
					View Full Report
				</a>
			</div>
		</div>
	</body>
	</html>
	`, targetURL, criticalCount, highCount)

	return SendAlert(to, subject, body)
}
