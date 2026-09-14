// Package notify (legacy) routes findings to Slack/Discord/Teams.
//
// Deprecated: use github.com/temren/pkg/notify instead. The unified package
// supports 13 channels (Slack, Discord, Teams, Email, ntfy, Pushover, Telegram,
// PagerDuty, Opsgenie, Mattermost, Rocket.Chat, Twilio, generic HMAC-signed
// webhook) behind a single Notifier interface. Will be removed in v2.0.
package notify

import (
	"context"

	"github.com/temren/pkg/scanner"
)

type SeverityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ScanResult struct {
	Target        string            `json:"target"`
	TotalFindings int               `json:"total_findings"`
	SeverityCount SeverityCount     `json:"severity_count"`
	TopFindings   []scanner.Finding `json:"top_findings"`
	Timestamp     string            `json:"timestamp"`
}

type Notifier interface {
	Name() string
	Send(ctx context.Context, result ScanResult) error
}

func CountSeverities(findings []scanner.Finding) SeverityCount {
	var sc SeverityCount
	for _, f := range findings {
		switch f.Severity {
		case scanner.SeverityCritical:
			sc.Critical++
		case scanner.SeverityHigh:
			sc.High++
		case scanner.SeverityMedium:
			sc.Medium++
		case scanner.SeverityLow:
			sc.Low++
		case scanner.SeverityInfo:
			sc.Info++
		}
	}
	return sc
}

func TopCriticalHigh(findings []scanner.Finding, max int) []scanner.Finding {
	var result []scanner.Finding
	for _, f := range findings {
		if f.Severity == scanner.SeverityCritical || f.Severity == scanner.SeverityHigh {
			result = append(result, f)
			if len(result) >= max {
				break
			}
		}
	}
	return result
}