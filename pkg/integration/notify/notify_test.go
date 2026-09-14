package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/scanner"
)

func TestCountSeverities(t *testing.T) {
	findings := []scanner.Finding{
		{Title: "A", Severity: scanner.SeverityCritical},
		{Title: "B", Severity: scanner.SeverityCritical},
		{Title: "C", Severity: scanner.SeverityHigh},
		{Title: "D", Severity: scanner.SeverityMedium},
		{Title: "E", Severity: scanner.SeverityLow},
		{Title: "F", Severity: scanner.SeverityInfo},
	}

	sc := CountSeverities(findings)

	if sc.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", sc.Critical)
	}
	if sc.High != 1 {
		t.Errorf("expected 1 high, got %d", sc.High)
	}
	if sc.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", sc.Medium)
	}
	if sc.Low != 1 {
		t.Errorf("expected 1 low, got %d", sc.Low)
	}
	if sc.Info != 1 {
		t.Errorf("expected 1 info, got %d", sc.Info)
	}
}

func TestTopCriticalHigh(t *testing.T) {
	findings := []scanner.Finding{
		{Title: "A", Severity: scanner.SeverityCritical},
		{Title: "B", Severity: scanner.SeverityHigh},
		{Title: "C", Severity: scanner.SeverityMedium},
		{Title: "D", Severity: scanner.SeverityCritical},
		{Title: "E", Severity: scanner.SeverityHigh},
		{Title: "F", Severity: scanner.SeverityLow},
	}

	top := TopCriticalHigh(findings, 3)

	if len(top) != 3 {
		t.Errorf("expected 3 top findings, got %d", len(top))
	}
	for _, f := range top {
		if f.Severity != scanner.SeverityCritical && f.Severity != scanner.SeverityHigh {
			t.Errorf("expected only critical/high, got %s", f.Severity)
		}
	}
}

func TestSlackNotifierSend(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(SlackConfig{WebhookURL: server.URL})

	result := ScanResult{
		Target:        "https://example.com",
		TotalFindings: 5,
		SeverityCount: SeverityCount{
			Critical: 1,
			High:     2,
			Medium:   1,
			Low:      1,
			Info:     0,
		},
		TopFindings: []scanner.Finding{
			{Title: "SQL Injection", Severity: scanner.SeverityCritical, URL: "https://example.com/api/users"},
			{Title: "XSS", Severity: scanner.SeverityHigh, URL: "https://example.com/search"},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	err := notifier.Send(context.Background(), result)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedPayload["username"] != "Temren Security Scanner" {
		t.Errorf("expected username 'Temren Security Scanner', got %v", receivedPayload["username"])
	}

	blocks, ok := receivedPayload["blocks"].([]interface{})
	if !ok {
		t.Fatal("expected blocks array in payload")
	}
	if len(blocks) == 0 {
		t.Error("expected non-empty blocks")
	}
}

func TestSlackNotifierCustomUsername(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(SlackConfig{
		WebhookURL: server.URL,
		Username:   "Custom Bot",
	})

	result := ScanResult{
		Target:        "https://example.com",
		TotalFindings: 1,
		SeverityCount: SeverityCount{Low: 1},
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	err := notifier.Send(context.Background(), result)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedPayload["username"] != "Custom Bot" {
		t.Errorf("expected username 'Custom Bot', got %v", receivedPayload["username"])
	}
}

func TestDiscordNotifierSend(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notifier := NewDiscordNotifier(DiscordConfig{WebhookURL: server.URL})

	result := ScanResult{
		Target:        "https://example.com",
		TotalFindings: 5,
		SeverityCount: SeverityCount{
			Critical: 1,
			High:     2,
			Medium:   1,
			Low:      1,
			Info:     0,
		},
		TopFindings: []scanner.Finding{
			{Title: "SQL Injection", Severity: scanner.SeverityCritical, URL: "https://example.com/api/users"},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	err := notifier.Send(context.Background(), result)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedPayload["username"] != "Temren Security Scanner" {
		t.Errorf("expected username, got %v", receivedPayload["username"])
	}

	embeds, ok := receivedPayload["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatal("expected embeds array in payload")
	}

	embed, ok := embeds[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected embed object")
	}

	if embed["color"] != float64(16711680) {
		t.Errorf("expected red color for critical, got %v", embed["color"])
	}
}

func TestDiscordSeverityColor(t *testing.T) {
	tests := []struct {
		sc       SeverityCount
		expected int
	}{
		{SeverityCount{Critical: 1}, 16711680},
		{SeverityCount{High: 1}, 16741632},
		{SeverityCount{Medium: 1}, 16776960},
		{SeverityCount{Low: 1}, 255},
		{SeverityCount{Info: 1}, 8421504},
		{SeverityCount{}, 8421504},
	}

	for _, tt := range tests {
		result := highestSeverityColor(tt.sc)
		if result != tt.expected {
			t.Errorf("highestSeverityColor(%+v) = %d, want %d", tt.sc, result, tt.expected)
		}
	}
}

func TestTeamsNotifierSend(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewTeamsNotifier(TeamsConfig{WebhookURL: server.URL})

	result := ScanResult{
		Target:        "https://example.com",
		TotalFindings: 5,
		SeverityCount: SeverityCount{
			Critical: 1,
			High:     2,
			Medium:   1,
			Low:      1,
			Info:     0,
		},
		TopFindings: []scanner.Finding{
			{Title: "SQL Injection", Severity: scanner.SeverityCritical, URL: "https://example.com/api/users"},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	err := notifier.Send(context.Background(), result)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedPayload["type"] != "message" {
		t.Errorf("expected type 'message', got %v", receivedPayload["type"])
	}

	attachments, ok := receivedPayload["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("expected attachments in payload")
	}

	attachment, ok := attachments[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected attachment object")
	}

	if attachment["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("expected adaptive card content type, got %v", attachment["contentType"])
	}
}

func TestSlackNotifierError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(SlackConfig{WebhookURL: server.URL})
	result := ScanResult{Target: "https://example.com", Timestamp: time.Now().Format(time.RFC3339)}

	err := notifier.Send(context.Background(), result)
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestDiscordNotifierError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier := NewDiscordNotifier(DiscordConfig{WebhookURL: server.URL})
	result := ScanResult{Target: "https://example.com", Timestamp: time.Now().Format(time.RFC3339)}

	err := notifier.Send(context.Background(), result)
	if err == nil {
		t.Error("expected error for 400 response, got nil")
	}
}

func TestTeamsNotifierError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := NewTeamsNotifier(TeamsConfig{WebhookURL: server.URL})
	result := ScanResult{Target: "https://example.com", Timestamp: time.Now().Format(time.RFC3339)}

	err := notifier.Send(context.Background(), result)
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestNotifierNames(t *testing.T) {
	slack := NewSlackNotifier(SlackConfig{WebhookURL: "http://localhost"})
	discord := NewDiscordNotifier(DiscordConfig{WebhookURL: "http://localhost"})
	teams := NewTeamsNotifier(TeamsConfig{WebhookURL: "http://localhost"})

	if slack.Name() != "slack" {
		t.Errorf("expected 'slack', got %s", slack.Name())
	}
	if discord.Name() != "discord" {
		t.Errorf("expected 'discord', got %s", discord.Name())
	}
	if teams.Name() != "teams" {
		t.Errorf("expected 'teams', got %s", teams.Name())
	}
}