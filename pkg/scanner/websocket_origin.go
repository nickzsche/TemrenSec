package scanner

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/temren/pkg/httpengine"
)

// WebSocketOriginScanner attempts a WebSocket upgrade from a foreign origin and
// flags servers that accept it without rejecting on Origin mismatch.
type WebSocketOriginScanner struct{}

func NewWebSocketOriginScanner() *WebSocketOriginScanner { return &WebSocketOriginScanner{} }

func (s *WebSocketOriginScanner) Name() string { return "WebSocket Origin Validation" }

func (s *WebSocketOriginScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	if !strings.HasPrefix(target, "http") {
		return nil, nil
	}
	wsURL := target
	wsURL = strings.Replace(wsURL, "http", "ws", 1) // marker only for reporting; we send via HTTP upgrade
	key := wsKey()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, nil
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return []Finding{{
			URL: wsURL, Title: "WebSocket Accepts Cross-Origin Upgrade",
			Description: "Server upgraded a WebSocket handshake when Origin was attacker-controlled. Cross-site WebSocket hijacking (CSWSH) is possible — pair with cookies for full account takeover.",
			Severity: SeverityHigh, Confidence: ConfidenceHigh, Scanner: s.Name(),
			Payload: "Origin: https://evil.example", Timestamp: time.Now(),
			OWASPCategory: "A05:2021-Security Misconfiguration", CVSSScore: 7.5,
		}}, nil
	}
	return nil, nil
}

func wsKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
