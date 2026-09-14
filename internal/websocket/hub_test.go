package websocket

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHubSingleton(t *testing.T) {
	hub1 := GetHub()
	hub2 := GetHub()
	
	assert.Equal(t, hub1, hub2)
	assert.NotNil(t, hub1)
}

func TestHubPublish(t *testing.T) {
	hub := GetHub()
	
	msg := &Message{
		Type:    "test",
		Topic:   "test-topic",
		Payload: map[string]string{"key": "value"},
		Time:    time.Now().Unix(),
	}
	
	hub.Publish("test-topic", msg.Payload)
	time.Sleep(100 * time.Millisecond)
}

func TestScanProgress(t *testing.T) {
	hub := GetHub()
	
	hub.PublishScanStarted("scan-123", "target-456")
	time.Sleep(50 * time.Millisecond)
	
	progress, ok := hub.GetScanProgress("scan-123")
	assert.True(t, ok)
	assert.Equal(t, "scan-123", progress.ScanID)
	assert.Equal(t, "started", progress.Status)
}

func TestScanProgressUpdate(t *testing.T) {
	hub := GetHub()
	
	hub.PublishScanProgress("scan-456", 50, 100, "https://example.com/page")
	time.Sleep(50 * time.Millisecond)
	
	progress, ok := hub.GetScanProgress("scan-456")
	assert.True(t, ok)
	assert.Equal(t, 50, progress.ScannedURLs)
	assert.Equal(t, 100, progress.TotalURLs)
	assert.Equal(t, "https://example.com/page", progress.CurrentURL)
}

func TestVulnerabilityFound(t *testing.T) {
	hub := GetHub()
	
	hub.PublishScanStarted("scan-789", "target-000")
	time.Sleep(50 * time.Millisecond)
	
	vuln := &VulnFound{
		Title:    "SQL Injection",
		Severity: "HIGH",
		URL:      "https://example.com/page?id=1",
	}
	
	hub.PublishVulnerabilityFound("scan-789", vuln)
	time.Sleep(50 * time.Millisecond)
	
	progress, ok := hub.GetScanProgress("scan-789")
	assert.True(t, ok)
	assert.Equal(t, 1, progress.Findings)
	assert.Len(t, progress.Vulnerabilities, 1)
}

func TestGenerateClientID(t *testing.T) {
	id1 := generateClientID()
	id2 := generateClientID()
	
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Contains(t, id1, "client_")
}

func TestClientTopics(t *testing.T) {
	hub := GetHub()
	client := &Client{
		ID:     "test-client",
		UserID: "user-123",
		hub:    hub,
		send:   make(chan []byte, 256),
		topics: make(map[string]bool),
	}
	
	hub.Subscribe(client, "scan:123")
	assert.True(t, client.topics["scan:123"])
	
	hub.Unsubscribe(client, "scan:123")
	assert.False(t, client.topics["scan:123"])
}
