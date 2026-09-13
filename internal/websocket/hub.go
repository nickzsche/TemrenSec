package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gofiber/contrib/websocket"
)

type Client struct {
	ID       string
	UserID   string
	conn     *websocket.Conn
	hub      *Hub
	send     chan []byte
	topics   map[string]bool
	mu       sync.RWMutex
}

type Message struct {
	Type    string      `json:"type"`
	Topic   string      `json:"topic,omitempty"`
	Payload interface{} `json:"payload"`
	Time    int64       `json:"time"`
}

type Hub struct {
	clients        map[*Client]bool
	broadcast      chan *Message
	register       chan *Client
	unregister     chan *Client
	topics         map[string]map[*Client]bool
	mu             sync.RWMutex
	scanProgress   map[string]*ScanProgress

	// instanceID identifies this Hub process — used to filter our own
	// messages off the cross-instance bridge so we don't echo them back
	// to local clients twice. Set on first GetHub() call.
	instanceID string

	// bridge is the optional cross-instance fan-out (Redis pub/sub etc.).
	// nil = single-process mode. Set via AttachBridge.
	bridgeMu sync.RWMutex
	bridge   Bridge
}

// Bridge fans broadcasts out across multiple Hub instances so that a
// WebSocket client connected to pod-A still sees scan progress messages
// emitted by pod-B. Implementations: NoopBridge (default), RedisBridge.
type Bridge interface {
	// Publish forwards a Message envelope to peer Hubs. Implementations
	// MUST be safe for concurrent use.
	Publish(env Envelope) error
	// Close releases any background goroutines/connections.
	Close() error
}

// Envelope wraps a Message with the originating instance ID so receivers
// can ignore their own emissions.
type Envelope struct {
	Origin  string   `json:"origin"`
	Message *Message `json:"message"`
}

type ScanProgress struct {
	ScanID       string   `json:"scan_id"`
	TargetID     string   `json:"target_id"`
	Status       string   `json:"status"`
	Progress     int      `json:"progress"`
	TotalURLs    int      `json:"total_urls"`
	ScannedURLs  int      `json:"scanned_urls"`
	Findings     int      `json:"findings"`
	CurrentURL   string   `json:"current_url,omitempty"`
	Message      string   `json:"message,omitempty"`
	Vulnerabilities []VulnFound `json:"vulnerabilities,omitempty"`
}

type VulnFound struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
}

var instance *Hub
var once sync.Once

func GetHub() *Hub {
	once.Do(func() {
		instance = &Hub{
			broadcast:    make(chan *Message),
			register:     make(chan *Client),
			unregister:   make(chan *Client),
			clients:      make(map[*Client]bool),
			topics:       make(map[string]map[*Client]bool),
			scanProgress: make(map[string]*ScanProgress),
			instanceID:   fmt.Sprintf("hub-%d", time.Now().UnixNano()),
		}
		go instance.run()
	})
	return instance
}

// AttachBridge wires a cross-instance Bridge. After attach, every local
// broadcast is also published to the Bridge, and incoming Bridge messages
// from other instances are injected into the local fan-out (without
// re-publishing them — that would loop forever).
func (h *Hub) AttachBridge(b Bridge) {
	h.bridgeMu.Lock()
	defer h.bridgeMu.Unlock()
	h.bridge = b
}

// InstanceID returns this Hub's process-unique ID. Used by bridges to
// filter out their own messages off the wire.
func (h *Hub) InstanceID() string {
	return h.instanceID
}

// InjectRemote takes a Message that came in over the Bridge and fans it
// out to local clients ONLY (does not re-publish). The Bridge calls this
// after filtering out envelopes whose Origin == h.instanceID.
func (h *Hub) InjectRemote(msg *Message) {
	if msg == nil {
		return
	}
	// A scan_update coming from a peer (e.g. the worker process) must also land
	// in this hub's progress map, so the REST /scans/:id/progress endpoint —
	// not just the live WS stream — reflects cross-process scans. Payload has
	// been through JSON, so round-trip it back into a ScanProgress.
	if msg.Type == "scan_update" && msg.Payload != nil {
		if raw, err := json.Marshal(msg.Payload); err == nil {
			var sp ScanProgress
			if json.Unmarshal(raw, &sp) == nil && sp.ScanID != "" {
				h.mu.Lock()
				h.scanProgress[sp.ScanID] = &sp
				h.mu.Unlock()
			}
		}
	}
	h.broadcastToTopic(msg)
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("[ws] client %s connected (total: %d)", client.ID, len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				
				for topic := range client.topics {
					if clients, ok := h.topics[topic]; ok {
						delete(clients, client)
						if len(clients) == 0 {
							delete(h.topics, topic)
						}
					}
				}
			}
			h.mu.Unlock()
			log.Printf("[ws] client %s disconnected (total: %d)", client.ID, len(h.clients))

		case message := <-h.broadcast:
			h.broadcastToTopic(message)
			h.fanoutToBridge(message)
		}
	}
}

func (h *Hub) fanoutToBridge(message *Message) {
	h.bridgeMu.RLock()
	b := h.bridge
	h.bridgeMu.RUnlock()
	if b == nil {
		return
	}
	// Best-effort: a bridge failure must not break the local hub. Log
	// would be noisy at scan-tick rate, so swallow silently — the bridge
	// itself is responsible for emitting failure metrics.
	_ = b.Publish(Envelope{Origin: h.instanceID, Message: message})
}

func (h *Hub) broadcastToTopic(message *Message) {
	h.mu.RLock()
	clients, ok := h.topics[message.Topic]
	h.mu.RUnlock()

	if !ok {
		return
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	for client := range clients {
		select {
		case client.send <- data:
		default:
			close(client.send)
			h.unregister <- client
		}
	}
}

func (h *Hub) Subscribe(client *Client, topic string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.topics[topic] == nil {
		h.topics[topic] = make(map[*Client]bool)
	}
	h.topics[topic][client] = true

	client.mu.Lock()
	client.topics[topic] = true
	client.mu.Unlock()
}

func (h *Hub) Unsubscribe(client *Client, topic string) {
	h.mu.Lock()
	if clients, ok := h.topics[topic]; ok {
		delete(clients, client)
		if len(clients) == 0 {
			delete(h.topics, topic)
		}
	}
	h.mu.Unlock()

	client.mu.Lock()
	delete(client.topics, topic)
	client.mu.Unlock()
}

func (h *Hub) Publish(topic string, payload interface{}) {
	msg := &Message{
		Type:    "broadcast",
		Topic:   topic,
		Payload: payload,
		Time:    time.Now().Unix(),
	}
	h.broadcast <- msg
}

func (h *Hub) PublishScanUpdate(scanID string, progress *ScanProgress) {
	h.mu.Lock()
	h.scanProgress[scanID] = progress
	h.mu.Unlock()

	topic := "scan:" + scanID
	msg := &Message{
		Type:    "scan_update",
		Topic:   topic,
		Payload: progress,
		Time:    time.Now().Unix(),
	}
	h.broadcast <- msg
}

func (h *Hub) PublishScanStarted(scanID, targetID string) {
	progress := &ScanProgress{
		ScanID:   scanID,
		TargetID: targetID,
		Status:   "started",
		Progress: 0,
	}
	h.PublishScanUpdate(scanID, progress)
}

func (h *Hub) PublishScanProgress(scanID string, scanned, total int, currentURL string) {
	h.mu.Lock()
	progress, ok := h.scanProgress[scanID]
	h.mu.Unlock()

	if !ok {
		progress = &ScanProgress{ScanID: scanID}
	}

	progress.ScannedURLs = scanned
	progress.TotalURLs = total
	progress.CurrentURL = currentURL
	progress.Status = "running"
	
	if total > 0 {
		progress.Progress = (scanned * 100) / total
	}

	h.PublishScanUpdate(scanID, progress)
}

func (h *Hub) PublishVulnerabilityFound(scanID string, vuln *VulnFound) {
	h.mu.Lock()
	progress, ok := h.scanProgress[scanID]
	h.mu.Unlock()

	if ok {
		progress.Findings++
		progress.Vulnerabilities = append(progress.Vulnerabilities, *vuln)
		h.PublishScanUpdate(scanID, progress)
	}
}

func (h *Hub) PublishScanCompleted(scanID string, findings int) {
	h.mu.Lock()
	progress, ok := h.scanProgress[scanID]
	h.mu.Unlock()

	if ok {
		progress.Status = "completed"
		progress.Progress = 100
		progress.Findings = findings
		h.PublishScanUpdate(scanID, progress)
	}

	time.AfterFunc(1*time.Hour, func() {
		h.mu.Lock()
		delete(h.scanProgress, scanID)
		h.mu.Unlock()
	})
}

func (h *Hub) GetScanProgress(scanID string) (*ScanProgress, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	progress, ok := h.scanProgress[scanID]
	return progress, ok
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[ws] error: %v", err)
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "subscribe":
			if msg.Topic != "" {
				c.hub.Subscribe(c, msg.Topic)
			}
		case "unsubscribe":
			if msg.Topic != "" {
				c.hub.Unsubscribe(c, msg.Topic)
			}
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.WriteMessage(websocket.TextMessage, message)

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func HandleWebSocket(hub *Hub) func(*websocket.Conn) {
	return func(c *websocket.Conn) {
		client := &Client{
			ID:     c.Query("client_id", generateClientID()),
			UserID: c.Locals("user_id").(string),
			hub:    hub,
			conn:   c,
			send:   make(chan []byte, 256),
			topics: make(map[string]bool),
		}

		hub.register <- client

		go client.writePump()
		client.readPump()
	}
}

func generateClientID() string {
	return fmt.Sprintf("client_%d", time.Now().UnixNano())
}
