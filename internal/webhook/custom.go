package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookEndpoint struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	URL         string    `json:"url"`
	Secret      string    `json:"-"`
	Events      []string  `json:"events"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Delivery struct {
	ID         string `json:"id"`
	EndpointID string `json:"endpoint_id"`
	Event      string `json:"event"`
	Payload    string `json:"payload"`
	StatusCode int    `json:"status_code"`
	Response   string `json:"response"`
	Duration   int    `json:"duration_ms"`
	Success    bool   `json:"success"`
	CreatedAt  time.Time `json:"created_at"`
}

type CustomWebhookManager struct {
	db         *sql.DB
	httpClient *http.Client
}

func NewCustomWebhookManager(db *sql.DB) *CustomWebhookManager {
	return &CustomWebhookManager{
		db: db,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (m *CustomWebhookManager) CreateEndpoint(endpoint *WebhookEndpoint) error {
	query := `
		INSERT INTO webhook_endpoints (id, user_id, url, secret, events, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	
	if endpoint.ID == "" {
		endpoint.ID = generateWebhookID()
	}
	if endpoint.CreatedAt.IsZero() {
		endpoint.CreatedAt = time.Now()
	}
	endpoint.UpdatedAt = time.Now()
	
	eventsJSON, _ := json.Marshal(endpoint.Events)
	
	_, err := m.db.Exec(query,
		endpoint.ID,
		endpoint.UserID,
		endpoint.URL,
		endpoint.Secret,
		eventsJSON,
		endpoint.Active,
		endpoint.CreatedAt,
		endpoint.UpdatedAt,
	)
	
	return err
}

func (m *CustomWebhookManager) GetEndpoint(id string) (*WebhookEndpoint, error) {
	query := `SELECT id, user_id, url, secret, events, active, created_at, updated_at FROM webhook_endpoints WHERE id = $1`
	
	row := m.db.QueryRow(query, id)
	endpoint := &WebhookEndpoint{}
	
	var eventsJSON []byte
	err := row.Scan(
		&endpoint.ID,
		&endpoint.UserID,
		&endpoint.URL,
		&endpoint.Secret,
		&eventsJSON,
		&endpoint.Active,
		&endpoint.CreatedAt,
		&endpoint.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("webhook not found")
		}
		return nil, err
	}
	
	json.Unmarshal(eventsJSON, &endpoint.Events)
	return endpoint, nil
}

func (m *CustomWebhookManager) ListEndpoints(userID string) ([]*WebhookEndpoint, error) {
	query := `SELECT id, user_id, url, secret, events, active, created_at, updated_at FROM webhook_endpoints WHERE user_id = $1`
	
	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var endpoints []*WebhookEndpoint
	
	for rows.Next() {
		endpoint := &WebhookEndpoint{}
		var eventsJSON []byte
		
		err := rows.Scan(
			&endpoint.ID,
			&endpoint.UserID,
			&endpoint.URL,
			&endpoint.Secret,
			&eventsJSON,
			&endpoint.Active,
			&endpoint.CreatedAt,
			&endpoint.UpdatedAt,
		)
		
		if err != nil {
			return nil, err
		}
		
		json.Unmarshal(eventsJSON, &endpoint.Events)
		endpoints = append(endpoints, endpoint)
	}
	
	return endpoints, rows.Err()
}

func (m *CustomWebhookManager) DeleteEndpoint(id string) error {
	query := `DELETE FROM webhook_endpoints WHERE id = $1`
	_, err := m.db.Exec(query, id)
	return err
}

func (m *CustomWebhookManager) UpdateEndpoint(endpoint *WebhookEndpoint) error {
	query := `
		UPDATE webhook_endpoints 
		SET url = $1, secret = $2, events = $3, active = $4, updated_at = $5
		WHERE id = $6
	`
	
	endpoint.UpdatedAt = time.Now()
	eventsJSON, _ := json.Marshal(endpoint.Events)
	
	_, err := m.db.Exec(query,
		endpoint.URL,
		endpoint.Secret,
		eventsJSON,
		endpoint.Active,
		endpoint.UpdatedAt,
		endpoint.ID,
	)
	
	return err
}

func (m *CustomWebhookManager) SendEvent(endpoint *WebhookEndpoint, event string, payload interface{}) (*Delivery, error) {
	if !endpoint.Active {
		return nil, fmt.Errorf("webhook is inactive")
	}

	delivery := &Delivery{
		ID:         generateDeliveryID(),
		EndpointID: endpoint.ID,
		Event:      event,
		CreatedAt:  time.Now(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	delivery.Payload = string(data)

	signature := m.generateSignature(data, endpoint.Secret)

	req, err := http.NewRequest("POST", endpoint.URL, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Temren-Event", event)
	req.Header.Set("X-Temren-Delivery", delivery.ID)
	req.Header.Set("X-Temren-Signature", signature)
	req.Header.Set("User-Agent", "Temren-Webhook/1.0")

	start := time.Now()
	resp, err := m.httpClient.Do(req)
	delivery.Duration = int(time.Since(start).Milliseconds())

	if err != nil {
		delivery.Success = false
		delivery.Response = err.Error()
		m.saveDelivery(delivery)
		return delivery, err
	}
	defer resp.Body.Close()

	delivery.StatusCode = resp.StatusCode
	delivery.Success = resp.StatusCode >= 200 && resp.StatusCode < 300

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	delivery.Response = buf.String()

	m.saveDelivery(delivery)

	return delivery, nil
}

func (m *CustomWebhookManager) generateSignature(payload []byte, secret string) string {
	if secret == "" {
		return ""
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func (m *CustomWebhookManager) saveDelivery(delivery *Delivery) {
	query := `
		INSERT INTO webhook_deliveries (id, endpoint_id, event, payload, status_code, response, duration, success, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	
	m.db.Exec(query,
		delivery.ID,
		delivery.EndpointID,
		delivery.Event,
		delivery.Payload,
		delivery.StatusCode,
		delivery.Response,
		delivery.Duration,
		delivery.Success,
		delivery.CreatedAt,
	)
}

func (m *CustomWebhookManager) GetDeliveries(endpointID string, limit int) ([]*Delivery, error) {
	query := `
		SELECT id, endpoint_id, event, payload, status_code, response, duration, success, created_at
		FROM webhook_deliveries
		WHERE endpoint_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	
	rows, err := m.db.Query(query, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var deliveries []*Delivery
	
	for rows.Next() {
		d := &Delivery{}
		err := rows.Scan(
			&d.ID,
			&d.EndpointID,
			&d.Event,
			&d.Payload,
			&d.StatusCode,
			&d.Response,
			&d.Duration,
			&d.Success,
			&d.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, d)
	}
	
	return deliveries, rows.Err()
}

func (m *CustomWebhookManager) TestEndpoint(endpoint *WebhookEndpoint) (*Delivery, error) {
	testPayload := map[string]interface{}{
		"test":    true,
		"message": "This is a test webhook from Temren",
		"timestamp": time.Now().Unix(),
	}
	
	return m.SendEvent(endpoint, "test", testPayload)
}

func InitSchema(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS webhook_endpoints (
		id VARCHAR(255) PRIMARY KEY,
		user_id VARCHAR(255) NOT NULL,
		url TEXT NOT NULL,
		secret TEXT,
		events JSONB,
		active BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS webhook_deliveries (
		id VARCHAR(255) PRIMARY KEY,
		endpoint_id VARCHAR(255) NOT NULL,
		event VARCHAR(100) NOT NULL,
		payload TEXT,
		status_code INTEGER,
		response TEXT,
		duration INTEGER,
		success BOOLEAN,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_user ON webhook_endpoints(user_id);
	CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id);
	`
	
	_, err := db.Exec(query)
	return err
}

func generateWebhookID() string {
	return fmt.Sprintf("wh_%d", time.Now().UnixNano())
}

func generateDeliveryID() string {
	return fmt.Sprintf("dlv_%d", time.Now().UnixNano())
}
