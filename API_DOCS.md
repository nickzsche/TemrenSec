# TemrenSec API Documentation

## New Endpoints

### WebSocket
- `GET /ws` - Real-time scan updates via WebSocket
  - Query params: `client_id`, `scan_id`
  - Subscribe: `{"type": "subscribe", "topic": "scan:{scanId}"}`
  - Unsubscribe: `{"type": "unsubscribe", "topic": "scan:{scanId}"}`

### Schedule Management
- `POST /api/v1/targets/:targetId/schedule` - Create scheduled scan
  - Body: `{ "cron_expr": "0 9 * * 1", "frequency": "weekly" }`
  - Response: `Schedule` object

- `GET /api/v1/targets/:targetId/schedule` - Get target schedule
  - Response: `{ "target_id": "...", "schedule": Schedule }`

- `DELETE /api/v1/targets/:targetId/schedule` - Delete schedule
  - Response: `{ "message": "schedule deleted" }`

### Scan Progress
- `GET /api/v1/scans/:scanId/progress` - Get scan progress
  - Response: `ScanProgress` object with `progress`, `status`, `scanned_urls`, etc.

### Vulnerability Detail
- `GET /api/v1/vulnerabilities/:vulnId` - Get vulnerability details
  - Response: `Vulnerability` object with full details

### Webhooks
- `GET /api/v1/webhooks` - List custom webhooks
  - Response: `{ "webhooks": [...] }`

- `POST /api/v1/webhooks` - Create custom webhook
  - Body: `{ "url": "https://...", "secret": "...", "events": ["scan.complete"] }`
  - Response: `WebhookEndpoint` object

- `DELETE /api/v1/webhooks/:id` - Delete webhook
  - Response: `{ "message": "webhook deleted" }`

- `POST /api/v1/webhooks/:id/test` - Test webhook
  - Response: `{ "message": "webhook test sent", "status": "success" }`

### Integrations

#### Jira
- `POST /api/v1/integrations/jira/configure` - Configure Jira integration
  - Body: `{ "base_url": "...", "username": "...", "api_token": "...", "project": "PROJ" }`
  - Response: `{ "connected": true, "message": "..." }`

- `POST /api/v1/integrations/jira/test` - Test Jira connection
  - Response: `{ "status": "ok" }`

#### GitHub
- `POST /api/v1/integrations/github/configure` - Configure GitHub integration
  - Body: `{ "token": "ghp_...", "owner": "user", "repository": "repo" }`
  - Response: `{ "connected": true, "message": "..." }`

- `POST /api/v1/integrations/github/test` - Test GitHub connection
  - Response: `{ "status": "ok" }`

## WebSocket Events

### Scan Update
```json
{
  "type": "scan_update",
  "topic": "scan:123",
  "payload": {
    "scan_id": "123",
    "status": "running",
    "progress": 45,
    "scanned_urls": 45,
    "total_urls": 100,
    "findings": 2,
    "current_url": "https://example.com/page",
    "vulnerabilities": [
      { "title": "SQL Injection", "severity": "HIGH", "url": "..." }
    ]
  },
  "time": 1234567890
}
```

## New Modules

### WAF Bypass
- Supports: Cloudflare, Akamai, Imperva, AWS WAF
- URL mutation strategies: Path encoding, Case tampering, Comment injection, Double encoding

### Scheduler
- Cron expression support
- Frequencies: hourly, daily, weekly, monthly
- PostgreSQL storage with next_run tracking

### Worker Pool
- Asynq-based with concurrency control
- Multiple queues: critical, scans, default
- Dead letter queue support
- Metrics collection

### Email Service
- Templates: Scan Complete, Vulnerability Alert, Welcome, Password Reset, Weekly Report
- HTML email with inline styles

### Custom Webhooks
- HMAC SHA256 signature verification
- Delivery logging
- Retry logic
- Event filtering
