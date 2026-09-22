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

### API Keys
Long-lived keys for the CLI and CI. Send them like a JWT: `Authorization: Bearer tsk_...`.
They work on every authenticated route **except** the three below, which need a login session.

- `POST /api/v1/api-keys` - Create a key
  - Body: `{ "name": "ci-runner" }`
  - Response (201): `{ "id", "name", "prefix", "created_at", "key" }`. `key` is returned only here.
- `GET /api/v1/api-keys` - List active keys (never includes the key itself)
- `DELETE /api/v1/api-keys/:id` - Revoke a key (204)

### CLI / CI Upload
- `POST /api/v1/cli/scan-results` - Store a scan that ran in the CLI as a new completed scan
  - Body: `{ "target_id": "...", "pages_crawled": 12, "duration_sec": 90, "findings": [{ "title", "severity", "url", "parameter", "payload", "evidence", "owasp_category", "proof" }] }`
  - `target_id` must belong to the caller (404 otherwise). At most 10,000 findings per upload.
  - Response: `{ "message", "scan_id", "total_findings" }`
  - Client: `temren scan -t URL --upload --api-url URL --api-key tsk_... --target-id ID`
    (or env `TEMREN_API_URL` / `TEMREN_API_KEY` / `TEMREN_TARGET_ID`)

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
