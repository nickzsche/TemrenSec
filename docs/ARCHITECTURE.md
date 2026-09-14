# Temren Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         Frontend (Next.js 15)                      │
│  Dashboard · Scans · Compliance · Threat Intel · AI · Heatmap …    │
└──────────────┬─────────────────────────────────────────────┬───────┘
               │ REST / WebSocket                            │
┌──────────────▼─────────────────────────────────────────────▼───────┐
│                       API (Fiber)  — cmd/api                       │
│  Auth (JWT / OIDC / SAML) · Rate limits · Routing · WS hub         │
└──────────────┬─────────────────────────────────────────────┬───────┘
               │                                              │
               │ Asynq queue (Redis)                          │ pgx
┌──────────────▼─────────────────────────┐    ┌───────────────▼──────┐
│           Worker (cmd/worker)          │    │  PostgreSQL          │
│  pulls scan jobs, runs scanners        │    │  scans / findings    │
└──────────────┬─────────────────────────┘    │  schedules / users   │
               │                              │  audit log           │
               │                              └──────────────────────┘
┌──────────────▼─────────────────────────────────────────────────────┐
│                    Scanner engine (pkg/scanner)                    │
│  ┌────────────┐ ┌─────────────┐ ┌──────────────────┐               │
│  │ Active     │ │ Passive     │ │ Cloud / IaC      │               │
│  │ scanners   │ │ analyzers   │ │ (pkg/cloudscan)  │               │
│  └────────────┘ └─────────────┘ └──────────────────┘               │
└──────────────┬─────────────────────────────────────────────────────┘
               │ Finding
┌──────────────▼─────────────────────────────────────────────────────┐
│                       Enrichment & output                          │
│  pkg/threatintel  →  CVE / EPSS / KEV                              │
│  pkg/compliance   →  framework mapping                             │
│  pkg/ai           →  triage, chains, exec summary                  │
│  pkg/exporter     →  SARIF · CycloneDX · JUnit · JSONL · …         │
│  pkg/notify       →  Slack / ntfy / PagerDuty / SMS / …            │
└────────────────────────────────────────────────────────────────────┘
```

## Data flow for a scan

1. User issues `POST /scans` (web UI or CLI).
2. API enqueues an Asynq job and returns scan ID.
3. Worker drains the queue, instantiates a `httpengine.Client`, and runs every enabled scanner.
4. Each `Finding` is written to Postgres and broadcast over the WebSocket hub.
5. Enrichment runs asynchronously: CVE lookup, AI triage, compliance mapping.
6. Configured notification channels fire for findings above the per-channel severity floor.

## Scaling

- API and Worker are stateless — scale horizontally behind a load balancer.
- Asynq's Redis backplane absorbs bursty job queues.
- Worker concurrency tunable via `WORKER_CONCURRENCY`.
- For multi-tenant deployments, run separate worker pools and Postgres schemas per tenant.

## Extension points

| What | Where | Interface |
|------|-------|-----------|
| New active scanner | `pkg/scanner/*.go` | `scanner.Scanner` |
| New cloud check | `pkg/cloudscan/*.go` | `cloudscan.New` walker |
| Notification channel | `pkg/notify/*.go` | `notify.Channel` |
| LLM provider | `pkg/ai/*.go` | `ai.Provider` |
| Export format | `pkg/exporter/*.go` | exported funcs |
| Lua plugin | `pkg/plugin/scripts/*.lua` | `Scan(target)` entrypoint |
