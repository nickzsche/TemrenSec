# TemrenSec — Detailed Technical Documentation

> This document explains end to end **what the project does, how it works, and
> which file carries which responsibility**. The goal: handed to another Claude
> session or a new developer, it should let them build a complete mental model
> without opening every file one by one.
>
> Repo: `github.com/nickzsche/TemrenSec` · Module: `github.com/temren` · Language: Go 1.26 + Next.js 15 (TypeScript)

---

## 1. What is this project?

**TemrenSec** is a self-hosted **DAST + ASPM** platform (Dynamic Application
Security Testing + Application Security Posture Management) focused on the OWASP
Top 10, built from **89 active scanners**, **35+ supporting packages**,
**3 binaries** (API, worker, CLI) and **a Next.js dashboard**.

In one line: **give it a URL and it produces hundreds of vulnerability checks,
compliance mappings, an AI summary, and a CI/CD-ready report.**

### Core capability families
1. **Active scanning** — detect SQLi/XSS/SSRF/SSTI/RCE/IDOR and more via HTTP requests
2. **Passive analysis** — TLS certificate, security headers, SPF/DMARC, missing SRI
3. **Supply chain** — lockfile + OSV.dev + CycloneDX SBOM
4. **Threat intelligence** — NVD CVE + EPSS + CISA KEV enrichment
5. **AI-assisted** — summarization, triage and prompt-injection scanning via Anthropic / OpenAI / Ollama
6. **Compliance** — PCI-DSS, HIPAA, GDPR, ISO 27001, SOC2, NIST CSF, CIS, ASVS mapping
7. **Output/export** — SARIF, CycloneDX, JUnit, CSV, Markdown, JIRA, JSONL
8. **CI/CD** — GitHub Action, GitLab MR, Jenkins, Azure DevOps; threshold + exit code
9. **Notifications** — 13 channels (Slack, Discord, Teams, Email, ntfy, Pushover, Telegram, PagerDuty, Opsgenie, Mattermost, Rocket.Chat, Twilio, Webhook)
10. **Operations** — workspaces, policy DSL, scan templates, audit log (hash-chain), triage rules, scan diff

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                                │
│  CLI (`temren`)   │   Web Dashboard (Next.js)   │   VSCode Extension │
└─────────────────────────────────────────────────────────────────────┘
                  │                  │                       │
                  └────────── HTTP/WebSocket ─────────────────┘
                                  │
┌─────────────────────────────────────────────────────────────────────┐
│  API (cmd/api)  — Fiber HTTP, JWT, rate-limit, WebSocket push      │
│   ├── internal/handler/routes.go       (auth + projects + scans)   │
│   └── internal/handler/v2_routes.go    (compliance, AI, intel...)  │
└─────────────────────────────────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌────────────────┐    ┌────────────────────┐    ┌──────────────────┐
│  Postgres      │    │  Redis + asynq     │    │  Worker          │
│  (pgx/v5)      │    │  (job queue)       │    │  (cmd/worker)    │
│  migrations/   │    │                    │    │  runs scans      │
└────────────────┘    └────────────────────┘    └──────────────────┘
                                                          │
                                  ┌───────────────────────┼──────────────────┐
                                  ▼                                          ▼
                       ┌─────────────────────┐                  ┌─────────────────────┐
                       │  pkg/scanner/*      │                  │  pkg/* support      │
                       │  89 scanners        │   ◀── registry ─▶│  compliance, AI,    │
                       │  registry.go        │                  │  exporter, notify…  │
                       └─────────────────────┘                  └─────────────────────┘
```

---

## 3. Directory Map (folder by folder)

### `/cmd` — Executable binaries

| Path | What it does |
|---|---|
| `cmd/api/main.go` | Fiber HTTP API. Wires v2 endpoints via `handler.RegisterV2()`; auto-selects an AI provider based on `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OLLAMA_MODEL`. |
| `cmd/worker/main.go` | asynq (Redis-backed) job worker. Pulls scan jobs from the queue, runs the `pkg/scanner` engine, writes results to the DB. |
| `cmd/temren/main.go` | Cobra-based CLI entry point. |
| `cmd/temren/cmd/*.go` | The CLI subcommands (full list in §6). |

### `/internal` — Code private to this module

| Path | What it does |
|---|---|
| `internal/config/` | Env / config loading. |
| `internal/database/` | pgx connection pool, migration runner, repository pattern (scan, target, project, vulnerability, user). |
| `internal/handler/routes.go` | Auth (register/login/2FA), project CRUD, target CRUD, scan start, webhook, JIRA/GitHub integrations. |
| `internal/handler/v2_routes.go` | v2 endpoints: `compliance/summary`, `intel/lookup`, `ai/chat`, `profiles`, `sbom`, `workspaces`, `policies/evaluate`, `triage`, `risk`, `scans/diff`, `honeypot`, `export/:format`, `notify/test`. Also hosts `ConfigureAI(provider)`. |
| `internal/handler/auth_handler.go` | JWT issue/verify, refresh token, TOTP 2FA. |
| `internal/handler/scan_handler.go` | Create scan → enqueue on asynq, return progress/results. |
| `internal/handler/cli_handler.go` | Persists scan results submitted by the CLI (`/api/cli/scan-results`). |
| `internal/queue/` | asynq client + handler types. |
| `internal/scheduler/` | gocron-based scheduled-scan manager. |
| `internal/middleware/` | JWT auth (`auth.go`), rate limiting per IP / per user (`ratelimit.go`), plan enforcement (`plans.go`), CORS. |
| `internal/websocket/` | Fiber WebSocket Hub — live scan progress broadcast, finding stream. |
| `internal/webhook/` | HMAC-SHA256-signed outbound webhook dispatcher. |
| `internal/email/` | SMTP (STARTTLS + implicit TLS) sending. |
| `internal/pdf/` | Findings PDF report via go-pdf/fpdf. |
| `internal/payloads/` | Embedded payload lists for scanners. |
| `internal/metrics/` | Prometheus collector registration and `/metrics` handler. |
| `internal/service/` | Domain service layer (scan orchestration, notification routing, etc.). |

### `/pkg` — Reusable packages (importable by external projects)

The table below gives a one-line summary of each package.

| Package | Responsibility |
|---|---|
| `pkg/scanner` | **Core.** 89 scanners, shared `Finding` type, `ScanEngine`, **`registry.go` (single source of truth)**, CVSS 4.0 calculator. |
| `pkg/scanners` | Legacy scanner namespace (kept for migration; deprecated). |
| `pkg/httpengine` | Rate-limited HTTP client, redirect control, custom user-agent, TLS-skip option. |
| `pkg/spider` | URL crawler (BFS, same-domain, max-depth, max-pages). |
| `pkg/ai` | **Provider abstraction.** `Anthropic`, `OpenAI`, `Ollama` (local). Finding summary, triage suggestion, chat. Default models are overridable via env. |
| `pkg/compliance` | Maps findings to **PCI-DSS / HIPAA / GDPR / ISO 27001 / SOC2 / NIST CSF / CIS / OWASP ASVS** controls; produces summaries. |
| `pkg/threatintel` | NVD CVE → CVSS, EPSS exploitability score, CISA KEV flag. Cache: `cve_cache` table. |
| `pkg/exporter` | SARIF 2.1.0, CycloneDX, JUnit XML, CSV, Markdown, JIRA-ready JSON, JSONL. |
| `pkg/sbom` | Lockfile (npm/Go/PyPI/RubyGems/Cargo/Composer) → CycloneDX SBOM. |
| `pkg/depscan` | Lockfile parse + OSV.dev cross-ref → vulnerable dependency list. |
| `pkg/policy` | **YAML policy DSL.** Expression evaluator (`severity == "critical" && cvss >= 9.0`); rule decision = `fail`/`warn`/`pass`. |
| `pkg/triage` | Dedup, suppress (regex / scanner / URL), re-rank, false-positive rule engine. |
| `pkg/risk` | Blended risk score = CVSS × EPSS × KEV × asset criticality × business context. |
| `pkg/scandiff` | Semantic diff between two scan JSONs: `added`/`fixed`/`regressed`/`improved`. |
| `pkg/profiles` | Curated scan profiles (`api-quick`, `full-owasp`, `pre-prod`, …). |
| `pkg/scantemplate` | YAML scan-template validate + pretty-print. |
| `pkg/workspace` | Multi-workspace (multi-tenant-like) separation, asset tagging. |
| `pkg/cookieaudit` | Cookie security attribute audit (Secure, HttpOnly, SameSite, Domain scope). |
| `pkg/honeypot` | Scores the probability a target is a honeypot (0–100). |
| `pkg/tlsaudit` | TLS handshake, cert chain, expiry, weak cipher, protocol downgrade. |
| `pkg/emailauth` | SPF, DMARC, DKIM record audit via DNS. |
| `pkg/secretsmgr` | Retrieves secrets via env / file / vault (vault shim). |
| `pkg/sandbox` | Subprocess sandbox: CPU/RAM/wall-clock limit, env scrub, cap-writer. |
| `pkg/llmscan` | For an LLM endpoint: prompt injection, system-prompt leak, jailbreak, output XSS tests. |
| `pkg/mcp` | Audits an MCP (Model Context Protocol) HTTP server for unauthenticated tools/resources. |
| `pkg/dnsenum` | Subdomain enumeration: DNS bruteforce + certificate-transparency logs. |
| `pkg/observability` | Structured logging (JSON), trace id, scan correlation id. |
| `pkg/replay` | Replays a recorded JSONL trace against a local HTTP server. |
| `pkg/proxy` | Recording HTTP/HTTPS forward proxy (each transaction → JSONL). |
| `pkg/wordlists` | Embedded directory / parameter / subdomain wordlists. |
| `pkg/openapi` | OpenAPI/Swagger spec parse → scannable operation list. |
| `pkg/auditlog` | **Hash-chain (SHA-256) audit log.** Each event includes the previous event's hash → tamper-evident. |
| `pkg/orchestrator` | Topologically ordered scan orchestration (`depends_on` graph). |
| `pkg/cloudscan` | Dockerfile, Kubernetes YAML, Terraform misconfiguration audit. |
| `pkg/server` | Embedded "laptop mode" HTTP server — dashboard that runs without Postgres/Redis. |
| `pkg/notify` | **13 notification channels.** All implement the `Notifier` interface. |
| `pkg/integration/github` | GitHub Issue create/update; PR comment; severity → label. |
| `pkg/integration/gitlab` | GitLab Issue + MR note; same pattern. |
| `pkg/integration/defectdojo` | DefectDojo finding push (engagement + product). |
| `pkg/integration/notify` | (Legacy) Slack/Discord/Teams shim — new code uses `pkg/notify`. |
| `pkg/auth` | JWT helpers, password hashing (bcrypt), TOTP. Also contains OIDC (`oidc.go`) and SAML (`saml.go`) helpers that are **implemented but not yet wired into the API** (SSO is on the roadmap). |
| `pkg/discovery` | Service discovery / asset inventory. |
| `pkg/wafbypass` | WAF detection + bypass payload mutations (encoding, case, comment injection). |
| `pkg/analyzer` | Finding post-processing: categorize, severity normalize. |
| `pkg/report` | Collects findings into a format-agnostic Report object. SARIF generator also here. |
| `pkg/remediation` | Finding → CWE-specific remediation text. |
| `pkg/collaboration` | (Embedded) simple comments, assignment, threads. |
| `pkg/plugin` | External scanner plugin loader (Lua + gopher-lua). |
| `pkg/scheduler` | (pkg-level) gocron wrapper. |
| `pkg/templates` | Nuclei-style YAML detection template engine + 46 built-in templates. |

### `/migrations` — Postgres schema

| File | Contents |
|---|---|
| `001_init.sql` | `users`, `refresh_tokens`, `projects`, `targets`, `scans`, `vulnerabilities`, `reports`, `scan_alerts`. |
| `002_schedules_webhooks.sql` | `schedules`, `webhook_endpoints`, `webhook_deliveries` (webhooks are stored as `webhook_endpoints`, not `webhooks`). |
| `003_workspaces_policies_audit.sql` | `workspaces`, `workspace_targets`, `policies`, `scan_templates`, `audit_events` (hash-chain), `notifications`, `asset_tags`, `triage_suppressions`, `cve_cache`, `plugins`. |
| `004_perf_indexes.sql` | Performance indexes. |
| `005_audit_grants.sql` | Grants that make the audit log append-only (`REVOKE UPDATE, DELETE`). |
| `006_integrations.sql` | `integrations` table (third-party integration config). |
| `007_notifications.sql` | Additional notification persistence. |

> Note: there is no dedicated `integrations` table in `001`; it is introduced in
> migration `006`. `001` also does not create a `webhooks` table — webhooks live
> in `webhook_endpoints` (migration `002`).

### `/frontend` — Next.js 15 dashboard (TypeScript + App Router)

Each page under `/frontend/src/app/dashboard/` is a feature:

| Page | Shows |
|---|---|
| `advisor/` | AI-assisted natural-language finding query/suggestion. |
| `ai-chat/` | Direct LLM provider chat (Anthropic/OpenAI/Ollama). |
| `assets/` | Asset inventory + tag management. |
| `attack-paths/` | Graph of findings (toxic combinations). |
| `audit-log/` | Hash-chain audit event timeline. |
| `compliance/` | PCI/HIPAA/ISO/SOC2 heatmap. |
| `diff/` | Semantic diff UI between two scans. |
| `kanban/` | Finding kanban board (open / triaged / fixed). |
| `live/` | Live scan progress over WebSocket. |
| `notifications/` | Notification center. |
| `plugins/` | Load/enable Lua plugins. |
| `policies/` | Policy DSL editor + dry-run. |
| `risk-heatmap/` | Asset × severity matrix. |
| `sbom/` | CycloneDX SBOM view + export. |
| `scans/` | Scan list + detail. |
| `schedules/` | Scheduled-scan management. |
| `settings/` | API key, provider, theme. |
| `targets/` | Target CRUD. |
| `team/` | Membership / roles. |
| `threat-intel/` | CVE search + EPSS/KEV info. |
| `vulnerabilities/` | Global view of all findings. |

`/frontend/src/lib/api.ts` → API client (fetch wrapper, JWT inject). It defaults
to the same-origin `/api/v1` path (served through the Next.js rewrite proxy to
`API_URL`) unless `NEXT_PUBLIC_API_URL` is set.
`/frontend/src/components/ui/` → minimal design system.

### Other directories

| Path | Contents |
|---|---|
| `action/` | GitHub Action wrapper (runs the CLI image; see `action/action.yml`). |
| `vscode-extension/` | VS Code extension (TypeScript). |
| `helm/temren/` | Helm chart. |
| `k8s/base/` | Raw Kubernetes manifests. |
| `deploy/systemd/` | systemd unit files for bare-metal api/worker installs. |
| `docker-compose.yml` / `.dev.yml` | Compose stack (api + worker + postgres + redis + frontend). |
| `examples/` | Example scan template, policy, GitHub Action workflow. |
| `docs/` | External documentation (architecture, runbook, deployment, …). |
| `specs/` | OpenAPI spec + protocol schemas. |

---

## 4. Data Flow — a Typical Scan Journey

```
1. User        →  POST /api/v1/targets/:id/scans  (handler/scan_handler.go)
2. handler     →  asynq.Enqueue("scan:run", {scan_id, profile})
3. cmd/worker  →  asynq handler  →  pkg/scanner.NewScanEngine(...)
4. scan engine →  spider.Crawl(target)  →  URL list
5. scanner.EnabledScanners(filter)  →  each URL × each scanner   (registry.go)
6. each scanner →  httpengine.Client.Do(...)   payload mutations (pkg/wafbypass)
7. pkg/analyzer →  dedupe, severity normalize
8. pkg/scanner.InferCVSS4Vector → CalculateCVSS4 → SeverityFromCVSS
9. pkg/triage   →  suppression / FP filter
10. pkg/risk    →  blended risk score
11. Persist     →  database.SaveScan + SaveVulnerabilities
12. Stream      →  websocket.Hub.Broadcast(scan_id, findings)
13. Notify      →  pkg/notify (per user channel)
14. Audit       →  pkg/auditlog (hash-chain SHA-256)
15. User        →  GET /api/v1/scans/:id  or  /api/v2/export/:format
```

---

## 5. Key Packages in Detail

### 5.1 `pkg/scanner/registry.go` — Single Source of Truth

All scanners are registered in **one slice**. To add a scanner:

1. Write `pkg/scanner/your_scanner.go`, implement the `Scanner` interface.
2. Add the `New<Name>()` constructor to `registry.go`'s `AllScanners()`.

`AllScanners()` and `EnabledScanners(filter []string)` are used by both the CLI
and the API. **There is no hardcoded scanner list in the CLI anymore.**

### 5.2 `pkg/scanner/scanner.go` — Shared Types

- `Severity`: `Critical | High | Medium | Low | Info`
- `Confidence`: `Certain | Firm | Tentative`
- `Finding`: `Scanner, Title, Severity, URL, Description, Evidence, Payload, OWASPCategory, CWE, CVSSScore, Timestamp, Tags, ...`
- `Scanner` interface: `Name() string` + `Scan(ctx, url, client) ([]Finding, error)`
- `ScanEngine`: concurrency-limited fan-out, URL × scanner cross-product.

### 5.3 `pkg/scanner/cvss.go` — CVSS 4.0

- `InferCVSS4Vector(finding) Vector` — infer a vector from the finding type.
- `CalculateCVSS4(vector) float64` — 0.0–10.0 score.
- `SeverityFromCVSS(score) Severity` — threshold mapping.

### 5.4 `pkg/ai/` — Provider Abstraction

```go
type Provider interface {
    Chat(ctx context.Context, msgs []Message, opts ChatOptions) (string, error)
    Name() string
}
```

`cmd/api/main.go` auto-selects from env:
- `ANTHROPIC_API_KEY` → Anthropic
- `OPENAI_API_KEY` → OpenAI
- `OLLAMA_MODEL` → Ollama
- Otherwise → AI features disabled (endpoints return 503).

Model names are overridable: `TEMREN_ANTHROPIC_MODEL`, `TEMREN_OPENAI_MODEL`,
`TEMREN_OLLAMA_MODEL`.

### 5.5 `pkg/notify/` — 13 Channels

Each file is a channel, all implement:

```go
type Notifier interface {
    Send(ctx context.Context, msg Message) error
    Name() string
}
```

Channels: **Slack, Discord, Teams, Email (SMTP+STARTTLS), ntfy, Pushover,
Telegram, PagerDuty, Opsgenie, Mattermost, Rocket.Chat, Twilio (SMS),
Webhook (HMAC-SHA256 signed).**

### 5.6 `pkg/policy/` — YAML DSL

```yaml
rules:
  - name: block-critical-prod
    when: "severity == 'critical' && env == 'prod'"
    decision: fail
  - name: warn-medium
    when: "severity == 'medium'"
    decision: warn
```

`Evaluator.Evaluate(findings, ctx)` → `Decision{Pass, Warn, Fail}` + matched
rules. The `temren policy` command produces a CI exit code.

### 5.7 `pkg/auditlog/` — Hash-Chain

```
event_n.hash = SHA256(event_n.payload || event_{n-1}.hash)
```

`temren audit-verify` validates the chain end to end. Tampering breaks the hash
and reports the line number. Append-only enforcement comes from migration
`005_audit_grants.sql` (`REVOKE UPDATE, DELETE`), not from application middleware.

### 5.8 `pkg/integration/github/` and `pkg/integration/gitlab/`

- Finding → Issue title `[Temren] [SEVERITY] Title`
- Update existing issue if present, otherwise create
- Severity → label (`security-critical`, `security-high`, …)
- PR/MR comment: severity-count table + Critical/High list
- Status-code tolerance: 2xx range (not only 201)

### 5.9 `pkg/sandbox/` — Subprocess Jail

- CPU time, RSS memory, wall-clock limit
- Env scrub: minimal `PATH` only when `Limits.Env` is empty
- Tolerates exit 141 (SIGPIPE)
- Cap-writer: bounds stdout/stderr size

---

## 6. CLI Commands (`temren`)

| Command | What it does |
|---|---|
| `temren scan --target URL` | Run all enabled scanners. |
| `temren ci --target URL --threshold high` | CI-optimized; exit 1 if findings exceed the threshold. SARIF/JSON/text. |
| `temren serve` | Embedded laptop dashboard (no Postgres/Redis). |
| `temren tui` | Terminal UI scan-profile picker. |
| `temren profile [name]` | Curated profile list/detail. |
| `temren template` | Validate scan-template YAML. |
| `temren schedule {create,list,run,enable,disable,delete}` | Scheduled scans. |
| `temren baseline` | Diff findings against a baseline; regression → non-zero exit. |
| `temren scan-diff` | Semantic diff between two scan JSONs. |
| `temren triage` | Dedup/suppress/rerank via triage rules. |
| `temren policy` | Evaluate a YAML policy. |
| `temren compliance` | PCI/HIPAA/GDPR/ISO/SOC2/NIST/CIS mapping report. |
| `temren risk` | Compute blended risk score. |
| `temren intel CVE-2024-XXXX` | NVD + EPSS + KEV enrichment. |
| `temren dep` | Lockfile dependency scan (OSV.dev). |
| `temren sbom` | Generate a CycloneDX SBOM. |
| `temren mlbom` | Generate a CycloneDX ML-BOM of AI providers/models. |
| `temren swagger` | Parse an OpenAPI spec → scannable operations. |
| `temren cloud` | Dockerfile / K8s YAML / Terraform misconfig. |
| `temren dns` | Subdomain enumeration. |
| `temren llm` | LLM endpoint security testing. |
| `temren mcp` | MCP server audit. |
| `temren honeypot` | Honeypot probability score. |
| `temren proxy` | Recording forward proxy. |
| `temren replay` | Replay a recorded JSONL trace. |
| `temren notify` | Notification channel smoke test. |
| `temren export` | Findings JSON → SARIF/CycloneDX/JUnit/CSV/MD/JIRA/JSONL. |
| `temren audit-verify` | Verify the hash-chain audit log. |
| `temren self-test` | Built-in vulnerable target + full-subsystem integration test. |
| `temren completion [shell]` | Shell completion script. |

---

## 7. HTTP API Surface

### v1 (auth + asset + scan; `internal/handler/routes.go`)

```
POST   /api/v1/auth/register
POST   /api/v1/auth/login           [rate-limited per IP]
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout          [auth required]
GET    /api/v1/auth/me
POST   /api/v1/auth/2fa/enable
POST   /api/v1/auth/2fa/verify

GET    /api/v1/dashboard

POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/:id
PUT    /api/v1/projects/:id
DELETE /api/v1/projects/:id

POST   /api/v1/targets
GET    /api/v1/projects/:projectId/targets
GET    /api/v1/targets/:id
PUT    /api/v1/targets/:id
DELETE /api/v1/targets/:id

POST   /api/v1/targets/:targetId/schedule
GET    /api/v1/targets/:targetId/schedule
DELETE /api/v1/targets/:targetId/schedule

POST   /api/v1/targets/:targetId/scans
GET    /api/v1/targets/:targetId/scans
GET    /api/v1/scans/:scanId
GET    /api/v1/scans/:scanId/progress
GET    /api/v1/scans/:scanId/vulnerabilities

GET    /api/v1/targets/:targetId/vulnerabilities
PATCH  /api/v1/vulnerabilities/:vulnId
GET    /api/v1/vulnerabilities/:vulnId

GET    /api/v1/webhooks
POST   /api/v1/webhooks
DELETE /api/v1/webhooks/:id
POST   /api/v1/webhooks/:id/test

POST   /api/v1/integrations/jira/configure
POST   /api/v1/integrations/jira/test
POST   /api/v1/integrations/github/configure
POST   /api/v1/integrations/github/test

POST   /api/v1/cli/scan-results       (CLI → API persist)

GET    /health
GET    /ws                            (WebSocket; live stream)
```

### v2 (`internal/handler/v2_routes.go`)

```
POST   /api/v2/compliance/summary
POST   /api/v2/intel/lookup
POST   /api/v2/ai/chat
GET    /api/v2/profiles
GET    /api/v2/sbom
GET    /api/v2/workspaces
POST   /api/v2/workspaces
POST   /api/v2/policies/evaluate
POST   /api/v2/triage
POST   /api/v2/risk
POST   /api/v2/scans/diff
GET    /api/v2/honeypot
POST   /api/v2/export/:format         (sarif|cyclonedx|junit|csv|md|jira|jsonl)
POST   /api/v2/notify/test
```

---

## 8. Configuration & Env

See `.env.example`. Important variables:

| Env | Purpose |
|---|---|
| `DATABASE_URL` | Postgres DSN |
| `REDIS_URL` | Redis (asynq) |
| `JWT_SECRET` | Token signing (required) |
| `JWT_EXPIRY` | Token lifetime (default `24h`) |
| `TEMREN_WS_REDIS` / `TEMREN_WS_REDIS_CHANNEL` | WebSocket pub/sub bridge for multi-process live progress |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OLLAMA_MODEL` | AI provider selection |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Email notifications |
| `WEBHOOK_SECRET` | Outbound webhook HMAC secret |
| `PORT` | API port (default `8080`) |
| `API_URL` / `NEXT_PUBLIC_WS_URL` | Frontend rewrite target / browser WebSocket endpoint |

---

## 9. Test Strategy

- **Unit:** `*_test.go` in each package.
- **Scanner pattern:** local `httptest.NewServer` + vulnerable handler + run scanner + assert findings.
- **Integration:** `pkg/integration/github`, `pkg/integration/gitlab` → mock GitHub/GitLab API (2xx tolerance, path-encoding differences).
- **Sandbox:** `TestCapWriterCaps` tolerates SIGPIPE exit 141; `TestEnvScrubbed` injects PATH only.
- **Timeout:** `TestScanner_Timeout` uses a 5-second `context.WithTimeout` budget.
- **TLS audit:** `AuditWithConfig()` allows `InsecureSkipVerify` in tests.

```bash
GOCACHE=/tmp/temren-gocache GOMODCACHE=/tmp/temren-gomodcache go test ./...
```

---

## 10. Deployment

### Docker Compose

```bash
docker compose up -d        # api + worker + postgres + redis + frontend
docker compose -f docker-compose.dev.yml up
```

### Kubernetes

```bash
kubectl apply -k k8s/base/
# or
helm dependency update helm/temren && helm install temren helm/temren \
  --set secrets.jwtSecret=$(openssl rand -hex 32) \
  --set postgresql.auth.password=$(openssl rand -hex 16)
```

### Single-binary laptop mode

```bash
temren serve --port 8080     # embedded dashboard, no DB, in-memory
```

### Use in CI

```yaml
# .github/workflows/security.yml
- uses: nickzsche/TemrenSec/action@v1
  with:
    target: https://app.example.com
    format: sarif
    output: temren.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: temren.sarif }
```

---

## 11. Security & Operations Notes

- **Outbound webhook:** HMAC-SHA256 signed (`X-Temren-Signature`), with a replay-protecting timestamp header.
- **JWT:** access token short-lived; refresh via a separate endpoint.
- **2FA:** TOTP, base64 QR code.
- **Rate limit:** per-IP on `/auth/login` and `/auth/register` — brute-force protection.
- **Audit log:** every destructive action is appended to the chain; verified with `temren audit-verify`. Append-only enforcement is at the database grant level (migration 005).
- **Secrets:** `pkg/secretsmgr` shim — env / file / external vault.
- **Sandbox:** plugin execution runs sandboxed (CPU/RAM/walltime limit + env scrub).
- **TLS:** the scanner performs its own TLS audit; tests may skip verification via `AuditWithConfig`.

---

## 12. Extension Guide

### Add a new scanner
1. `pkg/scanner/foo_scanner.go` — implement the `Scanner` interface.
2. Add `NewFooScanner()` to `AllScanners()` in `pkg/scanner/registry.go`.
3. (Optional) add its name to the `cmd/temren/cmd/ci.go` filter list.
4. The CLI, API and dashboard pick it up automatically.

### Add a new notification channel
1. `pkg/notify/foo.go` — `Notifier` interface.
2. Register it in the `pkg/notify/notify.go` factory.
3. Update the config YAML schema.

### Add a new export format
1. Add a case to `Export(format, findings)` in `pkg/exporter/exporter.go`.
2. The v2 route `/api/v2/export/:format` recognizes it.
3. `temren export -f <format>` recognizes it.

### Add a new compliance framework
1. `pkg/compliance/<framework>.go` — control → CWE / OWASP ID mapping table.
2. Register it in the `pkg/compliance/summary.go` framework registry.

### Add a new AI provider
1. `pkg/ai/<provider>.go` — `Provider` interface.
2. Add it to the env-based auto-wire block in `cmd/api/main.go`.

---

## 13. Known Limitations / Trade-offs

- **Active-scan ethics:** use only against systems you own or have explicit permission to test. SSRF/RCE payloads are designed to produce real findings.
- **AI provider optional:** without one, endpoints return 503.
- **Postgres + Redis required** for `cmd/api` and `cmd/worker` (not for `temren serve`, which is embedded).
- **Spider scope:** `same-domain` by default; subdomains are not followed unless widened.
- **WAF bypass:** detection + payload mutation, plus optional Tor identity rotation; it is not a full evasion suite.
- **SSO (OIDC/SAML):** helper code exists in `pkg/auth` but is not yet wired into the API.

---

## 14. Versioning & Release

- `CHANGELOG.md` — release notes.
- `.goreleaser.yaml` — multi-platform binaries (darwin/linux/windows × amd64/arm64) for CLI, api and worker.
- `Dockerfile` — multi-stage; `--target api|worker|cli` selects the image.
- `Makefile` — `make build / test / bench / lint / docker / release-snapshot`.

---

## 15. Referenced Standards & Resources

| Standard | Where |
|---|---|
| OWASP Top 10 (Web 2025) | `pkg/scanner` `OWASPCategory` field on each finding |
| OWASP API Security Top 10 | `pkg/scanner/api_security.go` |
| CVSS 4.0 | `pkg/scanner/cvss.go` |
| CWE | Finding `CWE` field |
| SARIF 2.1.0 | `pkg/exporter` + `pkg/report` |
| CycloneDX | `pkg/sbom`, `pkg/exporter` |
| NIST CSF / CIS / ISO 27001 / SOC2 / PCI-DSS / HIPAA / GDPR / OWASP ASVS | `pkg/compliance` |
| MITRE ATT&CK | `pkg/scanner` (attack-path mapping) |

---

## 16. Notes for a Claude Reviewing This Documentation

Critical points when reasoning about the project:

1. **`pkg/scanner/registry.go` is the single source of truth.** The CLI and API both read from it — a new scanner is registered in exactly one place.
2. **`internal/handler/v2_routes.go`** holds all v2 endpoints, wired from `cmd/api/main.go` via `handler.RegisterV2(app)`.
3. **AI providers are optional;** without env keys the module is disabled and returns 503, not an error.
4. **Hash-chain audit log** is tamper-evident; append-only enforcement is at the DB grant level.
5. **Active payloads are generated;** only use against authorized systems.
6. **3 binaries** — `temren` (CLI), `temren-api` (HTTP), `temren-worker` (asynq job runner). Same module, different `main`.
