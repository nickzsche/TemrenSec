<h1 align="center">TemrenSec</h1>

<p align="center">
  <strong>Open-Source OWASP Top 10 Security Scanner</strong>
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-15-black?logo=next.js&logoColor=white" alt="Next.js"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0-blue" alt="License"></a>
  <a href="https://owasp.org/Top10/"><img src="https://img.shields.io/badge/OWASP-Top%2010%202025-red" alt="OWASP"></a>
</p>

---

## What is TemrenSec?

**TemrenSec** is an open-source, self-hosted security vulnerability scanner that detects **OWASP Top 10** vulnerabilities in your web applications. Unlike expensive commercial tools, TemrenSec gives you full control with a modern dashboard, real-time monitoring, and enterprise-grade features — all for free.

### Why TemrenSec?

- **Free & Open Source** - No per-scan pricing, no API limits
- **89 Scanners** - SQL Injection, XSS, SSRF, IDOR, XXE, request smuggling, GraphQL, and more
- **WAF-Aware** - Detects and adapts to Cloudflare, Akamai, Imperva, AWS WAF (payload mutation + optional Tor identity rotation)
- **Real-time Dashboard** - Watch scans live via WebSocket
- **Integrations** - Jira, GitHub, GitLab, Slack, Discord, Email, and more
- **Scheduled Scans** - Automated recurring security checks
- **Self-hosted** - Your data stays on your infrastructure

---

## Features

### Vulnerability Detection

The unified registry (`pkg/scanner/registry.go`) ships **89 scanners**. A sample:

| Scanner | Description | Severity |
|---------|-------------|----------|
| SQL Injection | Error-based & time-based detection | Critical |
| XSS | Reflected, DOM-based, stored | High |
| Command Injection | OS command execution | Critical |
| SSRF | Server-Side Request Forgery (incl. cloud metadata) | High |
| IDOR | Insecure Direct Object Reference | High |
| Path Traversal | Directory traversal attacks | High |
| XXE | XML External Entity attacks | Critical |
| HTTP Request Smuggling | CL.TE / TE.CL / TE.TE | High |
| Auth Failures | Default credentials, JWT confusion, session fixation | High |
| Template Engine (YAML) | 46 built-in Nuclei-style detection templates | Varies |

### Dashboard & Monitoring

- **Real-time Scan Progress** - WebSocket-powered live updates (optional Redis pub/sub bridge for multi-replica HA)
- **Severity Analytics** - Interactive charts (Pie, Bar, Timeline)
- **Vulnerability Timeline** - Track security posture over time
- **CVSS 4.0 Scoring** - Automatic severity calculation
- **Security Score** - Overall health rating per target

### Integrations

| Platform | Feature | Status |
|----------|---------|--------|
| Jira | Auto-create tickets on findings | Ready |
| GitHub | Auto-create issues on findings | Ready |
| GitLab | Auto-create issues / MR notes | Ready |
| Slack | Instant notifications | Ready |
| Discord | Instant notifications | Ready |
| Email | HTML reports & alerts | Ready |
| Webhooks | HMAC-signed endpoint notifications | Ready |

### Enterprise Features

- **Scheduled Scans** - Cron-based automation (hourly, daily, weekly, monthly)
- **Plan-based Rate Limiting** - Configurable per-plan request ceilings
- **2FA Authentication** - TOTP support
- **Report Export** - SARIF, CycloneDX, JUnit, CSV, JSONL, Markdown, JIRA (PDF/HTML available via the API/report pipeline)
- **Prometheus Metrics** - Full observability
- **Kubernetes Ready** - Helm chart included
- **CI/CD Integration** - GitHub Action included

---

## Quick Start

### One-Line Install

```bash
# Clone & run with Docker Compose
git clone https://github.com/nickzsche/TemrenSec.git
cd TemrenSec
cp .env.example .env      # set JWT_SECRET and POSTGRES_PASSWORD
docker compose up -d
```

Visit `http://localhost:3000` and create your first scan.

### CLI

```bash
# Build CLI binary
go build -o temren ./cmd/temren

# Scan a target
./temren scan --target https://example.com --format json

# Deeper crawl, authenticated, JSON report to a file
./temren scan --target https://example.com --depth 3 --auth-token "$TOKEN" --output results.json --format json
```

Run `./temren scan --help` for the full flag list (rate limiting, proxies, Tor, headless, compliance filters, remediation, notifications, and more).

### API

```bash
# Register
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret","full_name":"User"}'

# Create target & scan
curl -X POST http://localhost:8080/api/v1/targets \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","url":"https://example.com"}'

curl -X POST http://localhost:8080/api/v1/targets/{id}/scans \
  -H "Authorization: Bearer <token>"
```

---

## Architecture

```
TemrenSec/
├── CLI         # Single binary scanner (cmd/temren)
├── API         # REST + WebSocket API server (cmd/api, Go + Fiber)
├── Worker      # Background job processor (cmd/worker, Asynq + Redis)
├── Frontend    # Next.js dashboard
└── Scanner     # 89 vulnerability detectors (pkg/scanner)
```

**Stack:** Go 1.26+ | Next.js 15 | PostgreSQL | Redis | Docker | Kubernetes

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.26, Fiber, pgx |
| Frontend | Next.js 15, React 19, Tailwind CSS, Recharts |
| Queue | Asynq (Redis-based) |
| Database | PostgreSQL 15 |
| Cache | Redis 7 |
| Auth | JWT + TOTP 2FA |
| Metrics | Prometheus |
| Deployment | Docker, Kubernetes, Helm |

---

## Roadmap

- [x] OWASP Top 10 2025 coverage (A01–A10, with 2021→2025 mapping for back-compat)
- [x] Real-time WebSocket updates with optional Redis pub/sub bridge for multi-replica HA (`TEMREN_WS_REDIS`)
- [x] WAF detection with payload mutation + Tor identity rotation on 3× consecutive 429s
- [x] Jira/GitHub/GitLab integration
- [x] Scheduled scans
- [x] SARIF / CycloneDX 1.6 / JUnit / CSV / JSONL / Markdown / JIRA export
- [x] CycloneDX 1.6 ML-BOM (`temren mlbom` / `GET /api/v1/mlbom`) — inventory of every AI provider/model the scanner can call
- [x] Custom scanner plugins (Lua via gopher-lua) with sandbox: dangerous globals stripped, 64 MB memory cap, 30 s ctx-deadline, no `io/os/debug/require`
- [x] Per-host adaptive rate limiting (`httpengine.Config.PerHostRate`)
- [x] Idempotent scan enqueue (`asynq.Unique` — same scan_id can't run twice within 6 h)
- [x] DefectDojo two-way sync
- [x] Scanner benchmark corpus (`benchmarks/accuracy/`)
- [x] Pluggable egress (`EgressProvider`: direct, rotating proxy list, Tor)
- [ ] Residential proxy provider integrations (Smartproxy / Bright Data)
- [ ] API key management
- [ ] SAML/SSO support
- [ ] Mobile app (React Native)

### Package layout notes

Two namespaces still ship side-by-side; the legacy ones are **deprecated** and
will be removed in **v2.0**:

| Use this | Don't use this | Why |
|---|---|---|
| `pkg/scanner` | ~~`pkg/scanners/active`, `pkg/scanners/passive`~~ | Unified 89-scanner registry, CVSS 4.0, single `Finding` type |
| `pkg/notify` | ~~`pkg/integration/notify`~~ | 13 channels behind one `Notifier` interface |

### Audit log semantics

The hash-chain audit log (`pkg/auditlog`) is **tamper-evident**, not
tamper-preventing. An attacker with database write access can rewrite the chain
end-to-end — but `temren audit-verify` will then fail at the first checkpoint
exported off-system (e.g. shipped to S3 Object Lock, an SIEM, or a WORM bucket).
For real prevention, pair TemrenSec with append-only storage:
`REVOKE DELETE, UPDATE ON audit_events FROM api_user` plus immutable log shipping.

---

## Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Quick dev setup
git clone https://github.com/nickzsche/TemrenSec.git
cd TemrenSec
go mod download
npm install --prefix frontend

# Run tests
go test ./...

# Start dev environment
docker compose -f docker-compose.dev.yml up
```

---

## Support

- **Issues**: [GitHub Issues](https://github.com/nickzsche/TemrenSec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/nickzsche/TemrenSec/discussions)

---

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built by <a href="https://github.com/nickzsche">nickzsche</a></strong>
  <br>
  <sub>Part of <a href="https://zerosixlab.com">ZerosixLab</a> security tools</sub>
</p>
