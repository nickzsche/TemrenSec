# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

TemrenSec is a self-hosted OWASP Top 10 web vulnerability scanner: a Go CLI (`temren`), a Fiber REST/WebSocket API, an Asynq worker, and a Next.js dashboard. Go module path is `github.com/temren` (not the GitHub repo path).

## Commands

```bash
make build                 # bin/temren, bin/temren-api, bin/temren-worker
make test                  # go test -race -timeout=180s ./...
make lint                  # golangci-lint v2 (.golangci.yml: govet, staticcheck SA*, ineffassign, unconvert, misspell, gofmt)
make vet / make fmt        # go vet / gofmt -s -w .
make bench BENCH=<regex>   # micro-benchmarks in ./pkg/...

# Single test / package
go test -race -run TestWebCacheDeception_NoFPOnSPACatchAll ./pkg/scanner/

# Frontend (frontend/) — CI runs all four
make frontend              # npm ci
make frontend-typecheck    # npx tsc --noEmit
make frontend-lint         # eslint
make frontend-build        # next build

# Full stack
cp .env.example .env       # JWT_SECRET is required; API refuses to start without it
docker compose up -d       # or: make compose-dev
```

The Makefile sets `GOCACHE`/`GOMODCACHE` to `.gocache`/`.gomodcache` inside the repo. CI runs tests with Postgres 15 + Redis 7 services (`DATABASE_URL`, `REDIS_URL`); most `pkg/` tests are self-contained `httptest` fixtures.

Accuracy benchmark against a real vulnerable app (Juice Shop v15.0.0, ground truth in `benchmarks/accuracy/juice-shop/ground_truth.yaml`):
```bash
cd benchmarks/accuracy/juice-shop && docker compose up -d
cd ../runner && go run . --target http://localhost:3000 --truth ../juice-shop/ground_truth.yaml
```

## Architecture

**Three binaries, one scanner engine.**
- `cmd/temren` — cobra CLI (`cmd/temren/cmd/*.go`, one file per subcommand). `temren scan` runs scanners in-process; `temren serve` uses the lightweight embedded dashboard in `pkg/server` (go:embed, in-memory store) — not the Next.js app.
- `cmd/api` — Fiber server. Connects Postgres, runs embedded migrations (`migrations/*.sql` via `migrations/embed.go`, applied in filename order by `internal/database/migrate.go`), mounts `internal/handler.SetupRoutes` + `RegisterV2` (both under `/api/v1`, all v2 routes behind `middleware.AuthRequired()`). AI provider is picked from env: first of `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `OLLAMA_MODEL` wins.
- `cmd/worker` — drains Asynq jobs (`internal/queue/worker.go`): spider → optional passive analysis → active scanners → Lua plugins → persist findings.

**Scan flow:** API enqueues an Asynq job (idempotent per scan_id) → worker runs `scanner.NewScanEngine(client, scanners, concurrency).RunAll(...)` → findings go to Postgres and are broadcast on the WebSocket hub (`internal/websocket`). The worker is a separate process with no WS clients, so live progress reaches the browser only via the Redis pub/sub bridge (`TEMREN_WS_REDIS`); without it the dashboard's live view stays empty.

**`internal/` vs `pkg/`:** `internal/` is the server app (config, database repos, handlers, services, middleware, queue, scheduler, websocket). `pkg/` holds the reusable engine and features (scanner, httpengine, templates, spider, exporter, notify, ai, compliance, threatintel, plugin, …) used by both the CLI and the server.

### Scanners (`pkg/scanner`)
- `registry.go` `AllScanners()` is the **single source of truth**; the CLI and worker both read it (`EnabledScanners(names)` narrows it). Adding a scanner = implement `Scanner{Name(); Scan(ctx, target, *httpengine.Client)}` and add it to `AllScanners()` — nowhere else. The scanner count (currently 89) also appears in README and the frontend landing/onboarding copy; keep those in sync when it changes.
- Scanners emit the **2021** OWASP tag in `Finding.OWASPCategory`; `ScanEngine` fills `OWASPCategory2025` afterwards (`owasp.go`). Don't set the 2025 field in scanners.
- `proof.go` is a deterministic verification layer that re-checks findings with an independent request and sets `Verified`/`Proof`.
- All HTTP goes through `pkg/httpengine.Client` (rate limiting, per-host rate, WAF-aware mutation, egress providers: direct/proxy/Tor, headless via chromedp).
- Simple request+matcher checks belong in YAML templates (`pkg/templates/builtin/*.yaml`, Nuclei-style, engine in `pkg/templates/engine.go`, see `docs/TEMPLATES.md`); write Go only for timing, stateful probing, or payload mutation.
- Lua plugins (`pkg/plugin`) run sandboxed via gopher-lua.

### False-positive discipline
Much recent work is removing false positives found by the Juice Shop benchmark. The recurring pattern: SPAs and soft-404 servers return the same 200 HTML shell for every path, so a check must compare against a **control request** (random/nonexistent path) before reporting. Each fix ships with a `*_fp_test.go` / `fp_guard_test.go` style test using an `httptest` server that returns a catch-all 200, asserting zero findings, plus a positive test proving the real case still fires.

### Deprecated namespaces (removal planned for v2.0)
Use `pkg/scanner`, not `pkg/scanners/active|passive`; use `pkg/notify`, not `pkg/integration/notify`.

### Frontend (`frontend/`)
Next.js App Router (package.json pins Next 16 / React 19, although docs say 15), Tailwind, Recharts. `src/lib/api.ts` is the API client; it calls `/api/v1` through the `next.config.js` rewrite to `API_URL` unless `NEXT_PUBLIC_API_URL` is set. JWT is stored in `localStorage` (`temren_token`). Dashboard pages live under `src/app/dashboard/*`.

## Conventions
- Conventional Commits (`feat(scanner): …`, `fix(notify): …`); recent commit messages in this repo are written in Turkish. Template remediation/description strings are also Turkish.
- Tests sit next to code (`*_test.go`), table-driven for payload sets, `httptest` to stub targets.
- PRs update `CHANGELOG.md` under `## [Unreleased]`.
- `pkg/tlsaudit` intentionally uses deprecated TLS constants (SA1019 is excluded there).
- The audit log (`pkg/auditlog`) is a hash chain: tamper-evident, not tamper-proof.
