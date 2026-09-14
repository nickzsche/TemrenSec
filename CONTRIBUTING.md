# Contributing to TemrenSec

Thanks for your interest! Temren welcomes contributions of every size — new scanners,
bug fixes, documentation, and UX polish.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Quick start

```bash
git clone https://github.com/nickzsche/TemrenSec
cd TemrenSec
make all                       # lint + test + build
./bin/temren scan --target https://example.com
```

You will need:
- Go 1.26+
- Node 20+ (for the dashboard; CI uses Node 24)
- Docker & Docker Compose (for end-to-end tests against vulnerable demo apps)
- golangci-lint v2 (`make lint`)

## Project layout

```
cmd/temren        CLI entry points (cobra subcommands)
cmd/api          REST + WebSocket API server
cmd/worker       Background scan worker
pkg/scanner      Active vulnerability scanners + registry.go (single source of truth)
pkg/templates    Nuclei-style YAML template engine and built-in templates
pkg/cloudscan    Static analysis for Dockerfile / K8s / Terraform
pkg/notify       Notification channels (Slack, ntfy, PagerDuty, …)
pkg/exporter     Output formats (SARIF, CycloneDX, JUnit, JIRA, …)
pkg/compliance   PCI-DSS / HIPAA / GDPR / ISO 27001 / SOC2 mappings
pkg/threatintel  NVD / EPSS / CISA-KEV enrichment
pkg/ai           LLM-backed triage and exploit-chain analysis
frontend         Next.js 15 dashboard
```

## Adding a new scanner

1. Create `pkg/scanner/myscanner.go` implementing the `scanner.Scanner` interface:

   ```go
   type Scanner interface {
       Name() string
       Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error)
   }
   ```

2. Return `Finding` values with at least `Title`, `Severity`, `Confidence`, `Scanner`, and `OWASPCategory`.
3. Tag the OWASP category from the [Top 10 2025 list](https://owasp.org/Top10/) (`A01`–`A10`) so compliance mapping works.
4. Add tests at `pkg/scanner/myscanner_test.go` using `httptest` to stub the target.
5. Register the scanner in `pkg/scanner/registry.go` (`AllScanners()`). The CLI, API and worker all read from that list — there is no second place to register.

Prefer a YAML template (`pkg/templates/builtin/`, see [docs/TEMPLATES.md](docs/TEMPLATES.md)) when the check is a simple request + matcher; write Go only when you need timing, stateful probing or payload mutation.

## Style

- `gofmt -s` everything; `goimports` keeps imports tidy
- Package names: lowercase, no underscores
- Public types/funcs need doc comments
- Tests live alongside production code, named `*_test.go`
- Prefer table-driven tests for new payload sets
- Frontend: `npm run lint` and `npx tsc --noEmit` must pass

## Commits

We follow Conventional Commits (loose form). Examples:

- `feat(scanner): add NoSQL operator injection probes`
- `fix(notify): respect HTTP timeout on Telegram errors`
- `docs: expand contributing guide`

## Pull requests

- Open against `main`
- All CI checks must pass (build, test, lint, frontend, gosec, govulncheck)
- Cover new code with tests; aim ≥80% on touched files
- Update CHANGELOG.md under `## [Unreleased]`
- Fill in the pull request template

## Security disclosures

If you discover a vulnerability **in Temren itself**, please email
`security@zerosixlab.com` — do not file a public issue. See [SECURITY.md](SECURITY.md).
