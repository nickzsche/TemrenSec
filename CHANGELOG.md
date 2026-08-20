# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — launch readiness

Everything in this section was found by running the stack end-to-end against a
real Postgres, Redis and a deliberately-vulnerable local test app. Most of it
had never been exercised before.

- **The documented quickstart could not start.** A weak default JWT secret
  combined with `ENVIRONMENT=production` made the API exit on boot; nothing
  ever applied the migrations; and the rate limiter passed a `redis://` URL
  where go-redis wanted `host:port`, so login and register returned 500.
- **`migrations/004_perf_indexes.sql` was invalid.** A partial index predicate
  used `NOW()`, which Postgres rejects as non-IMMUTABLE. The file had never
  been executed, so nobody had hit it.
- **`PUT /targets/:id` returned 500** when `scan_settings` was omitted: the
  empty string was written into a `jsonb` column.
- **The dashboard fabricated a severity trend.** With no timeline from the API
  — which is always, until a target is scanned on more than one day — it drew a
  hardcoded week of invented critical/high/medium counts. Now shows an empty
  state.
- **Scanner false positives.** Several detectors matched markers contained in
  their own payloads, so any endpoint that reflected input produced Critical
  findings:
  - SSTI reported on any page containing the string `49`, or any HTTP 500
  - `{{config.SECRET_KEY}}` matched on the marker `SECRET_KEY`
  - SSI matched `document_name`, part of its own `<!--#echo -->` directive
  - Prototype pollution matched `__proto__`, part of its own payload
  - SSRF matched `computeMetadata`, part of its own payload, and treated *any*
    non-empty response to a `file://` payload as confirmed
  - Dev-tool probes appended absolute paths to a URL that already had a query
    string, producing `/search?q=x/__cypress/` and matching their own input

  All now go through `MarkerIsEvaluated`, which requires the marker to survive
  with the reflected payload removed and to be absent from the baseline
  response. Against the test fixture this took critical findings from 5 to 1
  and high from 12 to 2 — leaving exactly the three bugs that were planted.
- **Counts and badges corrected.** The project advertised "26+", "36+" and
  "76" scanners across the README, landing page and onboarding, and an OWASP
  Top 10 **2025** badge over a mapping that is entirely 2021.

### Added

- `docs/LAUNCH.md` — Product Hunt copy, gallery order, and the commands that
  verify each claim in it
- `docs/screenshots/` — real captures of the dashboard, taken against an actual
  scan rather than mocked


### Added

- **13 new active scanners**
  - HTTP Request Smuggling (CL.TE / TE.CL / TE.TE-obf)
  - Web Cache Poisoning (unkeyed header reflection)
  - Race Condition (TOCTOU smell via concurrent identical requests)
  - Mass Assignment / BOLA probes
  - LDAP Injection
  - XPath Injection
  - Insecure Deserialization (Java / PHP / Python / Ruby / .NET magic bytes)
  - OAuth / OIDC Discovery misconfiguration (alg=none, missing PKCE, implicit flow)
  - CORS Preflight (wildcard+credentials, null origin, reflected origin)
  - GraphQL Batching & Alias overloading
  - SSRF — Cloud Metadata (AWS / GCP / Azure / Alibaba / OpenStack)
  - Host Header Injection (password-reset poisoning)
  - Security Headers audit (HSTS, CSP, XFO, RP, PP, COOP, CORP, cookie flags)
  - SSTI engine fingerprinting (Jinja2 / Twig / FreeMarker / ERB / Spring EL)
  - Web Cache Deception
  - Exposed Sensitive Endpoints (.git, .env, actuator, pprof, etc.)

- **`pkg/cloudscan`** — offline Dockerfile / Kubernetes / Terraform / .env audit
- **`pkg/compliance`** — PCI-DSS 4.0 / HIPAA / GDPR / ISO 27001:2022 / SOC 2 / NIST CSF 2.0 / CIS Controls v8 / OWASP ASVS 5.0 mapping with executive summaries
- **`pkg/threatintel`** — NVD CVE lookup, EPSS exploit probability, CISA KEV flagging, blended prioritization score
- **`pkg/notify`** — unified dispatcher with ntfy / Pushover / Telegram / PagerDuty / OpsGenie / Mattermost / RocketChat / Twilio SMS / signed generic webhook
- **`pkg/exporter`** — SARIF v2.1, CycloneDX 1.5, JUnit, CSV, JSONL, Markdown, JIRA wiki markup
- **`pkg/ai`** — pluggable LLM provider for finding triage, exploit-chain reasoning, natural-language → scan-query translation, executive summary
- **CLI subcommands** — `temren cloud`, `temren export`, `temren compliance`, `temren intel`, `temren baseline`, `temren notify`, `temren tui`, `temren completion`
- **Frontend pages** — Compliance, Threat Intel, AI Advisor, Asset Inventory, Risk Heatmap, Attack Paths, Notifications, Team, Audit Log, Settings (API keys, integrations, profile)
- **CI / DevEx** — Makefile, `.golangci.yml`, security workflow (gosec / govulncheck / Trivy / Semgrep), release workflow (goreleaser + GHCR multi-arch), CONTRIBUTING / SECURITY / CODE_OF_CONDUCT

### Tests

- ≥60 new tests covering cloudscan, compliance, threatintel, notify, ai, exporter packages.

## [1.0.0] - 2026-05-13

Initial public release.
