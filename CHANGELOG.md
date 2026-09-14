# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-14

First stable release of TemrenSec — a self-hosted OWASP Top 10 2025 DAST + ASPM
platform made up of three binaries (CLI, API, worker) and a Next.js dashboard.

### Added

- **Unified scanner registry** (`pkg/scanner/registry.go`) — a single
  `AllScanners()` source of truth with **89 scanners**. The CLI, API and worker
  all read from it; there is no second place to register a scanner.
- **Nuclei-style YAML template engine** (`pkg/templates`) — request + matcher
  (status/word/regex/header, and/or, negative) and extractor (regex capture,
  header key/value) support. **46 built-in templates** (.git/.env/SSH key,
  actuator heapdump, Firebase/Rails/Vault secrets, phpMyAdmin, Jenkins, …) plus
  user templates from `~/.temren/templates`, wired into the registry as the
  "Template Engine (YAML)" scanner.
- **13 active scanners** — HTTP Request Smuggling (CL.TE / TE.CL / TE.TE),
  Web Cache Poisoning, Race Condition (TOCTOU), Mass Assignment / BOLA, LDAP
  Injection, XPath Injection, Insecure Deserialization (Java/PHP/Python/Ruby/.NET),
  OAuth/OIDC discovery misconfiguration, CORS preflight, GraphQL batching &
  alias overloading, SSRF cloud metadata (AWS/GCP/Azure/Alibaba/OpenStack),
  Host Header Injection, security-headers audit, SSTI engine fingerprinting,
  Web Cache Deception, and exposed sensitive endpoints.
- **`pkg/cloudscan`** — offline Dockerfile / Kubernetes / Terraform / .env audit.
- **`pkg/compliance`** — PCI-DSS 4.0 / HIPAA / GDPR / ISO 27001:2022 / SOC 2 /
  NIST CSF 2.0 / CIS Controls v8 / OWASP ASVS 5.0 mapping with executive summaries.
- **`pkg/threatintel`** — NVD CVE lookup, EPSS exploit probability, CISA KEV
  flagging, blended prioritization score.
- **`pkg/notify`** — unified dispatcher for 13 channels (Slack, Discord, Teams,
  Email, ntfy, Pushover, Telegram, PagerDuty, OpsGenie, Mattermost, Rocket.Chat,
  Twilio SMS, HMAC-signed webhook).
- **`pkg/exporter`** — SARIF 2.1, CycloneDX, JUnit, CSV, JSONL, Markdown, JIRA.
- **`pkg/ai`** — pluggable LLM provider (Anthropic / OpenAI / Ollama) for finding
  triage, exploit-chain reasoning and executive summaries.
- **Persistent workspaces** — moved from in-memory to Postgres (`WorkspaceRepo`,
  migration 003) so workspaces survive restarts.
- **CLI subcommands** — `temren cloud`, `export`, `compliance`, `intel`,
  `baseline`, `notify`, `tui`, `completion`, `mlbom`, and more.
- **Frontend pages** — Compliance, Threat Intel, AI Advisor, Asset Inventory,
  Risk Heatmap, Attack Paths, Notifications, Team, Audit Log, Settings.
- **CI / DevEx** — Makefile, `.golangci.yml` (golangci-lint v2), security
  workflow (gosec / govulncheck / Trivy / Semgrep), release workflow
  (goreleaser + GHCR multi-arch), Helm chart, Kubernetes manifests, GitHub
  Action, CONTRIBUTING / SECURITY / CODE_OF_CONDUCT.

### Fixed

- **Worker runs every registered scanner** — replaced the hardcoded 26-scanner
  list with the registry, so all 89 scanners actually execute (62 that were
  compiled but never run are now active).
- **Uniform OWASP 2025 categorization** — passive findings and broken labels are
  normalized; keyword inference; A00 is reserved for genuine informational findings.
- **Live progress across processes** — the worker publishes scan events to the
  WebSocket hub through a Redis bridge, so `/scans/:id/progress` works across
  separate API and worker processes.
- **Per-scanner 60 s timeout + panic isolation** — a single slow or hung scanner
  no longer blocks a scan up to the 30-minute outer timeout, and a panicking
  scanner no longer crashes the worker.
- **Remediation** — `pkg/remediation` rule engine plus an OWASP-category fallback
  raised the share of findings with actionable fixes to roughly 90%.

### Security

- **v2 endpoints require JWT** — ai/chat, export, intel/lookup, sbom, compliance,
  risk, triage, workspaces and others now require authentication.

### Tests

- 60+ tests covering cloudscan, compliance, threatintel, notify, ai and exporter.

## [0.1.0] - 2026-05-13

Initial public preview release.

[Unreleased]: https://github.com/nickzsche/TemrenSec/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/nickzsche/TemrenSec/releases/tag/v1.0.0
[0.1.0]: https://github.com/nickzsche/TemrenSec/releases/tag/v0.1.0
