# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Nuclei tarzı YAML şablon motoru** (`pkg/templates`) — request + matcher
  (status/word/regex/header, and/or, negative) ve extractor (regex capture +
  header kval) destekli YAML tespit şablonları. 38 gömülü şablon (.git/.env/SSH
  key/actuator heapdump/Firebase-Rails-Vault sırları/phpMyAdmin/Jenkins/...) +
  `~/.temren/templates`'ten kullanıcı şablonları. Registry'ye "Template Engine
  (YAML)" scanner olarak bağlı (artık 89 scanner).
- **Workspaces kalıcılığı** — in-memory yerine Postgres (`WorkspaceRepo`,
  migration 003), yeniden başlatmayı atlatıyor.

### Fixed

- **Worker tüm kayıtlı scanner'ları çalıştırıyor** — 26 hardcode yerine registry
  (88→ artık 89). Kalan 62 scanner derlenmiş ama çalışmıyordu.
- **OWASP kategorisi tek tip 2025** — pasif bulgular + bozuk etiketler dahil
  normalize; keyword tahmini; A00 yalnız gerçek bilgilendirmeye kalıyor.
- **Canlı ilerleme** — worker tarama olaylarını Redis köprüsüyle WebSocket
  hub'ına yayınlıyor; REST `/scans/:id/progress` cross-process çalışıyor.
- **Scanner başına 60sn timeout + panic izolasyonu** — tek yavaş/asılı scanner
  artık taramayı 30dk dış timeout'a kadar kilitlemiyor; bozuk scanner worker'ı
  çökertmiyor.
- **Remediation** — `pkg/remediation` kural motoru + OWASP kategori-bazlı yedek;
  taramaların bulgularında anlamlı çözüm oranı ~%90'a çıktı.

### Security

- **v2 uçları JWT ile kilitlendi** — ai/chat, export, intel/lookup, sbom,
  compliance, risk, triage, workspaces vb. artık kimlik doğrulaması istiyor.

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
