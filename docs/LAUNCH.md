# Product Hunt launch kit

Copy-paste assets for the Temren launch. Every number here is verified against
the code — see **Verification** at the bottom before changing any of them.

---

## Tagline (60 char limit)

> Open-source OWASP scanner that proves its findings

Alternatives:

- `Self-hosted web security scanner with verified findings` (54)
- `Find OWASP Top 10 bugs in your app. Self-hosted, free.` (53)
- `The security scanner that doesn't cry wolf` (41)

---

## Description (260 char limit)

> Temren scans your web app for OWASP Top 10 vulnerabilities — SQL injection,
> XSS, SSRF, IDOR and 72 more. Every finding is checked against a clean
> baseline before it's reported, so you get real bugs instead of noise.
> Self-hosted, GPL-3.0, no per-scan pricing.

(254 characters.)

---

## First comment (the maker comment)

> Hey Product Hunt 👋
>
> I built Temren because every scanner I tried had the same problem: it would
> flag a page as critically vulnerable because the word "postgresql" appeared
> in the footer.
>
> So the core idea here is simple — **a finding has to be attributable to the
> payload.** Before Temren reports anything, it fetches the page untouched,
> then compares. SQL injection is only reported when a database error appears
> that wasn't there before. XSS injects a random marker per request and only
> fires if that exact marker comes back unencoded, in a place a browser would
> execute it. Time-based injection has to reproduce across two independent
> measurements.
>
> What you get:
>
> - **76 scanners** covering OWASP Top 10 (2021), from SQL injection and SSRF
>   to JWT algorithm confusion and request smuggling
> - **A real dashboard** — live scan progress over WebSocket, severity
>   breakdowns, per-finding evidence and proof-of-concept
> - **A CLI** for CI pipelines, with SARIF/JUnit output
> - **Integrations** with GitHub, GitLab, Jira, Slack, Discord, Teams,
>   DefectDojo and custom webhooks
> - **Self-hosted**, so your scan results never leave your infrastructure
>
> It's GPL-3.0 and there's no per-scan pricing, no API limits, no cloud tier
> you get pushed toward.
>
> Two things I want to be upfront about: this is a young project, and a
> scanner is only as good as its false-positive rate — if Temren flags
> something wrong on your app, open an issue with the URL pattern and I'll fix
> the detector. That feedback is the most useful thing you can give me today.
>
> `git clone` → `make setup` → `docker compose up -d`. Would love to hear what
> it finds on your stack.

---

## Topics

`Developer Tools` · `Security` · `Open Source` · `Web App` · `SaaS`

---

## Gallery order

| # | File | Why it's here |
|---|------|---------------|
| 1 | `docs/screenshots/landing.png` | Establishes what the product is |
| 2 | `docs/screenshots/vulnerability-detail.png` | The findings list — the actual product |
| 3 | `docs/screenshots/dashboard.png` | Severity breakdown and charts |
| 4 | `docs/screenshots/scan-progress.png` | Scan history |
| 5 | `docs/screenshots/scans-analytics.png` | Analytics |
| 6 | `docs/screenshots/targets.png` | Target management |

All screenshots are real captures of a scan against a local test application,
not mockups. See **Verification**.

---

## Pre-launch checklist

- [ ] Merge this branch to `main` so the README screenshots resolve on GitHub
- [ ] Tag a release (`v0.1.0`) and let goreleaser publish binaries
- [ ] Confirm the Product Hunt badge `post_id` in `README.md` matches the real
      post — it is currently `post_id=temren`
- [x] ~~Decide what `https://temren.sh` should be~~ — removed. The CLI now
      points at the results file and the integrations that exist; the API
      derives report links from `FRONTEND_URL` (override with
      `PUBLIC_BASE_URL`); the Helm and k8s ingress examples use
      `temren.example.com`.
- [ ] Turn on GitHub Discussions for launch-day questions
- [ ] Have the "what do I do about a false positive" answer ready: open an
      issue with the URL pattern

---

## Answers to questions you'll get

**"How is this different from ZAP / Nuclei?"**
ZAP is a proxy-first tool built for manual testing; Nuclei is template-driven
and community-maintained. Temren is a self-hosted scanning *service*: a queue,
a worker pool, a dashboard, scheduled scans and integrations, with detection
logic that compares against a clean baseline rather than pattern-matching a
single response. It is not more capable than either of them today — it is a
different shape.

**"Is it accurate?"**
Against a deliberately-vulnerable local test app with three planted bugs, the
current build reports exactly those three as critical/high — one SQL injection
and two reflected XSS — and nothing else at those severities. That's one small
fixture, not a benchmark; `benchmarks/accuracy/` is where broader measurement
belongs and it isn't populated yet.

**"Can I scan a site I don't own?"**
Don't. Temren rate-limits per host and identifies itself in the User-Agent,
but authorisation is your responsibility.

**"Does it phone home?"**
No. It's self-hosted; there's no telemetry in the Go code. The Next.js
dashboard inherits Next's own telemetry, which you can disable with
`npx next telemetry disable`.

**"Why GPL-3.0?"**
So improvements to the detection logic come back to the project.

---

## Verification

The numbers above were checked on this branch:

| Claim | How to check |
|-------|--------------|
| 76 scanners | `grep -oE 'New[A-Za-z0-9]+Scanner\(\)' pkg/scanner/registry.go \| sort -u \| wc -l` |
| OWASP 2021, every scanner mapped | `go test ./internal/queue/ -run OWASP` |
| Baseline-differential SQLi / nonce-based XSS | `go test ./pkg/scanner/ -run 'DetectSQLError\|IsPayloadReflected\|MarkerIsEvaluated'` |
| Build and tests green | `go build ./... && go vet ./... && go test ./...` (56 packages) |
| Screenshots are real | Captured with Playwright against the running app; the scan data behind them came from an actual scan of a local test server |

Do not raise any of these numbers without re-running the corresponding check.
The project previously advertised "26+", "36+" and "76" scanners on three
different surfaces, and an OWASP 2025 badge over a 2021 mapping — that kind of
drift is exactly what launch-day scrutiny finds.
