# Implementation status

This file previously declared the project "completed under OWASP Top 10 2025".
Neither half was accurate: the mapping the code implements is the **2021** list,
and at the time it was written the documented quickstart could not start, the
dashboard fabricated its trend chart, and several scanners reported findings by
matching their own payloads. It also pointed at `pkg/scanner/scanner.go` for
detectors that live in their own files.

A checklist that disagrees with the code is worse than no checklist, so the
authoritative sources are now:

| Question | Where to look |
|---|---|
| What changed and why | [`CHANGELOG.md`](CHANGELOG.md) |
| What ships today, and how each claim is verified | [`docs/LAUNCH.md`](docs/LAUNCH.md) |
| Which scanners exist | `pkg/scanner/registry.go` — `AllScanners()` |
| Which OWASP category each maps to | `internal/queue/owasp_test.go` walks the registry and fails on any gap |
| Whether it builds and passes | `go build ./... && go vet ./... && go test ./...` |

## Known gaps

These are open, and deliberately listed rather than marked done:

- **`benchmarks/accuracy/` is not populated.** Detection accuracy is currently
  evidenced by a single local fixture with three planted bugs, not a benchmark.
- **~4,300 lines are unreachable.** `pkg/auth` (SAML/OIDC), `pkg/scanners`,
  `pkg/orchestrator`, `pkg/sandbox`, `pkg/discovery` and others have no
  non-test importer. Each needs a wire-it-up-or-delete decision.
- **The CLI cannot push results to a self-hosted dashboard.** The server
  exposes `POST /api/v1/cli/scan-results`, but no CLI flag calls it.
- **The scan engine's baseline cache is unused.** `ScanEngine` fetches a
  baseline per target and discards it, because the `Scanner` interface does not
  carry one; scanners that need it fetch their own.
- **OWASP Top 10 2025 mapping** is not implemented. The 2025 list is real and
  finalised; the code maps to 2021 throughout.
