# Authoring Temren plugins

Temren has two extension surfaces.

## 1. Lua plugins (`pkg/plugin`)

Drop a `.lua` file into a directory and load it with `--plugin path/to/script.lua`.
Plugins can be hot-reloaded without restarting the worker.

### Lua API

| Function | Returns | Notes |
|----------|---------|-------|
| `temren.target` | string | URL the scanner is currently testing |
| `temren.http_get(url[, headers])` | `{status, body, headers}` | follows Temren rate-limit / WAF bypass settings |
| `temren.http_post(url, body[, headers])` | same shape | |
| `temren.finding{title, severity, description, ...}` | nil | emits a `scanner.Finding` |
| `temren.log(msg)` | nil | logs to the worker stdout |

### Field reference

```lua
temren.finding{
  title       = "string",         -- required
  severity    = "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  confidence  = "HIGH|MEDIUM|LOW",
  description = "string",
  scanner     = "lua/<your-name>",
  owasp       = "A02:2025-Security Misconfiguration",
  cvss        = 7.5,
  payload     = "string",
  evidence    = "string",
  parameter   = "string",
}
```

A full example lives at [examples/example-plugin.lua](../examples/example-plugin.lua).

## 2. Native Go scanners (`pkg/scanner`)

Implement the `scanner.Scanner` interface and register it in `pkg/scanner/registry.go` (`AllScanners()`).
Native scanners are faster, have full access to the `httpengine.Client` (proxy rotation,
WAF bypass, Tor circuits), and can opt into Temren' instrumentation:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error)
}
```

See [pkg/scanner/sqli.go](../pkg/scanner/sqli.go) for a reference implementation and
[CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-new-scanner) for the full process.

## Plugin marketplace

The `/dashboard/plugins` page surfaces a catalog of community plugins. To list yours,
open a PR adding the metadata to `marketplace/plugins.json` (planned).
