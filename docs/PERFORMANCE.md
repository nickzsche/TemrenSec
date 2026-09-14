# Performance tuning

Temren's defaults aim at "polite but useful". The knobs below let you trade scan
duration against load on the target, false-positive rate, and worker memory.

## Knobs

| Setting | CLI flag | Default | Notes |
|---------|----------|---------|-------|
| Request rate | `--rate <rps>` | 10 | Per-target. Honour any explicit Retry-After. |
| Worker concurrency | `WORKER_CONCURRENCY` | 4 | Asynq workers per pod. |
| Spider depth | `--depth <n>` | 2 | Each link expands ~exponentially. |
| Scanner timeout | `--scanner-timeout <dur>` | 60s | Per-scanner cap. |
| Body read limit | embedded | 1 MiB | Avoids OOM on enormous responses. |
| Connection pool | `httpengine.MaxIdleConns` | 100 | Per worker. |
| Jitter | `httpengine.applyJitter` | 50ms | Smooths bursts. |

## Bottlenecks observed in practice

1. **DNS** — `pkg/dnsenum` brute-force can saturate the resolver. Use `--concurrency 16`
   and a local Unbound for batches >5k.
2. **Headless browser** — `chromedp` spawns a Chromium per scan; cap with
   `BROWSER_POOL=4` and reuse where possible.
3. **GraphQL field-suggestion enumeration** — the server replies are large; turn
   it off for unreachable schemas via the scanner skip flag.
4. **OSV.dev rate limit** — batch lookups in 100s and add `OSV_TOKEN` if you have one.

## Profiling

```bash
# CPU
go test -cpuprofile=cpu.prof -bench=. ./pkg/scanner/...
go tool pprof -http :8080 cpu.prof

# Heap on a live worker
go install github.com/google/pprof@latest
go tool pprof -http :8080 http://worker:6060/debug/pprof/heap
```

The worker exposes `pprof` on `:6060` when started with `--debug-pprof`. **Never** turn
this on in production; it leaks goroutine traces, env, and heap.

## Benchmarks (M2 Pro, baseline)

| Workload | Wall | Notes |
|----------|------|-------|
| 1 host, standard profile | 4m 12s | ~2 200 requests |
| 1 host, deep profile     | 27m    | ~18 000 requests, 4 workers |
| 100 hosts, fast profile  | 14m    | parallel across 8 workers |
| Lockfile scan (12k pkgs) | 18s    | OSV.dev included |

Run the Go micro-benchmarks with `make bench` (wraps `go test -bench` over
`./pkg/...`; narrow the set with `make bench BENCH=BenchmarkScanner`).
