# Temren Operations Runbook

For oncall responders. This document is intentionally short and operational.

## Health checks

| Endpoint | Expected | Notes |
|----------|----------|-------|
| `GET /health` | 200 `ok` | Liveness |
| `GET /readyz` | 200 `ok` | Postgres + Redis reachable |
| `GET /metrics` | 200 text | Prometheus exposition |
| `GET /api/v1/scans?limit=1` | 200 JSON, ≤500 ms | Database wall-clock |

## Common alerts

### `temren_scan_failure_ratio > 0.1`

Most likely causes:

1. Upstream target is rate-limiting Temren. Confirm with `kubectl logs` for HTTP 429.
   - Mitigation: lower `--rate` or pause the schedule.
2. Worker is OOMing. Check `kubectl top pod -l app=temren-worker`.
3. Postgres connection saturation. `select count(*) from pg_stat_activity;`.

### `temren_queue_lag_seconds > 600`

Asynq queue is backed up.
- Scale worker replicas (`kubectl scale deploy/temren-worker --replicas=N`).
- Inspect dead-letter queue: `temren worker dlq list`.

### Pager: "audit-log chain broken"

Someone mutated the log file directly. Treat as a P1 incident — likely insider.
Capture the file, run `temren hash-chain --verify`, and contact security@.

## Rotating secrets

```bash
# rotate JWT signing key (24h overlap, two-key validation)
temren jwt rotate --next-key="$(openssl rand -hex 32)"
kubectl rollout restart deploy/temren-api
```

## Backups & restore

Database backups are taken by the standard Postgres operator. To do an ad-hoc dump:

```bash
kubectl exec -it sts/temren-postgres-0 -- pg_dump -Fc -U temren temren > backup.dump
```

Restore in a recovery cluster, then verify integrity:

```bash
psql -c "select count(*) from findings;"
```

## Disabling Temren quickly

When a scan is causing production grief:

```bash
temren schedule pause --all
kubectl scale deploy/temren-worker --replicas=0
```

The frontend stays up so the team can review history while you investigate.

## Escalation

| Severity | Contact |
|----------|---------|
| P1 — data corruption / audit breach | security@zerosixlab.com, oncall pager |
| P2 — scan failure | platform-on-call |
| P3 — UI bug | github issue |
