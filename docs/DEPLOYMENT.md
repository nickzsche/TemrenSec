# Deployment

Temren can be deployed three ways, in increasing order of operational complexity.

## 1. Docker Compose (single host, recommended for dev / small teams)

```bash
cp .env.example .env
# edit JWT_SECRET, ANTHROPIC_API_KEY (optional), etc.
docker compose up -d
```

Compose brings up:

- `api` (Fiber + WebSocket, port 8080)
- `worker` (Asynq consumer)
- `frontend` (Next.js, port 3000)
- `postgres` 15
- `redis` 7

Healthchecks:

```bash
curl localhost:8080/health
docker compose logs -f worker
```

### GHCR package visibility (one-time)

CD (`.github/workflows/cd.yml`) pushes three images on every merge/tag:
`ghcr.io/nickzsche/temrensec-api`, `-worker` and `-cli`. The **first** push
creates the packages under your account. GHCR then requires you to link each
package to the repository and set its visibility once, or pulls fail with
`installation not allowed to Create organization package` / access-denied:

1. Open each package at `https://github.com/users/nickzsche/packages/container/temrensec-<api|worker|cli>/settings`.
2. Under **Manage Actions access**, add the `TemrenSec` repository (role: Write).
3. Set **Danger Zone → Change visibility** to Public (or keep Private and add
   an image pull secret to the cluster).

## 2. Kubernetes / Helm

The chart bundles Bitnami PostgreSQL and Redis subcharts, so fetch them first:

```bash
helm dependency update ./helm/temren

helm install temren ./helm/temren \
  --namespace temren --create-namespace \
  --set image.tag=1.0.0 \
  --set postgresql.auth.password=$(openssl rand -hex 16) \
  --set secrets.jwtSecret=$(openssl rand -hex 32)
```

`secrets.jwtSecret` and `postgresql.auth.password` are **required** (the
templates call `required` and installation fails fast if either is empty).
`DATABASE_URL`, `REDIS_URL` and `JWT_SECRET` are rendered into a Kubernetes
Secret, never the ConfigMap.

Tunables of note (see `helm/temren/values.yaml`):

| Key | Default | Notes |
|-----|---------|-------|
| `api.replicaCount` | 1 | API is stateless; scale out (needs `config.wsRedis: true`, default) |
| `worker.replicaCount` | 3 | Each pod processes `config.workerConcurrency` jobs |
| `worker.autoscaling.enabled` | false | HPA on worker CPU (`targetCPUUtilizationPercentage`, default 70) |
| `api.ingress.enabled` | false | Set `api.ingress.host` + `api.ingress.tls.enabled` for prod |
| `postgresql.enabled` | true | Set false + `config.databaseUrl` to use an external DB |
| `redis.enabled` | true | Set false + `config.redisUrl` to use external Redis |
| `postgresql.primary.persistence.size` | 10Gi | Postgres PVC |

To use external managed datastores instead of the bundled subcharts:

```bash
helm install temren ./helm/temren \
  --set postgresql.enabled=false --set config.databaseUrl="postgres://user:pass@db:5432/temren?sslmode=require" \
  --set redis.enabled=false --set config.redisUrl="redis://redis:6379" \
  --set secrets.jwtSecret=$(openssl rand -hex 32)
```

Raw manifests (no Helm) live in `k8s/base/` — edit the placeholder Secret first,
then `kubectl apply -k k8s/base/`.

## 3. Bare-metal binary

Download a release from GitHub releases or build locally with `make release-snapshot`.

```bash
sudo useradd -r -s /usr/sbin/nologin temren
sudo mkdir -p /opt/temren
sudo install -m 0755 dist/temren-api /usr/local/bin/temren-api
sudo install -m 0755 dist/temren-worker /usr/local/bin/temren-worker
# Provide /opt/temren/.env (see .env.example)
sudo cp deploy/systemd/temren-api.service deploy/systemd/temren-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now temren-api temren-worker
```

## Hardening checklist

- Set `JWT_SECRET` to a random 32-byte value (rotated every 90 days).
- Run behind a TLS-terminating reverse proxy (Caddy, Nginx, traefik).
- Restrict outbound egress from worker pods if running against the public internet — Temren probes can reach 169.254.169.254 by design.
- Enable WAL archiving on Postgres; Temren writes to `findings` and `audit_log` continuously.
- Forward `audit_log` to a SIEM (Splunk, Datadog, Loki).
- Configure `notify` with PagerDuty / OpsGenie for CRITICAL findings.

## Backups

```bash
docker exec temren-postgres pg_dump -U temren temren | gzip > backup-$(date +%F).sql.gz
```

Restore:

```bash
gunzip -c backup-2026-05-15.sql.gz | docker exec -i temren-postgres psql -U temren temren
```
