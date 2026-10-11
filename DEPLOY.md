# Deploy — temren.zerosixlab.com

## Ayağa kalkan servisler (`docker compose up -d --build`)
postgres, redis, api (:8080), worker, frontend (:3000) ve **caddy** (tek giriş, host **:8089**).

Caddy (`deploy/Caddyfile`, `auto_https off` — TLS'i tünel yapar):
- `/api/*`, `/ws`, `/health` → `api:8080`
- gerisi → `frontend:3000`

Migration'lar API açılışında uygulanır. Doğrulama: `curl localhost:8089/` → 200, `curl localhost:8089/health` → 200, `/api/v1/*` → 401 (auth kapısı).

## .env
`.env` gitignore'da (commit edilmez). Gerekli: güçlü `JWT_SECRET`, `POSTGRES_PASSWORD`, `FRONTEND_URL=https://temren.zerosixlab.com`.

## Operatör adımı (sudo)
Tünel/DNS: `temren.zerosixlab.com → http://localhost:8089` (ör. cloudflared ingress veya reverse proxy).
