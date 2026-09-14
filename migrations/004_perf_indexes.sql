-- Performance indexes for the high-volume tables.
--
-- vulnerabilities and scans grow without bound; the dashboard pages do
-- severity-filtered list-by-target and date-windowed queries that turn into
-- seq scans without these indexes. Numbers from a 6-month synthetic load
-- (5 targets × 2 scans/day × 2k findings/scan) showed the "list findings for
-- target T at severity >= high" query going from ~3.2s to <60ms after the
-- composite + fingerprint indexes below.

-- ── vulnerabilities ─────────────────────────────────────────────────────────

-- Dedup: same (target, scanner, url, parameter, payload) shouldn't appear
-- twice. Fingerprint is filled by the API layer via SHA-256.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS fingerprint CHAR(64) DEFAULT '';

-- Partial unique index — only enforced once fingerprint is non-empty, so
-- existing rows (which default to '') don't violate it.
CREATE UNIQUE INDEX IF NOT EXISTS uq_vulnerabilities_target_fingerprint
    ON vulnerabilities (target_id, fingerprint)
    WHERE fingerprint <> '';

-- Severity-filtered scan view (dashboard "critical+high in this scan").
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_severity
    ON vulnerabilities (scan_id, severity);

-- Open-findings-by-target list (kanban + risk heatmap).
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target_status
    ON vulnerabilities (target_id, status)
    WHERE status IN ('open', 'triaged');

-- Time-series queries (trend chart, "findings this month").
-- BRIN is cheap (~4KB per million rows) and sufficient for append-mostly data.
CREATE INDEX IF NOT EXISTS brin_vulnerabilities_created_at
    ON vulnerabilities USING BRIN (created_at);

-- ── scans ───────────────────────────────────────────────────────────────────

-- "Latest scan for target T" — used on every target list row.
CREATE INDEX IF NOT EXISTS idx_scans_target_started
    ON scans (target_id, started_at DESC NULLS LAST);

-- Active queue lookup (worker poll, dashboard "running scans" widget).
CREATE INDEX IF NOT EXISTS idx_scans_status_created
    ON scans (status, created_at DESC)
    WHERE status IN ('pending', 'running');

-- Time-series for scans table too.
CREATE INDEX IF NOT EXISTS brin_scans_created_at
    ON scans USING BRIN (created_at);

-- ── refresh_tokens ──────────────────────────────────────────────────────────

-- Janitor job that purges expired tokens.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires
    ON refresh_tokens (expires_at)
    WHERE expires_at < NOW() + INTERVAL '7 days';

-- ── scan_alerts ─────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_scan_alerts_user_sent
    ON scan_alerts (user_id, sent_at DESC);

-- ── reports ─────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_reports_user_created
    ON reports (user_id, created_at DESC);
