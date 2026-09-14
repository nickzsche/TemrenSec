-- temren 005 — tamper-prevention grants for audit_events
--
-- pkg/auditlog is file-based and authoritative today. The audit_events
-- table from migration 003 is reserved for the future DB-backed sink.
-- Either way, we want the application's DB role to be INSERT/SELECT-only
-- on this table so a compromised app can't rewrite history.
--
-- This migration is a no-op if the role doesn't exist; production deploys
-- should create a low-privilege role (typically `temren_app`) used by the
-- API/worker processes and run migrations as a separate superuser.
--
-- Tamper-EVIDENCE (the SHA-256 hash chain) remains the primary defence
-- and works regardless of grants. Tamper-PREVENTION (these grants + an
-- off-system sink like S3 Object Lock) is defence in depth.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'temren_app') THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM temren_app;
        GRANT INSERT, SELECT ON audit_events TO temren_app;
        -- Sequence privilege needed because id is bigserial.
        GRANT USAGE ON SEQUENCE audit_events_id_seq TO temren_app;
    END IF;
END
$$;

-- Row-level lock the chain integrity column: even with a buggy app the
-- `sum` column is UNIQUE so duplicate sums are caught by the index.
-- Re-asserting here so the constraint is obvious in migration history.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'audit_events_sum_key'
    ) THEN
        -- 003 created this with UNIQUE(sum); guard makes the migration idempotent.
        ALTER TABLE audit_events ADD CONSTRAINT audit_events_sum_key UNIQUE (sum);
    END IF;
END
$$;
