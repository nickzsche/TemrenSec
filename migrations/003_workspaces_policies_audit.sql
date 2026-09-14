-- temren 003 — wave-2..6 feature tables
-- Workspaces (multi-tenant grouping of targets)
CREATE TABLE IF NOT EXISTS workspaces (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        UNIQUE NOT NULL,
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid        REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS workspaces_name_idx ON workspaces(name);

CREATE TABLE IF NOT EXISTS workspace_targets (
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    target_id    uuid NOT NULL REFERENCES targets(id)    ON DELETE CASCADE,
    PRIMARY KEY (workspace_id, target_id)
);

-- Policies (YAML rules loaded by pkg/policy)
CREATE TABLE IF NOT EXISTS policies (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid       REFERENCES workspaces(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    yaml        text        NOT NULL,
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS policies_workspace_idx ON policies(workspace_id);

-- Scan templates (YAML scan blueprints loaded by pkg/scantemplate)
CREATE TABLE IF NOT EXISTS scan_templates (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid       REFERENCES workspaces(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    yaml        text        NOT NULL,
    cron        text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Hash-chain audit events
CREATE TABLE IF NOT EXISTS audit_events (
    id          bigserial   PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    actor       text        NOT NULL,
    action      text        NOT NULL,
    object      text,
    data        jsonb,
    prev_sum    text        NOT NULL DEFAULT '',
    sum         text        NOT NULL,
    UNIQUE (sum)
);
CREATE INDEX IF NOT EXISTS audit_actor_idx ON audit_events(actor);
CREATE INDEX IF NOT EXISTS audit_action_idx ON audit_events(action);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_events(ts DESC);

-- Notification feed (in-app inbox)
CREATE TABLE IF NOT EXISTS notifications (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        REFERENCES users(id) ON DELETE CASCADE,
    ts          timestamptz NOT NULL DEFAULT now(),
    title       text        NOT NULL,
    body        text        NOT NULL,
    severity    text        NOT NULL,
    read        boolean     NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS notifications_user_idx ON notifications(user_id, ts DESC);

-- Asset tags (used by policy engine + risk model)
CREATE TABLE IF NOT EXISTS asset_tags (
    target_id uuid NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    tag       text NOT NULL,
    PRIMARY KEY (target_id, tag)
);
CREATE INDEX IF NOT EXISTS asset_tags_tag_idx ON asset_tags(tag);

-- Triage suppressions (persistent dedup rules)
CREATE TABLE IF NOT EXISTS triage_suppressions (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid       REFERENCES workspaces(id) ON DELETE CASCADE,
    scanner     text,
    url_glob    text,
    param       text,
    reason      text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- CVE enrichment cache (NVD + EPSS + KEV)
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      text        PRIMARY KEY,
    cvss_v3     numeric(3,1),
    epss        numeric(5,4),
    epss_pctile numeric(5,4),
    kev         boolean     NOT NULL DEFAULT false,
    kev_date    date,
    description text,
    refreshed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cve_cache_kev_idx ON cve_cache(kev) WHERE kev = true;

-- Plugin marketplace metadata
CREATE TABLE IF NOT EXISTS plugins (
    id          text        PRIMARY KEY,
    name        text        NOT NULL,
    author      text        NOT NULL,
    description text        NOT NULL,
    version     text        NOT NULL,
    source_url  text,
    installed   boolean     NOT NULL DEFAULT false,
    installed_at timestamptz
);
