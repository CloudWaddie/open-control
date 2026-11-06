-- 0002_control_plane.sql — API tokens (RBAC) and audit actor (PLAN.md M2)

CREATE TABLE api_tokens (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER NOT NULL REFERENCES orgs(id),
    name       TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    token_hash TEXT NOT NULL UNIQUE,  -- sha256 hex; the plaintext is shown once
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE audit_logs ADD COLUMN actor TEXT NOT NULL DEFAULT '';
