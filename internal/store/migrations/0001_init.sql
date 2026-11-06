-- 0001_init.sql — initial schema (PLAN.md §4)
CREATE TABLE orgs (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES orgs(id),
    email       TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    auth_source TEXT NOT NULL DEFAULT 'local',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, email)
);

CREATE TABLE profiles (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER NOT NULL REFERENCES orgs(id),
    name       TEXT NOT NULL,
    options    TEXT NOT NULL DEFAULT '{}',  -- upstreams, cache policy, log level
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, name)
);

CREATE TABLE blocklist_sources (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES orgs(id),
    url         TEXT NOT NULL,
    format      TEXT NOT NULL DEFAULT 'hosts',  -- hosts | dnsmasq | adguard
    etag        TEXT,
    last_synced TEXT,
    UNIQUE (org_id, url)
);

CREATE TABLE profile_rules (
    id         INTEGER PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('block', 'allow', 'redirect', 'rewrite')),
    matcher    TEXT NOT NULL,  -- domain | wildcard | tld
    pattern    TEXT NOT NULL,  -- domain name, or ".tld" for tld rules
    answer     TEXT NOT NULL DEFAULT '',  -- rewrite answer (IP or name); redirect target later
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_profile_rules_profile ON profile_rules(profile_id);

CREATE TABLE profile_filters (
    profile_id           INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    service_or_filter_id TEXT NOT NULL,
    state                TEXT NOT NULL CHECK (state IN ('allow', 'block')),
    PRIMARY KEY (profile_id, service_or_filter_id)
);

CREATE TABLE endpoints (
    id                 INTEGER PRIMARY KEY,
    org_id             INTEGER NOT NULL REFERENCES orgs(id),
    profile_id         INTEGER NOT NULL REFERENCES profiles(id),
    token              TEXT NOT NULL UNIQUE,  -- DoH path / DoT SNI token (M3+), DoT/DoH only
    name               TEXT NOT NULL,
    allowed_source_ips TEXT NOT NULL DEFAULT '[]',
    schedule           TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, name)
);
CREATE INDEX idx_endpoints_org ON endpoints(org_id);

CREATE TABLE exit_nodes (
    id      INTEGER PRIMARY KEY,
    org_id  INTEGER NOT NULL REFERENCES orgs(id),
    kind    TEXT NOT NULL CHECK (kind IN ('wireguard', 'socks5')),
    config  TEXT NOT NULL DEFAULT '{}',
    health  TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE query_logs (
    id          INTEGER PRIMARY KEY,
    org_id      INTEGER NOT NULL,
    endpoint_id INTEGER,
    ts          INTEGER NOT NULL,
    client_ip   TEXT NOT NULL,
    qname       TEXT NOT NULL,
    qtype       TEXT NOT NULL,
    action      TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_query_logs_org_ts ON query_logs(org_id, ts);

CREATE TABLE audit_logs (
    id      INTEGER PRIMARY KEY,
    org_id  INTEGER NOT NULL,
    user_id INTEGER,
    ts      INTEGER NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT NOT NULL,
    diff    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_logs_org_ts ON audit_logs(org_id, ts);
