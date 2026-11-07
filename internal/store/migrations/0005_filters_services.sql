-- 0005_filters_services.sql — per-profile filters, services and lists
--
-- One row per thing a profile turns on:
--   kind 'filter'  ref = built-in category id ("ads"), level = chosen level
--   kind 'service' ref = services registry id ("tiktok"), state block|allow|redirect
--   kind 'list'    ref = blocklist_sources.id of a custom subscription
-- A redirect row names the exit its traffic goes through. Deleting the exit
-- deletes the row (the service falls back to "not set").
--
-- The old profile_filters table was never written to; it is replaced.

DROP TABLE profile_filters;

CREATE TABLE profile_filters (
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('filter', 'service', 'list')),
    ref        TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('block', 'allow', 'redirect')),
    level      TEXT NOT NULL DEFAULT '',
    exit_id    INTEGER REFERENCES exit_nodes(id) ON DELETE CASCADE,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (profile_id, kind, ref),
    CHECK ((state = 'redirect') = (exit_id IS NOT NULL))
);

-- Until now every org list applied to every profile in the org. Keep that.
INSERT INTO profile_filters (profile_id, kind, ref, state)
SELECT p.id, 'list', CAST(b.id AS TEXT), 'block'
FROM profiles p JOIN blocklist_sources b ON b.org_id = p.org_id;
