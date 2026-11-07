-- 0008_endpoint_token_reveal.sql — endpoint tokens are re-viewable

-- Endpoint tokens are device identifiers, not account credentials: knowing one
-- only lets a client reach the filtering endpoint it belongs to. They are shown
-- again on the endpoints and setup pages, so they are stored in plaintext next
-- to their lookup hash (which stays authoritative for authentication).
-- Tokens minted before this migration have no recoverable plaintext; they keep
-- working until rotated.

ALTER TABLE endpoints ADD COLUMN token_plain TEXT NOT NULL DEFAULT '';
