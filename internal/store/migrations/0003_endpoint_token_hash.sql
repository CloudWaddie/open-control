-- 0003_endpoint_token_hash.sql — endpoint tokens become DoH/DoT credentials (PLAN.md M3)
--
-- From now on the token column holds SHA-256(token), never the plaintext.
-- Tokens minted before this migration are plaintext and can no longer be
-- matched, so they are disabled explicitly. Rotate an endpoint to issue a new one.

UPDATE endpoints SET token = 'disabled-' || id;
