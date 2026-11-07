-- 0010_exits_v2.sql — exits gain credentials and WireGuard tunnel keys

-- Socks5/HTTP outbounds can authenticate (username/password, stored in
-- plaintext: they are dial credentials shown again on the exits page).
-- WireGuard exits carry the tunnel material parsed from a wg-quick config:
-- the interface's private key, the peer's public key, optional preshared key
-- and the endpoint's allowed IPs.

ALTER TABLE exit_nodes ADD COLUMN username TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN password TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN wg_private TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN wg_peer TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN wg_preshared TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN wg_allowed TEXT NOT NULL DEFAULT '';
