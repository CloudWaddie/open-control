-- 0004_egress.sql — exit nodes for redirect rules (PLAN.md M5)
--
-- An exit node is an egress point the operator runs: a SOCKS5 proxy or a
-- WireGuard peer. answer_ip is the address the resolver returns for names that
-- are redirected to it; it must route to the exit node on the operator's network.

ALTER TABLE exit_nodes ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN address TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN answer_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE exit_nodes ADD COLUMN checked_at TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_exit_nodes_org_name ON exit_nodes(org_id, name);
