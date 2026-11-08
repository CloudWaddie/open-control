-- 0006_profile_settings.sql — profile options, org default profile, exit IPv6
--
-- profiles.options (JSON, since 0001) now holds policy.Options.
-- orgs.default_profile_id is the profile for clients that match no endpoint.
-- exit_nodes.answer_ipv6 is returned for AAAA queries in compatibility mode.

ALTER TABLE orgs ADD COLUMN default_profile_id INTEGER REFERENCES profiles(id) ON DELETE SET NULL;
UPDATE orgs SET default_profile_id = (SELECT MIN(id) FROM profiles WHERE profiles.org_id = orgs.id);

ALTER TABLE exit_nodes ADD COLUMN answer_ipv6 TEXT NOT NULL DEFAULT '';
