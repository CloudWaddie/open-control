-- 0009_users_password.sql — the seeded users table becomes password accounts

-- The initial schema included a users table no code ever used. It becomes the
-- dashboard account table: username with a bcrypt password hash. API tokens
-- stay for scripts and the CLI; signing in to the dashboard mints a session
-- bearer token (visible and revocable on the API tokens page).

ALTER TABLE users RENAME COLUMN email TO name;
ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_name_uq ON users(name);
