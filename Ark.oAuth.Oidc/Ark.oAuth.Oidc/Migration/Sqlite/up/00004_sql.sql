-- 00004: user-level activation.
--
-- Clients have carried an "is_active" switch since 00003; this adds the matching one to
-- "users", so an account can be suspended without deleting it or scrambling its password.
-- Both switches are read at sign-in and reported separately, so the person signing in is
-- told which level is off instead of getting a credentials error.
--
-- Additive and defaulted, so every existing row stays valid and stays active. SQLite ignores
-- "IF NOT EXISTS" on ADD COLUMN, so re-running this reports "duplicate column name", which
-- can be ignored.

ALTER TABLE "users" ADD COLUMN "is_active" INTEGER NOT NULL DEFAULT 1;
