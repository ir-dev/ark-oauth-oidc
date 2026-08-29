-- 00005: back-channel logout, and sessions that know which browser they are in.
--
-- Three things, all additive:
--
--   * "clients"."backchannel_logout_uri" / "backchannel_logout_session_required" — where to POST
--     a logout token when a session this client took part in ends, per OIDC Back-Channel Logout
--     1.0. A client with no URI is simply not notified, which is what every existing row gets.
--   * "sessions"."browser_id" — the user agent a session was created in. The session cookie only
--     ever holds the most recent sid, so without this a second person signing in on the same
--     machine leaves the first session live with its refresh tokens intact, and end_session only
--     closes the one the cookie names. Grouping by browser is what lets logout close all of them.
--     Rows that predate this column have no browser to name and are treated as their own.
--   * "session_clients" — one row per (session, client) the first time that session issues the
--     client a code or approves its device request. This is the audience list for back-channel
--     logout: deriving it from live refresh tokens instead would miss every client that never
--     asked for offline_access, which is most of them.
--
-- SQLite ignores "IF NOT EXISTS" on ADD COLUMN, so re-running the ALTERs reports "duplicate
-- column name", which can be ignored.

ALTER TABLE "clients" ADD COLUMN "backchannel_logout_uri" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "backchannel_logout_session_required" INTEGER NOT NULL DEFAULT 1;

ALTER TABLE "sessions" ADD COLUMN "browser_id" TEXT NULL;

CREATE TABLE IF NOT EXISTS "session_clients" (
    "id"         TEXT NOT NULL CONSTRAINT "PK_session_clients" PRIMARY KEY,
    "tenant_id"  TEXT NOT NULL,
    "session_id" TEXT NOT NULL,
    "client_id"  TEXT NOT NULL,
    "subject"    TEXT NOT NULL,
    "created_at" TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS "IX_session_clients_session_id" ON "session_clients" ("session_id");
CREATE INDEX IF NOT EXISTS "IX_sessions_browser_id" ON "sessions" ("browser_id");
