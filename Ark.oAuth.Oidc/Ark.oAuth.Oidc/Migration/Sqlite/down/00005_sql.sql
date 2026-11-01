-- Rollback for 00005.
--
-- DROP COLUMN needs SQLite 3.35 (2021) or newer; on anything older the statement fails and the
-- column is simply left in place, which costs nothing because no earlier build reads it.
-- Rolling back stops clients being notified of logout and stops sessions being grouped by
-- browser, so end_session goes back to ending only the session the cookie names.

DROP INDEX IF EXISTS "IX_session_clients_session_id";
DROP TABLE IF EXISTS "session_clients";

DROP INDEX IF EXISTS "IX_sessions_browser_id";
ALTER TABLE "sessions" DROP COLUMN "browser_id";

ALTER TABLE "clients" DROP COLUMN "backchannel_logout_session_required";
ALTER TABLE "clients" DROP COLUMN "backchannel_logout_uri";
