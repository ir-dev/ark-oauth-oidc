-- Rollback for 00003.
--
-- Drops the protocol state tables. The columns added to "clients" are intentionally left in
-- place: SQLite cannot drop a column without rebuilding the table, and leaving them costs
-- nothing because the v1 endpoints never read them.
--
-- Dropping these tables invalidates every outstanding authorization code, refresh token and
-- session issued by the standard endpoints. Users will have to sign in again.

DROP TABLE IF EXISTS "auth_codes";
DROP TABLE IF EXISTS "refresh_tokens";
DROP TABLE IF EXISTS "device_codes";
DROP TABLE IF EXISTS "par_requests";
DROP TABLE IF EXISTS "consents";
DROP TABLE IF EXISTS "sessions";
DROP TABLE IF EXISTS "scopes";
DROP TABLE IF EXISTS "signing_keys";
