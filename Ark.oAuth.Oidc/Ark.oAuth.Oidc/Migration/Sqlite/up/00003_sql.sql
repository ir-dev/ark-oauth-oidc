-- 00003: standard OAuth 2.1 / OIDC protocol state.
--
-- Adds the tables the standard endpoints need, plus the RFC 7591 registration metadata
-- columns on the existing "clients" table. Nothing here is destructive: the legacy
-- redirect_url / logout_url columns are left in place for the /v1 compatibility endpoints,
-- and every new column is nullable or defaulted so existing rows stay valid.
--
-- SQLite ignores "IF NOT EXISTS" on ADD COLUMN, so each ALTER is written to be run once.
-- Re-running this script is safe for the CREATE TABLE statements and will report
-- "duplicate column name" for the ALTERs, which can be ignored.

CREATE TABLE IF NOT EXISTS "signing_keys" (
    "kid"           TEXT NOT NULL,
    "tenant_id"     TEXT NOT NULL,
    "alg"           TEXT NOT NULL DEFAULT 'RS256',
    "usage"         TEXT NOT NULL DEFAULT 'sig',
    "public_key"    TEXT NOT NULL,
    "private_key"   TEXT NOT NULL,
    "status"        TEXT NOT NULL DEFAULT 'active',
    "created_at"    TEXT NOT NULL,
    "not_after"     TEXT NULL,
    CONSTRAINT "PK_signing_keys" PRIMARY KEY("kid")
);
CREATE INDEX IF NOT EXISTS "IX_signing_keys_tenant_status" ON "signing_keys" ("tenant_id", "status");

CREATE TABLE IF NOT EXISTS "auth_codes" (
    "code_hash"             TEXT NOT NULL,
    "tenant_id"             TEXT NOT NULL,
    "client_id"             TEXT NOT NULL,
    "subject"               TEXT NOT NULL,
    "session_id"            TEXT NULL,
    "redirect_uri"          TEXT NOT NULL,
    "scope"                 TEXT NULL,
    "code_challenge"        TEXT NULL,
    "code_challenge_method" TEXT NULL,
    "nonce"                 TEXT NULL,
    "auth_context"          TEXT NULL,
    "auth_time"             TEXT NOT NULL,
    "expires_at"            TEXT NOT NULL,
    "created_at"            TEXT NOT NULL,
    "consumed"              INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "PK_auth_codes" PRIMARY KEY("code_hash")
);
CREATE INDEX IF NOT EXISTS "IX_auth_codes_expires_at" ON "auth_codes" ("expires_at");

CREATE TABLE IF NOT EXISTS "refresh_tokens" (
    "token_hash"  TEXT NOT NULL,
    "family_id"   TEXT NOT NULL,
    "tenant_id"   TEXT NOT NULL,
    "client_id"   TEXT NOT NULL,
    "subject"     TEXT NOT NULL,
    "session_id"  TEXT NULL,
    "scope"       TEXT NULL,
    "expires_at"  TEXT NOT NULL,
    "created_at"  TEXT NOT NULL,
    "consumed_at" TEXT NULL,
    "revoked"     INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "PK_refresh_tokens" PRIMARY KEY("token_hash")
);
CREATE INDEX IF NOT EXISTS "IX_refresh_tokens_family" ON "refresh_tokens" ("family_id");
CREATE INDEX IF NOT EXISTS "IX_refresh_tokens_subject_client" ON "refresh_tokens" ("subject", "client_id");

CREATE TABLE IF NOT EXISTS "device_codes" (
    "device_code_hash" TEXT NOT NULL,
    "user_code"        TEXT NOT NULL,
    "tenant_id"        TEXT NOT NULL,
    "client_id"        TEXT NOT NULL,
    "scope"            TEXT NULL,
    "status"           TEXT NOT NULL DEFAULT 'pending',
    "subject"          TEXT NULL,
    "session_id"       TEXT NULL,
    "interval_seconds" INTEGER NOT NULL DEFAULT 5,
    "expires_at"       TEXT NOT NULL,
    "created_at"       TEXT NOT NULL,
    "last_polled_at"   TEXT NULL,
    CONSTRAINT "PK_device_codes" PRIMARY KEY("device_code_hash")
);
CREATE UNIQUE INDEX IF NOT EXISTS "IX_device_codes_user_code" ON "device_codes" ("user_code");

CREATE TABLE IF NOT EXISTS "par_requests" (
    "request_uri" TEXT NOT NULL,
    "tenant_id"   TEXT NOT NULL,
    "client_id"   TEXT NOT NULL,
    "payload"     TEXT NOT NULL,
    "expires_at"  TEXT NOT NULL,
    "created_at"  TEXT NOT NULL,
    "consumed"    INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "PK_par_requests" PRIMARY KEY("request_uri")
);

CREATE TABLE IF NOT EXISTS "consents" (
    "id"         TEXT NOT NULL,
    "tenant_id"  TEXT NOT NULL,
    "client_id"  TEXT NOT NULL,
    "subject"    TEXT NOT NULL,
    "scopes_"    TEXT NULL,
    "granted_at" TEXT NOT NULL,
    "expires_at" TEXT NULL,
    CONSTRAINT "PK_consents" PRIMARY KEY("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "IX_consents_tenant_client_subject" ON "consents" ("tenant_id", "client_id", "subject");

CREATE TABLE IF NOT EXISTS "sessions" (
    "session_id" TEXT NOT NULL,
    "tenant_id"  TEXT NOT NULL,
    "subject"    TEXT NOT NULL,
    "auth_time"  TEXT NOT NULL,
    "created_at" TEXT NOT NULL,
    "expires_at" TEXT NOT NULL,
    "revoked"    INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "PK_sessions" PRIMARY KEY("session_id")
);
CREATE INDEX IF NOT EXISTS "IX_sessions_subject" ON "sessions" ("subject");

CREATE TABLE IF NOT EXISTS "scopes" (
    "name"            TEXT NOT NULL,
    "display"         TEXT NULL,
    "description"     TEXT NULL,
    "claims_"         TEXT NULL,
    "is_default"      INTEGER NOT NULL DEFAULT 0,
    "require_consent" INTEGER NOT NULL DEFAULT 1,
    "is_protocol"     INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "PK_scopes" PRIMARY KEY("name")
);

-- the OIDC standard scope catalogue
INSERT OR IGNORE INTO "scopes" ("name", "display", "description", "claims_", "is_default", "require_consent", "is_protocol")
VALUES
 ('openid',         'Sign you in',           'Verify your identity.',                              '[]', 1, 0, 1),
 ('profile',        'Your basic profile',    'Your name and profile details.',                     '["name","family_name","given_name","middle_name","nickname","preferred_username","profile","picture","website","gender","birthdate","zoneinfo","locale","updated_at"]', 1, 1, 0),
 ('email',          'Your email address',    'Your email address and whether it is verified.',     '["email","email_verified"]', 1, 1, 0),
 ('address',        'Your address',          'Your postal address.',                               '["address"]', 0, 1, 0),
 ('phone',          'Your phone number',     'Your phone number and whether it is verified.',      '["phone_number","phone_number_verified"]', 0, 1, 0),
 ('offline_access', 'Stay signed in',        'Keep access when you are not using the app.',        '[]', 0, 1, 1);

-- RFC 7591 client registration metadata on the existing clients table
ALTER TABLE "clients" ADD COLUMN "client_name" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "client_secret_hash" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "client_secret_expires_at" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "token_endpoint_auth_method" TEXT NOT NULL DEFAULT 'client_secret_basic';
ALTER TABLE "clients" ADD COLUMN "application_type" TEXT NOT NULL DEFAULT 'web';
ALTER TABLE "clients" ADD COLUMN "client_uri" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "policy_uri" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "tos_uri" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "jwks_uri" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "redirect_uris_" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "post_logout_redirect_uris_" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "grant_types_" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "response_types_" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "scopes_" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "contacts_" TEXT NULL;
ALTER TABLE "clients" ADD COLUMN "require_pkce" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "clients" ADD COLUMN "require_par" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "clients" ADD COLUMN "require_consent" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "clients" ADD COLUMN "refresh_token_rotation" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "clients" ADD COLUMN "is_active" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "clients" ADD COLUMN "access_token_lifetime_seconds" INTEGER NOT NULL DEFAULT 3600;
ALTER TABLE "clients" ADD COLUMN "id_token_lifetime_seconds" INTEGER NOT NULL DEFAULT 3600;
ALTER TABLE "clients" ADD COLUMN "refresh_token_lifetime_seconds" INTEGER NOT NULL DEFAULT 1209600;
ALTER TABLE "clients" ADD COLUMN "authorization_code_lifetime_seconds" INTEGER NOT NULL DEFAULT 60;
ALTER TABLE "clients" ADD COLUMN "registration_access_token_hash" TEXT NULL;

-- Existing clients were browser-based and hold no secret, so they are public clients
-- and must use PKCE. Seed their standard metadata from the legacy columns.
UPDATE "clients"
SET "token_endpoint_auth_method" = 'none',
    "require_pkce" = 1,
    "client_name" = COALESCE("client_name", "display", "name", "client_id"),
    "redirect_uris_" = COALESCE("redirect_uris_", '["' || "redirect_url" || '"]'),
    "post_logout_redirect_uris_" = COALESCE("post_logout_redirect_uris_", '["' || "logout_url" || '"]'),
    "grant_types_" = COALESCE("grant_types_", '["authorization_code","refresh_token"]'),
    "response_types_" = COALESCE("response_types_", '["code"]'),
    "scopes_" = COALESCE("scopes_", '["openid","profile","email","offline_access"]')
WHERE "client_secret_hash" IS NULL;

-- Adopt each tenant's existing key as its active signing key, keeping kid = tenant_id so
-- tokens already issued keep validating against the new JWKS endpoint.
INSERT OR IGNORE INTO "signing_keys" ("kid", "tenant_id", "alg", "usage", "public_key", "private_key", "status", "created_at")
SELECT "tenant_id", "tenant_id", 'RS256', 'sig', "rsa_public", "rsa_private", 'active',
       strftime('%Y-%m-%dT%H:%M:%S', 'now')
FROM "tenants"
WHERE "rsa_public" IS NOT NULL AND "rsa_private" IS NOT NULL;
