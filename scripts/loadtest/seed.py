#!/usr/bin/env python3
"""Prints the SQL that seeds a scratch Ark IdP database for a load test.

    python3 seed.py --db pg|mysql|sqlite --password P --client-secret S [--users 30000] [--tenant ark_idp] | <database client>

Run it against a database the provider has already created (start the host once first). It adds
three clients cloned from the admin console's client — load_web (confidential, client_secret_post),
load_spa (public, PKCE) and load_device (public, device flow) — and N accounts
user00001@load.test .. each mapped to all three.

Every account gets the one password given here, hashed as the provider hashes it (PBKDF2-SHA256,
210,000 iterations). That makes seeding quick and is the reason this is for a scratch database
only: never run it against a provider anyone signs in to.
"""
import argparse, base64, hashlib, os, sys

p = argparse.ArgumentParser()
p.add_argument("--db", required=True, choices=["pg", "mysql", "sqlite"])
p.add_argument("--password", required=True, help="the password every seeded account gets")
p.add_argument("--client-secret", required=True, help="the secret of the load_web client")
p.add_argument("--users", type=int, default=30000)
p.add_argument("--tenant", default="ark_idp", help="the operator tenant (ark_oauth_server:TenantId)")
p.add_argument("--backchannel-uri", default="", help="where load_web is sent logout tokens, e.g. http://127.0.0.1:5399/bcl")
a = p.parse_args()


def pbkdf2(secret, iterations=210_000):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iterations, 32)
    return f"{iterations}.{base64.b64encode(salt).decode()}.{base64.b64encode(digest).decode()}"


uuid = {"pg": "gen_random_uuid()::text", "mysql": "UUID()", "sqlite": "lower(hex(randomblob(16)))"}[a.db]
email = {"pg": "'user' || lpad(g::text, 5, '0') || '@load.test'",
         "mysql": "CONCAT('user', LPAD(g, 5, '0'), '@load.test')",
         "sqlite": "'user' || substr('00000' || g, -5) || '@load.test'"}[a.db]
name = "CONCAT('Load User ', g)" if a.db == "mysql" else "'Load User ' || g"
series = (f"generate_series(1, {a.users}) g" if a.db == "pg" else
          f"(WITH RECURSIVE s(g) AS (SELECT 1 UNION ALL SELECT g + 1 FROM s WHERE g < {a.users}) SELECT g FROM s) n")

CLIENT_COLUMNS = ("id, tenant_id, client_id, client_logo, name, display, domain, redirect_url, logout_url, redirect_relative, "
                  "expire_mins, at, client_name, client_secret_hash, client_secret_expires_at, token_endpoint_auth_method, "
                  "application_type, client_uri, policy_uri, tos_uri, jwks_uri, redirect_uris_, post_logout_redirect_uris_, "
                  "grant_types_, response_types_, scopes_, contacts_, require_pkce, require_par, require_consent, "
                  "refresh_token_rotation, is_active, access_token_lifetime_seconds, id_token_lifetime_seconds, "
                  "refresh_token_lifetime_seconds, authorization_code_lifetime_seconds, registration_access_token_hash, "
                  "backchannel_logout_uri, backchannel_logout_session_required")


def client(row, client_id, label, redirect, secret_hash, method, kind, grants='["authorization_code","refresh_token"]', backchannel=""):
    secret = f"'{secret_hash}'" if secret_hash else "NULL"
    redirects = f'["{redirect}"]' if redirect else "[]"
    notify = f"'{backchannel}'" if backchannel else "NULL"
    return (f"INSERT INTO clients ({CLIENT_COLUMNS})\n"
            f"SELECT '{row}', tenant_id, '{client_id}', NULL, '{label}', '{label}', 'load.test', '{redirect}', "
            f"'http://127.0.0.1:9/out', NULL, 480, at, '{label}', {secret}, NULL, '{method}', '{kind}', NULL, NULL, NULL, NULL, "
            f"'{redirects}', '[\"http://127.0.0.1:9/out\"]', '{grants}', '[\"code\"]', "
            f"'[\"openid\",\"profile\",\"email\",\"offline_access\"]', NULL, true, false, false, true, true, 3600, 3600, 1209600, 60, "
            f"NULL, {notify}, true\nFROM clients WHERE client_id = '{a.tenant}_client';")


out = []
if a.db == "mysql":
    out.append(f"SET SESSION cte_max_recursion_depth = {a.users + 10};")
out.append(client("load-web-row", "load_web", "Load Web", "http://127.0.0.1:9/cb", pbkdf2(a.client_secret), "client_secret_post", "web",
                  backchannel=a.backchannel_uri))
out.append(client("load-spa-row", "load_spa", "Load SPA", "http://127.0.0.1:9/spa", None, "none", "spa"))
# a public device-flow client: no redirect URI, tokens only through a code approved on the provider
out.append(client("load-device-row", "load_device", "Load Device", "", None, "none", "native",
                  grants='["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]'))
out.append("INSERT INTO users (id, email, hash_pw, ref_uid, reset_mode, emailed, name, type, is_active, at)\n"
           f"SELECT {uuid}, {email}, '{pbkdf2(a.password)}', {uuid}, false, false, {name}, 'user', true, '2000-01-01T00:00:00'\n"
           f"FROM {series};")
out.append("INSERT INTO user_client_claims (id, email, client_id, tenant_id, claims_, at)\n"
           f"SELECT {uuid}, u.email, c.id, c.tenant_id, '[\"app.user\",\"reports.read\"]', '2000-01-01T00:00:00'\n"
           "FROM users u CROSS JOIN clients c WHERE u.email LIKE '%@load.test' AND c.client_id IN ('load_web', 'load_spa', 'load_device');")
out.append("ANALYZE TABLE users, user_client_claims;" if a.db == "mysql" else "ANALYZE;")
sys.stdout.write("\n".join(out) + "\n")
