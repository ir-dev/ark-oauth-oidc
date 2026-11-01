"""
Shared configuration for the examples.

Every value comes from the environment so nothing here has to be edited, and so a real deployment
copies the same pattern: an authority, a client id, and — for a confidential client — a secret that
never appears in source control.
"""

import os

# The issuer: {BaseUrl}/{TenantId}. This is the one URL an Ark application has to be told.
AUTHORITY = os.environ.get("ARK_AUTHORITY", "https://localhost:7221/auth/oauth/ark_idp")
CLIENT_ID = os.environ.get("ARK_CLIENT_ID", "my-app")
CLIENT_SECRET = os.environ.get("ARK_CLIENT_SECRET")  # omit entirely for a public client

# Signs the session cookie. Use one value across every instance behind a load balancer.
SESSION_SECRET = os.environ.get("ARK_SESSION_SECRET", "change-me-at-least-16-characters")

PORT = int(os.environ.get("PORT", "3000"))
ORIGIN = os.environ.get("ARK_ORIGIN", f"http://127.0.0.1:{PORT}")

# Only ever false for local development against a plain-http provider.
REQUIRE_HTTPS = os.environ.get("ARK_REQUIRE_HTTPS", "true").lower() != "false"


def client_config():
    """The `ark_oauth_client` section, in the shape add_ark_oidc_client() binds."""
    config = {
        "authority": AUTHORITY,
        "client_id": CLIENT_ID,
        "require_https_metadata": REQUIRE_HTTPS,
    }
    if CLIENT_SECRET:
        config["client_secret"] = CLIENT_SECRET
    return config
