"""
Protecting an API with bearer tokens from the same provider.

    ARK_AUTHORITY=https://idp.example.com/my_idp ARK_CLIENT_ID=my-api python examples/api_server.py

Verification is local, against the cached JWKS, so a request costs no round trip to the identity
server once the keys are loaded.

    curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:3001/api/me
"""

from flask import Flask, g, jsonify

from ark_oauth_client.flask import add_ark_oidc_api

from config import AUTHORITY, CLIENT_ID, REQUIRE_HTTPS

app = Flask(__name__)

bearer = add_ark_oidc_api(
    app,
    "/api",
    authority=AUTHORITY,
    client_id=CLIENT_ID,
    # The `aud` this API expects. Omit to skip the audience check.
    audience=CLIENT_ID,
    require_https=REQUIRE_HTTPS,
)


@app.get("/api/me")
def me():
    return jsonify(
        {
            "sub": g.ark.sub,
            "client_id": g.ark.client_id,
            "scopes": g.ark.scopes,
            "claims": g.ark.claims,
        }
    )


@app.get("/api/reports")
@bearer.require(claims=["reports.read"])
def reports():
    """403 with an RFC 6750 challenge when the token is valid but not allowed to do this."""
    return jsonify({"reports": ["q1", "q2"]})


@app.get("/health")
def health():
    """Outside the protected prefix, so a load balancer can reach it unauthenticated."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3001)
