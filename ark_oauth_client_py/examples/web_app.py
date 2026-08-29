"""
Interactive sign-in — the whole integration.

    ARK_AUTHORITY=https://idp.example.com/my_idp ARK_CLIENT_ID=my-app python examples/web_app.py

Register http://127.0.0.1:3000/signin-oidc as the redirect URI, then open http://127.0.0.1:3000.

add_ark_oidc_client serves /login, /signin-oidc and /logout, and adds the account-switch endpoints.
Nothing below deals with a token: the guard decides who may see a page, and current_ark says who
they are.
"""

from flask import Flask

from ark_oauth_client.flask import add_ark_oidc_client, current_ark, get_ark_access_token

from config import PORT, REQUIRE_HTTPS, SESSION_SECRET, client_config

app = Flask(__name__)
app.secret_key = SESSION_SECRET

auth = add_ark_oidc_client(
    app,
    client_config(),
    # Refuse a sign-in by an account with no ark_claims for this client, so a shared browser cannot
    # leave the second person holding the first person's session. See /ark/no-access.
    lambda options: setattr(options.config.account_switch, "require_ark_claims", True),
    cookie_secure=REQUIRE_HTTPS,
)


@app.get("/")
def home():
    if not current_ark.is_authenticated:
        return '<h1>Ark demo</h1><p><a href="/login">Sign in</a></p>'
    user = current_ark.user or {}
    return f"""
        <h1>Hello {user.get('name') or user.get('email')}</h1>
        <p>Authorization claims: {', '.join(current_ark.claims) or '(none)'}</p>
        <p>Granted scopes: {', '.join(current_ark.scopes)}</p>
        <p><a href="/billing">Billing</a> &middot; <a href="/whoami">Who am I</a>
           &middot; <a href="/logout">Sign out</a></p>
    """


@app.get("/whoami")
@auth.require_auth()
def whoami():
    # The access token is fetched per call so a token the middleware just refreshed is picked up.
    return {"user": current_ark.user, "has_token": bool(get_ark_access_token())}


@app.get("/billing")
@auth.require_claims("billing.admin")
def billing():
    """Reached only by a user the tenant granted `billing.admin` for this client."""
    return "<h1>Billing</h1><p><a href='/'>Back</a></p>"


@app.get("/downstream")
@auth.require_auth()
def downstream():
    """Calling another API with the caller's own token rather than the service's."""
    from ark_oauth_client.flask import with_ark_token

    return {"headers_we_would_send": with_ark_token({"Accept": "application/json"})}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT, debug=False)
