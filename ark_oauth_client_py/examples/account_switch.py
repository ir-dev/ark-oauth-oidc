"""
The shared browser.

    python examples/account_switch.py

Single sign-on is browser-wide: once one person has signed in anywhere, the provider's session
answers the authorize request of every other client in that browser. The second person opens a
different application, is silently signed in as the first, is told they do not have access — and has
no way back, because the sign-in link returns to the same session and gives the same answer.

This example turns on every part of the way out. Nothing here is on by default; a host that sets
none of it behaves exactly as it did before.
"""

from flask import Flask

from ark_oauth_client.flask import add_ark_oidc_client, ark_denied_account, current_ark

from config import PORT, REQUIRE_HTTPS, SESSION_SECRET, client_config

app = Flask(__name__)
app.secret_key = SESSION_SECRET


def configure(options):
    switch = options.config.account_switch

    # The check that makes the case recoverable: an account with no ark_claims for this client is
    # refused at the callback, before the session cookie is written, so the browser never holds a
    # session for somebody who cannot use the application.
    switch.require_ark_claims = True

    # What the built-in page at /ark/no-access says.
    switch.app_display_name = "Billing Portal"
    switch.support_email = "help@example.com"
    switch.show_signed_in_account = True

    # Local switch (the default): drop our cookie and challenge with prompt=login, so the person at
    # the keyboard signs in as themselves while the previous user's other tabs are left alone. Set
    # this True for a kiosk, where ending the provider session too is the right call.
    switch.end_provider_session_on_switch = False

    # A rule of your own, instead of the configured one. Return True to let the sign-in complete.
    options.events.on_evaluate_access = lambda ctx: (
        ctx.allowed_by_configuration or "tenant.root" in ctx.ark_claims
    )

    # Called before the redirect to the access-denied page. Log it, raise a request-access ticket,
    # or return a response to render your own page instead.
    def on_denied(ctx):
        print(f"[access denied] {ctx.email} ({ctx.reason}) wanted {ctx.return_url}")

    options.events.on_access_denied = on_denied


auth = add_ark_oidc_client(app, client_config(), configure, cookie_secure=REQUIRE_HTTPS)


@app.get("/")
def home():
    if not current_ark.is_authenticated:
        return '<a href="/login">Sign in</a>'
    return f"Signed in as {(current_ark.user or {}).get('email')} &middot; <a href='/logout'>Sign out</a>"


@app.get("/my-no-access")
def my_no_access():
    """
    A page of your own instead of the built-in one.

    Point account_switch.access_denied_path here and set serve_default_page = False; the two POST
    endpoints keep working, and ark_denied_account() gives this page the same information.
    """
    denied = ark_denied_account()
    who = (denied.email if denied else None) or "somebody else"
    return f"""
        <h1>No access</h1>
        <p>This browser is signed in as {who}.</p>
        <form method="post" action="/ark/switch-user">
          <input type="hidden" name="returnUrl" value="/">
          <button type="submit">Sign in as a different user</button>
        </form>
    """, 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)
