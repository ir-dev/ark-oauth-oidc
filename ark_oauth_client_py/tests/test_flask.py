"""The Flask integration: sign-in, guards, the API side, and account switching."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from flask import Flask, jsonify

from ark_oauth_client import ArkAccessDeniedReasons, ArkClientEvents
from ark_oauth_client.flask import (
    add_ark_oidc_api,
    add_ark_oidc_client,
    current_ark,
    get_ark_access_token,
    with_ark_token,
)

SECRET = "a-test-session-secret-of-sufficient-length"


def make_app(idp, *, configure=None, events=None, **config_overrides):
    app = Flask(__name__)
    app.secret_key = SECRET
    app.config["TESTING"] = True

    config = {
        "authority": idp.issuer,
        "client_id": "web-app",
        "require_https_metadata": False,
    }
    config.update(config_overrides)

    auth = add_ark_oidc_client(
        app, config, configure, cookie_secure=False, secret=SECRET
    )
    if events is not None:
        auth.events = events

    @app.get("/")
    def home():
        return "signed in" if current_ark.is_authenticated else "anonymous"

    @app.get("/me")
    @auth.require_auth()
    def me():
        return jsonify(
            {
                "sub": current_ark.sub,
                "name": (current_ark.user or {}).get("name"),
                "claims": current_ark.claims,
                "scopes": current_ark.scopes,
                "token": bool(get_ark_access_token()),
                "headers": with_ark_token({"X-Test": "1"}),
            }
        )

    @app.get("/billing")
    @auth.require_claims("billing.admin")
    def billing():
        return "billing"

    @app.get("/finance")
    @auth.require_claims("finance.admin")
    def finance():
        return "finance"

    @app.get("/reports")
    @auth.require_scopes("reports.read")
    def reports():
        return "reports"

    @app.get("/setup")
    def setup():
        return jsonify(auth.setup_model().to_dict())

    return app, auth


def sign_in(app, client, *, accept_html=True):
    """Walks /login -> the provider -> the callback, the way a browser would."""
    import urllib.error
    import urllib.request

    login = client.get("/login", headers={"Accept": "text/html"} if accept_html else {})
    assert login.status_code == 302
    authorize_url = login.headers["Location"]

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None

    try:
        urllib.request.build_opener(NoRedirect).open(authorize_url)
        raise AssertionError("the authorize endpoint should have redirected")
    except urllib.error.HTTPError as error:
        callback = error.headers["Location"]

    return client.get(urlparse(callback).path + "?" + urlparse(callback).query)


# -- sign-in ---------------------------------------------------------------


def test_login_redirects_to_the_provider_with_pkce(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        response = client.get("/login")

    assert response.status_code == 302
    query = dict((k, v[0]) for k, v in parse_qs(urlparse(response.headers["Location"]).query).items())
    assert query["client_id"] == "web-app"
    assert query["code_challenge_method"] == "S256"
    assert query["redirect_uri"].endswith("/signin-oidc")
    assert "nonce" in query and "state" in query


def test_a_full_sign_in_produces_a_session(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        callback = sign_in(app, client)
        assert callback.status_code == 302
        assert callback.headers["Location"] == "/"

        assert client.get("/").data == b"signed in"

        me = client.get("/me").get_json()
        assert me["sub"] == "alice@example.com"
        assert me["name"] == "Alice Example"
        assert me["claims"] == ["billing.admin", "reports.read"]
        assert me["token"] is True
        assert me["headers"]["Authorization"].startswith("Bearer ")
        assert me["headers"]["X-Test"] == "1"


def test_the_session_cookie_carries_no_token(idp):
    app, auth = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)
        value = _cookie_value(client, auth.cookie_name)

    # The cookie is an opaque id plus a signature over it, and nothing else.
    assert value, "the sign-in should have set a session cookie"
    assert "." in value
    assert "eyJ" not in value, "a JWT must never reach the browser"
    session_id, _, signature = value.rpartition(".")
    assert session_id and signature
    # The tokens are on the server, reachable only through the store.
    stored = auth.store.get(session_id)
    assert stored["tokens"]["access_token"].startswith("eyJ")


def test_return_to_comes_back_to_the_same_page(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        login = client.get("/login?returnTo=/billing")
        assert login.status_code == 302
        callback = sign_in_from(client, login)
        assert callback.headers["Location"] == "/billing"


def sign_in_from(client, login_response):
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None

    try:
        urllib.request.build_opener(NoRedirect).open(login_response.headers["Location"])
        raise AssertionError("expected a redirect")
    except urllib.error.HTTPError as error:
        callback = error.headers["Location"]
    parsed = urlparse(callback)
    return client.get(parsed.path + "?" + parsed.query)


def test_an_open_redirect_is_not_followed(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        login = client.get("/login?returnTo=https://evil.example.com/")
        callback = sign_in_from(client, login)
        assert callback.headers["Location"] == "/"


def test_a_callback_with_no_transaction_is_refused(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        response = client.get("/signin-oidc?code=x&state=y")

    assert response.status_code == 400
    assert b"could not be matched" in response.data


def test_the_session_id_is_replaced_at_sign_in(idp):
    """Session fixation: an id planted before sign-in must not be the authenticated one."""
    app, auth = make_app(idp)
    with app.test_client() as client:
        client.get("/login")  # writes a pre-authentication session cookie
        before = _cookie_value(client, auth.cookie_name)
        sign_in(app, client)
        after = _cookie_value(client, auth.cookie_name)

    assert before and after and before != after


def _cookie_value(client, name):
    for cookie in getattr(client, "_cookies", {}).values():
        if getattr(cookie, "key", getattr(cookie, "name", None)) == name:
            return cookie.value
    return None


# -- guards ----------------------------------------------------------------


def test_an_anonymous_browser_request_is_sent_to_the_login_page(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        response = client.get("/me", headers={"Accept": "text/html"})

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login?returnTo=")


def test_an_anonymous_api_request_gets_401_and_a_challenge(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        response = client.get("/me", headers={"Accept": "application/json"})

    assert response.status_code == 401
    assert "Bearer" in response.headers["WWW-Authenticate"]
    assert response.get_json()["error"] == "invalid_token"


def test_a_held_claim_passes_and_a_missing_one_is_refused(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)

        assert client.get("/billing", headers={"Accept": "application/json"}).status_code == 200

        refused = client.get("/finance", headers={"Accept": "application/json"})
        assert refused.status_code == 403
        assert refused.get_json()["error"] == "insufficient_scope"
        assert "finance.admin" in refused.get_json()["error_description"]


def test_a_missing_scope_is_refused(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)
        refused = client.get("/reports", headers={"Accept": "application/json"})

    assert refused.status_code == 403
    assert "reports.read" in refused.get_json()["error_description"]


# -- sign-out --------------------------------------------------------------


def test_logout_revokes_the_refresh_token_and_ends_the_session(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)
        assert client.get("/").data == b"signed in"

        response = client.get("/logout")
        assert response.status_code == 302
        assert "/oauth2/logout" in response.headers["Location"]
        assert idp.revoked, "the refresh token should be revoked at the provider"

        assert client.get("/").data == b"anonymous"


# -- account switching -----------------------------------------------------


def test_a_user_with_no_ark_claims_is_refused_before_a_session_exists(idp):
    idp.ark_claims = []
    app, _ = make_app(idp, configure=_require_claims)

    with app.test_client() as client:
        callback = sign_in(app, client)

        assert callback.status_code == 302
        assert callback.headers["Location"].startswith("/ark/no-access")
        # The whole point: no session was written for the account that was refused.
        assert client.get("/").data == b"anonymous"


def _require_claims(options):
    options.config.account_switch.require_ark_claims = True


def test_the_access_denied_page_names_the_account_and_offers_a_way_out(idp):
    idp.ark_claims = []
    app, _ = make_app(idp, configure=_require_claims)

    with app.test_client() as client:
        callback = sign_in(app, client)
        page = client.get(callback.headers["Location"])

    assert page.status_code == 403
    body = page.data.decode()
    assert "alice@example.com" in body, "the page has to say whose session this is"
    assert "Sign in as a different user" in body
    assert 'action="/ark/switch-user"' in body
    assert 'action="/ark/sign-out"' in body
    assert "no-store" in page.headers["Cache-Control"]


def test_the_denial_cookie_is_spent_on_first_read(idp):
    idp.ark_claims = []
    app, _ = make_app(idp, configure=_require_claims)

    with app.test_client() as client:
        callback = sign_in(app, client)
        target = callback.headers["Location"]
        assert "alice@example.com" in client.get(target).data.decode()
        # Second visit: the cookie is gone, so the page falls back to the unnamed wording.
        assert "alice@example.com" not in client.get(target).data.decode()


def test_switch_user_challenges_with_prompt_login(idp):
    app, _ = make_app(idp, configure=_require_claims)

    with app.test_client() as client:
        response = client.post(
            "/ark/switch-user",
            data={"returnUrl": "/billing"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )

    assert response.status_code == 302
    query = dict((k, v[0]) for k, v in parse_qs(urlparse(response.headers["Location"]).query).items())
    assert query["prompt"] == "login", "without this the provider answers from the old session"


def test_the_switch_endpoints_refuse_a_get(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        response = client.get("/ark/switch-user")

    assert response.status_code == 405
    assert response.headers["Allow"] == "POST"


def test_the_switch_endpoints_refuse_a_cross_site_post(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        response = client.post(
            "/ark/switch-user", headers={"Sec-Fetch-Site": "cross-site"}
        )

    assert response.status_code == 400
    assert b"cross-site" in response.data


def test_sign_out_completely_ends_both_sessions(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)
        response = client.post(
            "/ark/sign-out", headers={"Sec-Fetch-Site": "same-origin"}
        )

    assert response.status_code == 302
    assert "/oauth2/logout" in response.headers["Location"]


def test_a_403_reaches_the_access_denied_page_not_a_404(idp):
    """The framework default most apps never create renders as a 404; this must not."""
    app, _ = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)
        response = client.get("/finance", headers={"Accept": "text/html"})

        assert response.status_code == 302
        assert response.headers["Location"].startswith("/ark/no-access")

        page = client.get(response.headers["Location"])
        assert page.status_code == 403
        assert b"do not have access" in page.data


def test_a_host_rule_can_replace_the_configured_one(idp):
    events = ArkClientEvents(on_evaluate_access=lambda ctx: "billing.admin" in ctx.ark_claims)
    app, _ = make_app(idp, configure=_require_claims, events=events)

    with app.test_client() as client:
        assert sign_in(app, client).headers["Location"] == "/"

    idp.ark_claims = ["something.else"]
    app, _ = make_app(idp, configure=_require_claims, events=events)
    with app.test_client() as client:
        assert sign_in(app, client).headers["Location"].startswith("/ark/no-access")


def test_a_host_can_render_its_own_denial(idp):
    seen = {}

    def on_denied(ctx):
        seen["reason"] = ctx.reason
        seen["email"] = ctx.email
        return "our own page", 403

    idp.ark_claims = []
    app, _ = make_app(
        idp,
        configure=_require_claims,
        events=ArkClientEvents(on_access_denied=on_denied),
    )

    with app.test_client() as client:
        response = sign_in(app, client)

    assert response.status_code == 403
    assert response.data == b"our own page"
    assert seen["reason"] == ArkAccessDeniedReasons.NO_APP_ACCESS
    assert seen["email"] == "alice@example.com"


def test_required_claims_narrows_the_check(idp):
    def configure(options):
        options.config.account_switch.require_ark_claims = True
        options.config.account_switch.required_claims = ["tenant.root"]

    app, _ = make_app(idp, configure=configure)
    with app.test_client() as client:
        # alice holds billing.admin and reports.read, but not tenant.root.
        assert sign_in(app, client).headers["Location"].startswith("/ark/no-access")


def test_the_default_page_can_be_turned_off(idp):
    def configure(options):
        options.config.account_switch.serve_default_page = False

    app, _ = make_app(idp, configure=configure)

    @app.get("/ark/no-access")
    def our_page():
        return "ours", 403

    with app.test_client() as client:
        response = client.get("/ark/no-access")

    assert response.data == b"ours"


def test_support_details_appear_on_the_page(idp):
    def configure(options):
        options.config.account_switch.app_display_name = "Billing Portal"
        options.config.account_switch.support_email = "help@example.com"

    app, _ = make_app(idp, configure=configure)
    with app.test_client() as client:
        body = client.get("/ark/no-access").data.decode()

    assert "Billing Portal" in body
    assert "help@example.com" in body


# -- the API side ----------------------------------------------------------


def test_bearer_tokens_protect_an_api(idp):
    from ark_oauth_client import ArkOAuthClient

    api = Flask(__name__)
    api.config["TESTING"] = True
    bearer = add_ark_oidc_api(
        api,
        "/api",
        authority=idp.issuer,
        client_id="web-app",
        audience=idp.audience,
        require_https=False,
    )

    @api.get("/api/me")
    def me():
        from flask import g

        return jsonify({"sub": g.ark.sub, "claims": g.ark.claims})

    @api.get("/api/reports")
    @bearer.require(claims=["reports.read"])
    def reports():
        return "reports"

    @api.get("/api/finance")
    @bearer.require(claims=["finance.admin"])
    def finance():
        return "finance"

    client = ArkOAuthClient(
        authority=idp.issuer,
        client_id="web-app",
        redirect_uri="http://127.0.0.1:9999/signin-oidc",
        require_https=False,
    )
    transaction = client.create_authorization_url()
    from .test_client import follow

    tokens = client.handle_callback(follow(client, transaction), transaction)
    auth_header = {"Authorization": f"Bearer {tokens.access_token}"}

    with api.test_client() as http:
        assert http.get("/api/me").status_code == 401

        me_response = http.get("/api/me", headers=auth_header)
        assert me_response.status_code == 200
        assert me_response.get_json()["sub"] == "alice@example.com"

        assert http.get("/api/reports", headers=auth_header).status_code == 200

        refused = http.get("/api/finance", headers=auth_header)
        assert refused.status_code == 403
        assert refused.get_json()["error"] == "insufficient_scope"

        garbage = http.get("/api/me", headers={"Authorization": "Bearer not-a-token"})
        assert garbage.status_code == 401


# -- diagnostics -----------------------------------------------------------


def test_the_setup_page_reports_what_this_app_will_send(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        report = client.get("/setup").get_json()

    assert report["discovery_ok"] is True
    assert report["issuer_mismatch"] is False
    assert report["redirect_uri"].endswith("/signin-oidc")
    assert report["client_id"] == "web-app"


# -- silent refresh --------------------------------------------------------


def _grants(idp):
    return [r["form"].get("grant_type") for r in idp.requests if r["path"].endswith("/oauth2/token")]


def test_the_access_token_is_refreshed_before_it_expires(idp):
    """Without this a session survives only as long as its first access token."""
    idp.access_token_lifetime = 60  # inside the 120s refresh window from the first moment
    app, auth = make_app(idp)

    with app.test_client() as client:
        sign_in(app, client)
        idp.requests.clear()

        me = client.get("/me").get_json()

        assert "refresh_token" in _grants(idp), "the access token should have been renewed"
        assert me["token"] is True, "the caller must still get a usable access token"
        assert me["sub"] == "alice@example.com"

        # The renewed token is what is stored, not the spent one.
        value = _cookie_value(client, auth.cookie_name)
        stored = auth.store.get(value.rpartition(".")[0])
        assert stored["tokens"]["access_token"]


def test_a_dead_refresh_token_ends_the_session(idp):
    idp.access_token_lifetime = 60
    app, auth = make_app(idp)

    with app.test_client() as client:
        sign_in(app, client)
        # The provider forgets every refresh token: the next renewal answers invalid_grant.
        idp.refresh_tokens.clear()
        idp.families.clear()

        response = client.get("/")
        assert response.data == b"anonymous"
        # ...and the stale cookie is cleared rather than left to fail on every later request.
        assert _cookie_value(client, auth.cookie_name) in (None, "")


def test_switch_user_completes_a_sign_in_as_the_new_account(idp):
    """The whole point of the switch: the next callback must actually be redeemable."""
    app, _ = make_app(idp, configure=_require_claims)

    with app.test_client() as client:
        sign_in(app, client)  # somebody else is already signed in on this browser
        assert client.get("/").data == b"signed in"

        switch = client.post(
            "/ark/switch-user",
            data={"returnUrl": "/billing"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert switch.status_code == 302

        callback = sign_in_from(client, switch)
        assert callback.status_code == 302, callback.data
        assert callback.headers["Location"] == "/billing"
        assert client.get("/").data == b"signed in"


def test_the_session_cookie_is_secure_by_default(idp):
    """Flask pre-populates SESSION_COOKIE_SECURE=False; that must not turn the default off."""
    app = Flask(__name__)
    app.secret_key = SECRET
    app.config["TESTING"] = True
    auth = add_ark_oidc_client(
        app, {"authority": idp.issuer, "client_id": "web-app", "require_https_metadata": False}, secret=SECRET
    )
    with app.test_client() as client:
        response = client.get("/login")

    cookies = [c for c in response.headers.getlist("Set-Cookie") if c.startswith(auth.cookie_name + "=")]
    assert cookies, "the login step writes the session cookie"
    assert all("Secure" in c for c in cookies)


# -- what a session must not outlive ------------------------------------------


def test_a_refresh_with_rotation_off_leaves_a_session_that_can_be_refreshed_again(idp):
    """The refresh token used to be lost with the first answer, and the session with it stood unchecked."""
    idp.rotate_refresh_tokens = False
    idp.access_token_lifetime = 1
    app, auth = make_app(idp)

    with app.test_client() as client:
        sign_in(app, client)
        assert client.get("/billing").status_code == 200  # refreshed here
        session_id = _session_id(client, auth)
        assert auth.store.get(session_id)["tokens"]["refresh_token"]
        assert auth.store.get(session_id)["tokens"]["id_token"]

        idp.ark_claims = ["reports.read"]
        assert client.get("/billing").status_code == 403, "the withdrawn claim is gone at the next refresh"

        idp.refresh_tokens.clear()  # the account is deactivated
        assert client.get("/").data == b"anonymous"


def test_an_account_that_loses_its_access_is_signed_out_at_the_next_refresh(idp):
    idp.access_token_lifetime = 1
    app, auth = make_app(idp, configure=_require_claims)

    with app.test_client() as client:
        sign_in(app, client)
        assert client.get("/").data == b"signed in"

        idp.ark_claims = []
        assert client.get("/").data == b"anonymous"
        assert len(auth.store) == 0
        assert idp.revoked, "the refresh token that came with the refused answer is revoked"


def test_a_host_rule_that_cannot_answer_on_refresh_is_not_a_yes(idp):
    idp.access_token_lifetime = 1
    answers = iter([True])
    events = ArkClientEvents(on_evaluate_access=lambda _ctx: next(answers))
    app, _ = make_app(idp, events=events)

    with app.test_client() as client:
        sign_in(app, client)
        assert client.get("/").data == b"anonymous", "StopIteration: the rule failed"


def test_a_sign_out_during_a_refresh_is_not_undone_by_it(idp):
    import threading

    idp.access_token_lifetime = 1
    app, auth = make_app(idp)
    client = app.test_client()
    sign_in(app, client)
    session_id = _session_id(client, auth)
    cookie = f"{auth.cookie_name}={_cookie_value(client, auth.cookie_name)}"

    redeemed, proceed = threading.Event(), threading.Event()
    refresh = auth.client.refresh

    def slow(*args, **kwargs):
        answer = refresh(*args, **kwargs)
        redeemed.set()
        proceed.wait(5)
        return answer

    auth.client.refresh = slow
    answers = []

    def request():
        other = app.test_client(use_cookies=False)
        answers.append(other.get("/", headers={"Cookie": cookie}).data)

    thread = threading.Thread(target=request)
    thread.start()
    assert redeemed.wait(5)
    idp.access_token_lifetime = 3600
    with app.test_request_context("/", headers={"Cookie": cookie}):
        auth.sign_out_locally()
    proceed.set()
    thread.join()

    assert answers == [b"anonymous"]
    assert auth.store.get(session_id) is None
    assert app.test_client(use_cookies=False).get("/", headers={"Cookie": cookie}).data == b"anonymous"
    assert auth._refresh_locks == {}


def test_concurrent_requests_share_one_refresh(idp):
    import copy
    import threading
    import time

    from ark_oauth_client import MemorySessionStore

    class SharedStore(MemorySessionStore):
        """A store outside the process: every read is a copy, and a write takes a moment."""

        def get(self, session_id):
            return copy.deepcopy(super().get(session_id))

        def set(self, session_id, data, ttl_seconds):
            time.sleep(0.05)  # where a lock given up early let the next request in
            super().set(session_id, copy.deepcopy(data), ttl_seconds)

    idp.access_token_lifetime = 1
    app, auth = make_app(idp)
    auth.store = SharedStore()
    client = app.test_client()
    sign_in(app, client)
    cookie = f"{auth.cookie_name}={_cookie_value(client, auth.cookie_name)}"
    idp.access_token_lifetime = 3600
    idp.requests.clear()
    answers = []

    def request():
        answers.append(app.test_client(use_cookies=False).get("/", headers={"Cookie": cookie}).data)

    threads = [threading.Thread(target=request) for _ in range(8)]
    for thread in threads:
        thread.start()
        time.sleep(0.01)
    for thread in threads:
        thread.join()

    refreshes = [r for r in idp.requests if r["form"].get("grant_type") == "refresh_token"]
    assert len(refreshes) == 1 and answers == [b"signed in"] * 8


def test_signing_out_locally_and_switching_account_revoke_the_refresh_token(idp):
    app, auth = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)
        client.post("/ark/switch-user")
        assert len(idp.revoked) == 1

    with app.test_client() as client:
        sign_in(app, client)
        cookie = f"{auth.cookie_name}={_cookie_value(client, auth.cookie_name)}"
        with app.test_request_context("/", headers={"Cookie": cookie}):
            auth.sign_out_locally()
        assert len(idp.revoked) == 2


def test_a_refused_sign_in_leaves_neither_a_refresh_token_nor_its_transaction(idp):
    idp.ark_claims = []
    app, auth = make_app(idp, configure=_require_claims)
    with app.test_client() as client:
        sign_in(app, client)
        assert len(idp.revoked) == 1
        assert auth.store.get(_session_id(client, auth))["txs"] == {}


def test_userinfo_about_somebody_else_is_not_used(idp):
    app, auth = make_app(idp)
    auth.fetch_user_info = True
    answer = auth.client.user_info
    auth.client.user_info = lambda token: {**answer(token), "sub": "mallory", "name": "Mallory"}
    with app.test_client() as client:
        sign_in(app, client)
        assert client.get("/me").get_json()["name"] == "Alice Example"

    auth.client.user_info = lambda token: {**answer(token), "name": "Alice from UserInfo"}
    with app.test_client() as client:
        sign_in(app, client)
        assert client.get("/me").get_json()["name"] == "Alice from UserInfo"


# -- signing out from somebody else's page ------------------------------------


def test_a_sign_out_another_site_asked_for_is_a_question(idp):
    app, _ = make_app(idp)
    with app.test_client() as client:
        sign_in(app, client)

        asked = client.get("/logout", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"})
        assert asked.status_code == 200
        body = asked.data.decode()
        assert "Sign out of web-app?" in body and '<form method="post" action="/logout">' in body
        assert asked.headers["X-Frame-Options"] == "DENY" and "no-store" in asked.headers["Cache-Control"]
        assert client.get("/").data == b"signed in" and idp.revoked == []

        forged = client.post("/logout", headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
        assert forged.status_code == 400
        # An older browser sends no Sec-Fetch-Site, but a cross-site form carries its Origin.
        assert client.post("/logout", headers={"Origin": "https://evil.example"}).status_code == 400
        assert client.get("/").data == b"signed in"

        # The page's own button.
        done = client.post("/logout", headers={"Sec-Fetch-Site": "same-origin"})
        assert done.status_code == 302 and "id_token_hint=" in done.headers["Location"]
        assert client.get("/").data == b"anonymous" and len(idp.revoked) == 1


def test_a_link_on_this_site_and_a_typed_address_sign_out_as_before(idp):
    app, _ = make_app(idp)
    for site in (None, "none", "same-origin", "same-site"):
        with app.test_client() as client:
            sign_in(app, client)
            response = client.get("/logout", headers={"Sec-Fetch-Site": site} if site else {})
            assert response.status_code == 302, site
            assert client.get("/").data == b"anonymous"


# -- what arrives from outside -------------------------------------------------


def test_a_visit_to_the_login_page_is_not_kept_for_a_working_day(idp):
    from ark_oauth_client.flask import TRANSACTION_TTL_SECONDS

    app, auth = make_app(idp)
    kept = []
    write = auth.store.set
    auth.store.set = lambda sid, data, ttl: (kept.append(ttl), write(sid, data, ttl))

    with app.test_client() as client:
        response = client.get("/login")
        assert kept == [TRANSACTION_TTL_SECONDS]
        assert f"Max-Age={TRANSACTION_TTL_SECONDS}" in response.headers["Set-Cookie"]
        sign_in(app, client)
        assert kept[-1] == auth.session_ttl_seconds


def test_a_key_id_with_a_line_break_is_a_401_and_not_a_500(idp):
    import base64
    import json

    api = Flask(__name__)
    add_ark_oidc_api(api, "/api", authority=idp.issuer, client_id="web-app", require_https=False)

    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    header = {"alg": "RS256", "typ": "at+jwt", "kid": 'a\r\nX-Injected: "y" \u2603'}
    token = f"{segment(header)}.{segment({})}.AA"
    response = api.test_client().get("/api/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert "X-Injected" not in response.headers
    assert "\n" not in response.headers["WWW-Authenticate"]


def test_the_callers_address_is_the_one_the_proxy_wrote(idp):
    app, auth = make_app(idp)

    @app.get("/ip")
    def ip():
        return jsonify(current_ark.context().ip)

    forged = {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"}
    assert app.test_client().get("/ip", headers=forged).get_json() == "203.0.113.9"
    auth.trust_proxy = False
    assert app.test_client().get("/ip", headers=forged).get_json() == "127.0.0.1"


def _session_id(client, auth):
    from ark_oauth_client.session import unsign_session_id

    return unsign_session_id(_cookie_value(client, auth.cookie_name), SECRET)
