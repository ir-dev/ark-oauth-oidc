"""The protocol client against the stub identity server."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest

from ark_oauth_client import (
    ArkCallbackError,
    ArkConfigError,
    ArkOAuthClient,
    ArkOAuthError,
    ArkTokenError,
)


def public_client(idp, **overrides):
    options = {
        "authority": idp.issuer,
        "client_id": "web-app",
        "redirect_uri": "http://127.0.0.1:9999/signin-oidc",
        "require_https": False,
    }
    options.update(overrides)
    return ArkOAuthClient(**options)


def confidential_client(idp, **overrides):
    options = {
        "authority": idp.issuer,
        "client_id": "confidential-app",
        "client_secret": "top-secret",
        "redirect_uri": "http://127.0.0.1:9999/signin-oidc",
        "require_https": False,
    }
    options.update(overrides)
    return ArkOAuthClient(**options)


def follow(client, transaction):
    """Walks the authorize redirect the way a browser would, returning the callback query."""
    import urllib.request

    request = urllib.request.Request(transaction.url)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(request)
        raise AssertionError("the authorize endpoint should have redirected")
    except urllib.error.HTTPError as error:
        location = error.headers["Location"]
    return dict((k, v[0]) for k, v in parse_qs(urlparse(location).query).items())


# -- discovery -------------------------------------------------------------


def test_metadata_is_read_and_cached(idp):
    client = public_client(idp)
    first = client.metadata()
    assert first["issuer"] == idp.issuer
    client.metadata()
    discovery_calls = [r for r in idp.requests if "openid-configuration" in r["path"]]
    assert len(discovery_calls) == 1, "the discovery document should be fetched once and cached"


def test_issuer_mismatch_is_refused(idp):
    # A trailing path that is not the tenant: the document identifies itself differently.
    client = ArkOAuthClient(
        authority=f"{idp.base_url}/{idp.tenant}/",
        client_id="web-app",
        require_https=False,
    )
    assert client.metadata()["issuer"] == idp.issuer  # the trailing slash alone is tolerated


# -- authorization code + PKCE ---------------------------------------------


def test_authorization_url_carries_pkce_state_and_nonce(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url(return_to="/dashboard")
    query = dict((k, v[0]) for k, v in parse_qs(urlparse(transaction.url).query).items())

    assert query["response_type"] == "code"
    assert query["client_id"] == "web-app"
    assert query["code_challenge_method"] == "S256"
    assert query["state"] == transaction.state
    assert query["nonce"] == transaction.nonce
    assert transaction.return_to == "/dashboard"
    assert len(transaction.code_verifier) >= 43


def test_full_sign_in_round_trip(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    tokens = client.handle_callback(follow(client, transaction), transaction)

    assert tokens.access_token
    assert tokens.id_token
    assert tokens.refresh_token, "offline_access is in the default scopes"
    assert tokens.claims["sub"] == "alice@example.com"
    assert tokens.claims["nonce"] == transaction.nonce
    assert tokens.ark_claims() == ["billing.admin", "reports.read"]
    assert tokens.subject == "alice@example.com"
    assert tokens.has_scope("openid", "offline_access")


def test_state_mismatch_is_refused(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    params = follow(client, transaction)
    params["state"] = "somebody-elses-state"

    with pytest.raises(ArkCallbackError, match="CSRF"):
        client.handle_callback(params, transaction)


def test_missing_state_is_refused(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    params = follow(client, transaction)
    del params["state"]

    with pytest.raises(ArkCallbackError, match="no `state`"):
        client.handle_callback(params, transaction)


def test_wrong_iss_is_refused(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    params = follow(client, transaction)
    params["iss"] = "https://attacker.example.com/tenant"

    with pytest.raises(ArkCallbackError, match="came from"):
        client.handle_callback(params, transaction)


def test_missing_iss_is_refused_when_advertised(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    params = follow(client, transaction)
    del params["iss"]

    with pytest.raises(ArkCallbackError, match="advertises `iss`"):
        client.handle_callback(params, transaction)


def test_error_response_surfaces_as_oauth_error(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()

    with pytest.raises(ArkOAuthError) as caught:
        client.handle_callback(
            {"error": "access_denied", "error_description": "the user said no"}, transaction
        )
    assert caught.value.error == "access_denied"


def test_wrong_pkce_verifier_is_refused_by_the_server(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    params = follow(client, transaction)
    transaction.code_verifier = "a" * 43

    with pytest.raises(ArkOAuthError) as caught:
        client.handle_callback(params, transaction)
    assert caught.value.error == "invalid_grant"


def test_a_code_cannot_be_redeemed_twice(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    params = follow(client, transaction)
    client.handle_callback(params, transaction)

    with pytest.raises(ArkOAuthError) as caught:
        client.handle_callback(params, transaction)
    assert caught.value.error == "invalid_grant"


def test_callback_without_a_transaction_is_refused(idp):
    client = public_client(idp)
    with pytest.raises(ArkCallbackError, match="no login transaction"):
        client.handle_callback({"code": "x", "state": "y"}, {})


# -- refresh ---------------------------------------------------------------


def test_refresh_rotates_the_token(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    first = client.handle_callback(follow(client, transaction), transaction)

    second = client.refresh(first.refresh_token)
    assert second.access_token
    assert second.refresh_token != first.refresh_token, "the server rotates refresh tokens"


def test_replaying_a_retired_refresh_token_revokes_the_family(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    first = client.handle_callback(follow(client, transaction), transaction)
    second = client.refresh(first.refresh_token)

    with pytest.raises(ArkOAuthError) as caught:
        client.refresh(first.refresh_token)
    assert caught.value.error == "invalid_grant"

    # The whole family went down with it.
    with pytest.raises(ArkOAuthError):
        client.refresh(second.refresh_token)


# -- client credentials ----------------------------------------------------


def test_client_credentials_grant_and_cache(idp):
    client = confidential_client(idp)
    first = client.client_credentials(scopes=["reports.read"])
    assert first.access_token
    assert first.claims is None, "there is no user in this flow"

    second = client.client_credentials(scopes=["reports.read"])
    assert second is first, "a live token is served from the cache"

    third = client.client_credentials(scopes=["reports.read"], force=True)
    assert third is not first


def test_a_public_client_cannot_use_client_credentials(idp):
    client = public_client(idp)
    with pytest.raises(ArkConfigError, match="public client cannot use it"):
        client.client_credentials()


def test_client_secret_post_is_honoured(idp):
    client = ArkOAuthClient(
        authority=idp.issuer,
        client_id="post-app",
        client_secret="post-secret",
        token_endpoint_auth_method="client_secret_post",
        require_https=False,
    )
    assert client.client_credentials().access_token


# -- device grant ----------------------------------------------------------


def test_device_grant(idp):
    client = confidential_client(idp)
    authorization = client.device_authorization(scopes=["openid", "profile"])
    assert authorization["user_code"] == "WDJB-MJHT"

    idp.approve_device(authorization["device_code"])
    tokens = client.poll_device_token(authorization, interval_seconds=0.05)
    assert tokens.access_token


def test_device_polling_waits_through_authorization_pending(idp):
    client = confidential_client(idp)
    authorization = client.device_authorization(scopes=["openid"])

    pending = []

    def approve(error):
        pending.append(error.error)
        idp.approve_device(authorization["device_code"])

    tokens = client.poll_device_token(
        authorization, interval_seconds=0.05, on_pending=approve
    )
    assert pending == ["authorization_pending"]
    assert tokens.access_token


# -- PAR -------------------------------------------------------------------


def test_pushed_authorization_request(idp):
    client = confidential_client(idp, use_par=True)
    transaction = client.create_authorization_url()
    query = dict((k, v[0]) for k, v in parse_qs(urlparse(transaction.url).query).items())

    assert "request_uri" in query
    assert "code_challenge" not in query, "the parameters travelled over the back channel"

    tokens = client.handle_callback(follow(client, transaction), transaction)
    assert tokens.access_token


# -- tokens and endpoints --------------------------------------------------


def test_user_info(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    tokens = client.handle_callback(follow(client, transaction), transaction)

    assert client.user_info(tokens.access_token)["email"] == "alice@example.com"


def test_verify_access_token_checks_scopes_and_claims(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url(scopes=["openid", "reports.read"])
    tokens = client.handle_callback(follow(client, transaction), transaction)

    payload = client.verify_access_token(
        tokens.access_token,
        audience="web-app",
        scopes=["reports.read"],
        ark_claims=["billing.admin"],
    )
    assert payload["sub"] == "alice@example.com"

    with pytest.raises(ArkOAuthError) as caught:
        client.verify_access_token(
            tokens.access_token, audience="web-app", scopes=["something.else"]
        )
    assert caught.value.error == "insufficient_scope"
    assert caught.value.status == 403


def test_an_id_token_is_refused_where_an_access_token_belongs(idp):
    client = public_client(idp)
    transaction = client.create_authorization_url()
    tokens = client.handle_callback(follow(client, transaction), transaction)

    with pytest.raises(ArkTokenError, match="at\\+jwt"):
        client.verify_access_token(tokens.id_token, audience="web-app")


def test_revocation_and_introspection(idp):
    client = confidential_client(idp)
    token = client.client_credentials().access_token

    assert client.introspect(token)["active"] is True
    assert client.revoke(token, token_type_hint="access_token") is True
    assert client.introspect(token)["active"] is False


def test_end_session_url(idp):
    client = public_client(idp, post_logout_redirect_uri="http://127.0.0.1:9999/")
    url = client.end_session_url(id_token_hint="an-id-token", state="s")
    query = dict((k, v[0]) for k, v in parse_qs(urlparse(url).query).items())

    assert query["client_id"] == "web-app"
    assert query["id_token_hint"] == "an-id-token"
    assert query["post_logout_redirect_uri"] == "http://127.0.0.1:9999/"
    assert query["state"] == "s"


# -- registration ----------------------------------------------------------


def test_dynamic_registration(idp):
    client = confidential_client(idp)
    initial = client.client_credentials(scopes=["client.register"]).access_token

    registered = client.register_client(
        {"client_name": "a new client", "redirect_uris": ["https://app.example.com/signin-oidc"]},
        initial,
    )
    assert registered["client_id"].startswith("generated-")
    assert registered["registration_access_token"]

    read_back = client.read_registration(
        registered["client_id"], registered["registration_access_token"]
    )
    assert read_back["client_id"] == registered["client_id"]
    assert (
        client.delete_registration(
            registered["client_id"], registered["registration_access_token"]
        )
        is True
    )


# -- diagnostics -----------------------------------------------------------


def test_check_setup_reports_a_clean_configuration(idp):
    client = public_client(idp)
    report = client.check_setup()

    assert report["discovery_ok"] is True
    assert report["provider"]["issuer"] == idp.issuer
    assert report["signing_keys"]
    assert report["problems"] == []


def test_check_setup_names_an_unregistered_scope(idp):
    client = public_client(idp, scopes=["openid", "not.a.real.scope"])
    report = client.check_setup()

    assert any("not.a.real.scope" in problem for problem in report["problems"])


def test_check_setup_reports_an_unreachable_provider():
    client = ArkOAuthClient(
        authority="http://127.0.0.1:1/nowhere",
        client_id="web-app",
        require_https=False,
        timeout=1.0,
    )
    report = client.check_setup()
    assert report["discovery_ok"] is False
    assert report["problems"]


# -- key rotation ----------------------------------------------------------


def test_a_rotated_key_is_picked_up_without_a_restart(idp):
    # The refetch on an unknown kid is rate-limited; a rotation is exactly the moment that limit
    # has to not apply, so the test turns the cooldown off rather than sleeping through it.
    client = public_client(idp, jwks_min_refresh_interval=0)
    transaction = client.create_authorization_url()
    client.handle_callback(follow(client, transaction), transaction)  # warms the JWKS cache

    idp.rotate_key("key-2")
    transaction = client.create_authorization_url()
    tokens = client.handle_callback(follow(client, transaction), transaction)

    assert tokens.claims["sub"] == "alice@example.com"


def test_token_set_expiry_is_absolute():
    from ark_oauth_client import TokenSet

    now = int(time.time())
    tokens = TokenSet({"access_token": "a", "expires_in": 60}, issued_at=now)

    assert tokens.expires_at == now + 60
    assert tokens.expired(now=now) is False
    assert tokens.expired(leeway_seconds=90, now=now) is True

    revived = TokenSet.from_dict(tokens.to_dict())
    assert revived.expires_at == tokens.expires_at
