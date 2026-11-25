"""The setup probe and the two flows that need no browser."""

from __future__ import annotations

from ark_oauth_client import (
    ArkAuthConfig,
    ArkClientCredentials,
    ArkJson,
    ArkJwt,
    ArkRegistration,
    ArkSetupProbe,
)


def config_for(idp, **overrides):
    data = {
        "authority": idp.issuer,
        "client_id": "confidential-app",
        "client_secret": "top-secret",
        "require_https_metadata": False,
    }
    data.update(overrides)
    return ArkAuthConfig.from_mapping(data)


# -- the setup probe -------------------------------------------------------


def test_probe_pairs_configuration_with_live_metadata(idp):
    probe = ArkSetupProbe(config_for(idp))
    model = probe.probe(origin="https://app.example.com")

    assert model.discovery_ok is True
    assert model.issuer == idp.issuer
    assert model.issuer_mismatch is False
    assert model.redirect_uri == "https://app.example.com/signin-oidc"
    assert model.post_logout_redirect_uri == "https://app.example.com/signout-callback-oidc"
    assert model.supports_dynamic_registration is True
    assert model.supports_client_credentials is True
    assert model.token_endpoint.endswith("/oauth2/token")
    assert model.unsupported_scopes == []


def test_probe_names_a_scope_the_tenant_does_not_publish(idp):
    probe = ArkSetupProbe(config_for(idp, scopes=["openid", "not.a.real.scope"]))
    model = probe.probe(origin="https://app.example.com")
    assert model.unsupported_scopes == ["not.a.real.scope"]


def test_probe_reports_an_unreachable_provider():
    config = ArkAuthConfig.from_mapping(
        {"authority": "http://127.0.0.1:1/nowhere", "client_id": "x"}
    )
    model = ArkSetupProbe(config, timeout=1.0).probe()

    assert model.discovery_ok is False
    assert model.discovery_error


def test_probe_reports_a_missing_authority():
    model = ArkSetupProbe(ArkAuthConfig(client_id="x")).probe()
    assert model.discovery_ok is False
    assert "authority" in (model.discovery_error or "")


def test_the_admin_console_and_integration_links(idp):
    probe = ArkSetupProbe(config_for(idp))
    model = probe.probe(origin="https://app.example.com")

    assert model.tenant_id == idp.tenant
    assert model.admin_console_url == f"{idp.base_url}/{idp.tenant}/admin"
    assert model.integration_page_url == f"{idp.issuer}/oauth2/integrate/confidential-app"


def test_probe_model_is_json_safe(idp):
    model = ArkSetupProbe(config_for(idp)).probe(origin="https://app.example.com")
    import json

    assert json.loads(json.dumps(model.to_dict()))["discovery_ok"] is True


# -- client credentials ----------------------------------------------------


def test_client_credentials_reports_the_exchange(idp):
    # ArkClientCredentials authenticates with client_secret_post, as the .NET class does, so the
    # client it is used with must be registered for that method -- the server matches the
    # registered method exactly rather than accepting whichever one turns up.
    ArkClientCredentials.clear_cache()
    flow = ArkClientCredentials(config_for(idp))
    result = flow.request_token("post-app", "post-secret", ["reports.read"])

    assert result.succeeded is True
    assert result.access_token
    assert result.expires_in == 3600
    assert result.token_endpoint.endswith("/oauth2/token")
    assert result.access_token_payload  # decoded for display
    assert '"sub": "post-app"' in result.access_token_payload, "the service, not a person"


def test_the_secret_is_never_echoed_back(idp):
    flow = ArkClientCredentials(config_for(idp))
    result = flow.request_token("post-app", "post-secret")

    posted = dict(result.request_form)
    assert posted["client_id"] == "post-app"
    assert posted["client_secret"] != "post-secret"
    assert "post-secret" not in str(result.request_form)


def test_client_credentials_caches_until_near_expiry(idp):
    ArkClientCredentials.clear_cache()
    flow = ArkClientCredentials(config_for(idp))

    first = flow.get_token("post-app", "post-secret", ["reports.read"])
    second = flow.get_token("post-app", "post-secret", ["reports.read"])
    assert second is first

    ArkClientCredentials.clear_cache()
    third = flow.get_token("post-app", "post-secret", ["reports.read"])
    assert third is not first


def test_client_credentials_needs_both_halves(idp):
    flow = ArkClientCredentials(config_for(idp))
    result = flow.request_token("post-app", "")

    assert result.succeeded is False
    assert result.error == "invalid_client"


def test_the_registered_auth_method_must_match(idp):
    """confidential-app is registered for client_secret_basic; this flow always posts."""
    flow = ArkClientCredentials(config_for(idp))
    result = flow.request_token("confidential-app", "top-secret")

    assert result.succeeded is False
    assert result.error == "invalid_client"
    assert "registered for" in (result.error_description or "")


def test_a_wrong_secret_is_reported_readably(idp):
    flow = ArkClientCredentials(config_for(idp))
    result = flow.request_token("post-app", "not-the-secret")

    assert result.succeeded is False
    assert result.error == "invalid_client"
    assert "secret" in (result.error_description or "")


# -- dynamic registration --------------------------------------------------


def test_registration_round_trip(idp):
    config = config_for(idp)
    probe = ArkSetupProbe(config)
    initial = (
        ArkClientCredentials(config, probe)
        .request_token("post-app", "post-secret", ["client.register"])
        .access_token
    )

    registration = ArkRegistration(probe)
    created = registration.register(
        {"client_name": "a new client", "redirect_uris": ["https://app.example.com/signin-oidc"]},
        initial,
    )

    assert created.succeeded is True
    assert created.client_id.startswith("generated-")
    assert created.client_secret == "generated-secret"
    assert created.registration_access_token
    assert created.request_body and "a new client" in created.request_body

    read_back = registration.read(created.client_id, created.registration_access_token)
    assert read_back.succeeded is True
    assert read_back.client_id == created.client_id

    deleted = registration.delete(created.client_id, created.registration_access_token)
    assert deleted.succeeded is True
    assert deleted.status_code == 204


def test_registration_without_a_token_is_refused(idp):
    registration = ArkRegistration(ArkSetupProbe(config_for(idp)))
    result = registration.register({"client_name": "x"})

    assert result.succeeded is False
    assert result.error == "invalid_token"


# -- display helpers -------------------------------------------------------


def test_ark_jwt_decodes_a_payload_for_display():
    import json

    from ark_oauth_client import base64url_encode

    header = base64url_encode(json.dumps({}))
    payload = base64url_encode(json.dumps({"sub": "alice"}))
    assert '"sub": "alice"' in (ArkJwt.decode_payload(f"{header}.{payload}.sig") or "")


def test_ark_jwt_says_so_when_the_token_is_opaque():
    assert "opaque" in (ArkJwt.decode_payload("not-a-jwt") or "")
    assert ArkJwt.decode_payload(None) is None


def test_ark_json_leaves_non_json_alone():
    assert ArkJson.prettify('{"a":1}') == '{\n  "a": 1\n}'
    assert ArkJson.prettify("not json") == "not json"
    assert ArkJson.prettify(None) == ""


def test_a_wrong_secret_is_not_answered_from_the_cache(idp):
    """The cache is keyed on the credential: the right client_id is not enough."""
    ArkClientCredentials.clear_cache()
    flow = ArkClientCredentials(config_for(idp))
    good = flow.get_token("post-app", "post-secret", ["reports.read"])
    assert good.succeeded

    wrong = flow.get_token("post-app", "WRONG-SECRET", ["reports.read"])
    assert wrong is not good
    assert wrong.succeeded is False
    assert wrong.error == "invalid_client"


def test_a_secret_is_not_sent_to_a_plain_http_provider(idp):
    """The helpers ask what the client's constructor asks: https, unless loopback or told otherwise."""
    seen = []

    def transport(url, method, headers, body, timeout):
        seen.append((method, url))
        return 200, {"Content-Type": "application/json"}, b"{}"

    config = config_for(
        idp, authority="http://idp.example.com/t", require_https_metadata=True
    )
    result = ArkClientCredentials(config, transport=transport).request_token("post-app", "post-secret")
    assert not result.succeeded and "plain http" in result.error_description
    assert seen == [], "nothing was sent, the discovery request included"

    registration = ArkRegistration(ArkSetupProbe(config, transport=transport), transport=transport)
    refused = registration.register({"client_name": "x"}, "initial-access-token")
    assert not refused.succeeded and "plain http" in refused.error_description
    assert seen == []


def test_a_secret_is_not_sent_where_another_issuer_says(idp):
    import json

    seen = []

    def transport(url, method, headers, body, timeout):
        seen.append((method, url))
        document = {"issuer": "https://elsewhere.example/t", "token_endpoint": "https://elsewhere.example/token"}
        return 200, {"Content-Type": "application/json"}, json.dumps(document).encode()

    config = config_for(idp, authority="https://idp.example.com/t", require_https_metadata=True)
    probe = ArkSetupProbe(config, transport=transport)
    result = ArkClientCredentials(config, probe, transport=transport).request_token("post-app", "post-secret")

    assert not result.succeeded and "identifies itself as" in result.error_description
    assert [method for method, _ in seen] == ["GET"], "the secret went nowhere"
    # A set-up page still gets to show the mismatch.
    assert probe.probe().issuer_mismatch is True


def test_the_discovery_cache_makes_the_same_checks(idp):
    import json

    from ark_oauth_client import ArkDiscoveryCache

    def says(issuer):
        return lambda *_args: (200, {}, json.dumps({"issuer": issuer}).encode())

    ArkDiscoveryCache.clear()
    try:
        assert ArkDiscoveryCache.get(idp.issuer)["issuer"] == idp.issuer
        plain = "http://idp.example.com/t"
        assert ArkDiscoveryCache.get(plain, transport=says(plain)) is None
        assert ArkDiscoveryCache.get(plain, require_https=False, transport=says(plain))
        other = says("https://elsewhere.example/t")
        assert ArkDiscoveryCache.get("https://idp.example.com/t", transport=other) is None
    finally:
        ArkDiscoveryCache.clear()


def test_a_failed_onboarding_call_does_not_repeat_the_password():
    from ark_oauth_client import AuthClientHelper

    config = ArkAuthConfig.from_mapping(
        {"auth_server_url": "http://127.0.0.1:9", "tenant_id": "t", "client_id": "c"}
    )
    answer = AuthClientHelper(config, "service-token").onboard_user(
        "bob@example.com", "S3cret-Pa55!", "reader", "Bob"
    )
    assert answer["error"] is True
    assert "S3cret" not in str(answer) and "user_pw" not in str(answer)
    assert "/api/oauth/onboard/user" in answer["data"], "what failed is still said"
