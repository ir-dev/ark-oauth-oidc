"""Configuration: the protocol client's options, and the appsettings section the .NET client binds."""

from __future__ import annotations

import pytest

from ark_oauth_client import (
    ArkAccountSwitchOptions,
    ArkAuthConfig,
    ArkConfigError,
    DEFAULT_SCOPES,
    normalize_config,
)


def base(**overrides):
    options = {"authority": "https://idp.example.com/my_idp", "client_id": "my-app"}
    options.update(overrides)
    return normalize_config(**options)


# -- the protocol client's options -----------------------------------------


def test_authority_and_client_id_are_the_only_requirements():
    config = base()
    assert config.authority == "https://idp.example.com/my_idp"
    assert config.scopes == DEFAULT_SCOPES
    assert config.token_endpoint_auth_method == "none"
    assert config.is_confidential is False


def test_auth_server_url_and_tenant_id_are_joined():
    config = normalize_config(
        auth_server_url="https://idp.example.com/", tenant_id="my_idp", client_id="my-app"
    )
    assert config.authority == "https://idp.example.com/my_idp"


def test_a_missing_authority_is_refused():
    with pytest.raises(ArkConfigError, match="authority"):
        normalize_config(client_id="my-app")


def test_a_missing_client_id_is_refused():
    with pytest.raises(ArkConfigError, match="client_id"):
        normalize_config(authority="https://idp.example.com/my_idp")


def test_a_plain_http_authority_is_refused_unless_loopback():
    with pytest.raises(ArkConfigError, match="plain http"):
        normalize_config(authority="http://idp.example.com/my_idp", client_id="my-app")

    # Loopback is how local development works, and the server allows it too.
    assert normalize_config(authority="http://localhost:5001/my_idp", client_id="my-app")
    assert normalize_config(authority="http://127.0.0.1:5001/my_idp", client_id="my-app")


def test_a_secret_selects_basic_authentication():
    assert base(client_secret="s").token_endpoint_auth_method == "client_secret_basic"


def test_a_secret_alongside_method_none_is_refused():
    with pytest.raises(ArkConfigError, match="token_endpoint_auth_method is 'none'"):
        base(client_secret="s", token_endpoint_auth_method="none")


def test_private_key_jwt_needs_a_key():
    with pytest.raises(ArkConfigError, match="private_key"):
        base(token_endpoint_auth_method="private_key_jwt")


def test_a_redirect_uri_with_a_fragment_is_refused():
    with pytest.raises(ArkConfigError, match="fragment"):
        base(redirect_uri="https://app.example.com/signin-oidc#x")


def test_a_plain_http_redirect_uri_is_refused_unless_loopback():
    with pytest.raises(ArkConfigError, match="loopback"):
        base(redirect_uri="http://app.example.com/signin-oidc")

    assert base(redirect_uri="http://127.0.0.1:3000/signin-oidc").redirect_uri


def test_an_unknown_response_mode_is_refused():
    with pytest.raises(ArkConfigError, match="response_mode"):
        base(response_mode="fragment_post")


def test_a_trailing_slash_on_the_authority_is_trimmed():
    assert base(authority="https://idp.example.com/my_idp/").authority == (
        "https://idp.example.com/my_idp"
    )


# -- the appsettings section -----------------------------------------------


def test_the_csharp_spelling_binds():
    config = ArkAuthConfig.from_mapping(
        {
            "ark_oauth_client": {
                "AuthServerUrl": "https://idp.example.com/auth/oauth",
                "TenantId": "ark_idp",
                "ClientId": "ark_server",
                "Domain": "localhost",
                "ExpireMins": 480,
                "RequireHttpsMetadata": False,
            }
        }
    )

    assert config.auth_server_url == "https://idp.example.com/auth/oauth"
    assert config.tenant_id == "ark_idp"
    assert config.client_id == "ark_server"
    assert config.expire_mins == 480
    assert config.require_https_metadata is False
    assert config.resolve_authority() == "https://idp.example.com/auth/oauth/ark_idp"


def test_the_python_spelling_binds_too():
    config = ArkAuthConfig.from_mapping(
        {"authority": "https://idp.example.com/my_idp", "client_id": "my-app"}
    )
    assert config.resolve_authority() == "https://idp.example.com/my_idp"


def test_defaults_match_the_dotnet_client():
    config = ArkAuthConfig()
    assert config.resolve_callback_path() == "/signin-oidc"
    assert config.resolve_signed_out_callback_path() == "/signout-callback-oidc"
    assert config.resolve_cookie_name() == "ark_auth"
    assert config.resolve_role_claim_type() == "role"
    assert config.expire_mins == 480
    assert config.resolve_scopes() == ["openid", "profile", "email", "offline_access"]
    assert config.use_legacy_flow is False


def test_account_switch_options_bind():
    config = ArkAuthConfig.from_mapping(
        {
            "authority": "https://idp.example.com/my_idp",
            "client_id": "my-app",
            "AccountSwitch": {
                "RequireArkClaims": True,
                "AppDisplayName": "Billing",
                "SupportEmail": "help@example.com",
            },
        }
    )

    assert isinstance(config.account_switch, ArkAccountSwitchOptions)
    assert config.account_switch.require_ark_claims is True
    assert config.account_switch.app_display_name == "Billing"
    assert config.account_switch.support_email == "help@example.com"
    # Everything not named keeps the default.
    assert config.account_switch.access_denied_path == "/ark/no-access"
    assert config.account_switch.prompt == "login"


def test_account_switch_defaults_are_off_by_default():
    """An upgrade must change no behaviour for a host that sets nothing."""
    switch = ArkAccountSwitchOptions()
    assert switch.require_ark_claims is False
    assert switch.end_provider_session_on_switch is False
    assert switch.enabled is True
    assert switch.auto_register_endpoints is True
    assert switch.serve_default_page is True


def test_tenant_certificates_bind_for_the_legacy_flow():
    config = ArkAuthConfig.from_mapping(
        {
            "clientId": "my-app",
            "tenants": {"abc123": {"kid": "abc123", "RsaPublic": "AAA", "Issuer": "iss"}},
        }
    )
    assert config.tenants["abc123"].rsa_public == "AAA"
    assert config.tenants["abc123"].issuer == "iss"
