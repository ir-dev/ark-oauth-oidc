"""Agent-to-agent (A2A): tokens addressed to one agent, as itself and on behalf of a user."""

from __future__ import annotations

import pytest
from flask import Flask, jsonify

from ark_oauth_client import (
    ArkConfigError,
    ArkOAuthClient,
    ArkOAuthError,
    agent_actors,
    decode_jwt,
)
from ark_oauth_client.flask import add_ark_agent_api, current_ark

from .test_client import confidential_client, follow, public_client


def agent(idp, client_id="post-app", secret="post-secret"):
    """A second (and third) agent: any confidential client is one."""
    idp.clients.setdefault(
        client_id, {"secret": secret, "method": "client_secret_post", "grants": []}
    )
    return ArkOAuthClient(
        authority=idp.issuer,
        client_id=client_id,
        client_secret=secret,
        token_endpoint_auth_method="client_secret_post",
        require_https=False,
    )


def user_token(idp, client):
    """Signs alice in at ``client`` and returns her access token."""
    transaction = client.create_authorization_url()
    return client.handle_callback(follow(client, transaction), transaction).access_token


# -- the agent as itself ------------------------------------------------------


def test_an_agent_token_is_addressed_to_the_target_and_cached(idp):
    idp.agents = {"post-app": {"confidential-app": {"claims": ["orders.read"]}}}
    caller = confidential_client(idp)

    tokens = caller.agent_token("post-app")
    payload = decode_jwt(tokens.access_token).payload
    assert payload["aud"] == "post-app"
    assert payload["sub"] == "confidential-app"
    assert payload["ark_claims"] == ["orders.read"]
    assert agent_actors(payload) == []
    assert tokens.expires_in() <= 300, "agent tokens are short-lived"

    form = [r for r in idp.requests if r["path"].endswith("/oauth2/token")][-1]["form"]
    assert form["grant_type"] == "client_credentials" and form["audience"] == "post-app"

    assert caller.agent_token("post-app") is tokens, "a live token is served from the cache"
    assert caller.agent_token("post-app", force=True) is not tokens
    # The ordinary client credentials token is a different token, cached separately.
    assert decode_jwt(caller.client_credentials().access_token).payload["aud"] != "post-app"


def test_the_target_verifies_it_and_another_agent_refuses_it(idp):
    idp.agents = {"post-app": {"confidential-app": {"claims": ["orders.read"]}}}
    token = confidential_client(idp).agent_token("post-app").access_token

    payload = agent(idp).verify_agent_token(token, ark_claims=["orders.read"])
    assert payload["sub"] == "confidential-app"

    with pytest.raises(Exception, match="addressed to 'post-app', not to 'agent-c'"):
        agent(idp, "agent-c", "c-secret").verify_agent_token(token)
    with pytest.raises(ArkOAuthError) as missing:
        agent(idp).verify_agent_token(token, ark_claims=["orders.write"])
    assert missing.value.error == "insufficient_scope"


def test_an_unlisted_caller_is_refused(idp):
    with pytest.raises(ArkOAuthError) as refused:
        confidential_client(idp).agent_token("post-app")
    assert refused.value.error == "invalid_target"


def test_a_public_client_cannot_be_an_agent(idp):
    with pytest.raises(ArkConfigError, match="confidential client"):
        public_client(idp).agent_token("post-app")
    with pytest.raises(ArkConfigError, match="client_id of the agent"):
        confidential_client(idp).agent_token("")


# -- on behalf of a user ------------------------------------------------------


def test_a_user_is_handed_from_agent_to_agent(idp):
    idp.agents = {
        "post-app": {"confidential-app": {"delegate_users": True}},
        "agent-c": {"post-app": {"delegate_users": True}},
    }
    idp.user_claims_at = {"post-app": ["orders.read"], "agent-c": ["c.use"]}
    web = confidential_client(idp)
    b = agent(idp)
    c = agent(idp, "agent-c", "c-secret")

    first = web.agent_token("post-app", subject_token=user_token(idp, web))
    form = [r for r in idp.requests if r["path"].endswith("/oauth2/token")][-1]["form"]
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert form["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert first.raw["issued_token_type"] == "urn:ietf:params:oauth:token-type:access_token"

    at_b = b.verify_agent_token(first.access_token, ark_claims=["orders.read"])
    assert at_b["sub"] == "alice@example.com", "the subject is still the user"
    assert agent_actors(at_b) == ["confidential-app"]

    second = b.agent_token("agent-c", subject_token=first.access_token)
    at_c = c.verify_agent_token(second.access_token)
    assert at_c["sub"] == "alice@example.com"
    assert at_c["ark_claims"] == ["c.use"], "the user's own claims at the target"
    assert agent_actors(at_c) == ["post-app", "confidential-app"]
    assert at_c["exp"] <= at_b["exp"], "never outlives the token it was exchanged for"


def test_each_user_gets_their_own_cached_token(idp):
    idp.agents = {"post-app": {"confidential-app": {"delegate_users": True}}}
    idp.user_claims_at = {"post-app": []}
    web = confidential_client(idp)

    alice = user_token(idp, web)
    for_alice = web.agent_token("post-app", subject_token=alice)
    assert web.agent_token("post-app", subject_token=alice) is for_alice

    idp.user = {"sub": "bob@example.com", "name": "Bob"}
    for_bob = web.agent_token("post-app", subject_token=user_token(idp, web))
    assert decode_jwt(for_bob.access_token).payload["sub"] == "bob@example.com"
    assert decode_jwt(for_alice.access_token).payload["sub"] == "alice@example.com"


def test_delegation_needs_the_targets_permission_and_the_users_access(idp):
    web = confidential_client(idp)
    subject = user_token(idp, web)

    idp.agents = {"post-app": {"confidential-app": {"claims": ["x"]}}}  # itself only
    idp.user_claims_at = {"post-app": []}
    with pytest.raises(ArkOAuthError) as refused:
        web.agent_token("post-app", subject_token=subject)
    assert refused.value.error == "invalid_target"

    idp.agents = {"post-app": {"confidential-app": {"delegate_users": True}}}
    idp.user_claims_at = {}  # the user has no access to the target
    with pytest.raises(ArkOAuthError) as refused:
        web.agent_token("post-app", subject_token=subject)
    assert refused.value.error == "invalid_target"


def test_a_token_meant_for_someone_else_cannot_be_exchanged(idp):
    idp.agents = {"agent-c": {"post-app": {"delegate_users": True}}}
    idp.user_claims_at = {"agent-c": []}
    web = confidential_client(idp)
    with pytest.raises(ArkOAuthError) as refused:
        agent(idp).agent_token("agent-c", subject_token=user_token(idp, web))
    assert refused.value.error == "invalid_grant"


# -- the agent card and the Flask guard ---------------------------------------


def test_the_agent_card_security_section_comes_from_the_provider(idp):
    client = confidential_client(idp)
    card = client.agent_card_security()
    flow = card["securitySchemes"]["ark"]["oauth2SecurityScheme"]["flows"]["clientCredentials"]
    assert flow["tokenUrl"] == client.metadata()["token_endpoint"]
    assert card["securityRequirements"] == [{"schemes": {"ark": {"list": []}}}]

    older = client.agent_card_security(spec="0.3")
    assert older["securitySchemes"]["ark"]["type"] == "oauth2"
    assert older["security"] == [{"ark": []}]


def test_flask_agent_api_accepts_only_tokens_addressed_to_it(idp):
    idp.agents = {
        "post-app": {"confidential-app": {"claims": ["orders.read"], "delegate_users": True}},
        "agent-c": {"confidential-app": {"claims": ["orders.read"]}},
    }
    idp.user_claims_at = {"post-app": ["orders.read"]}

    api = Flask(__name__)
    api.config["TESTING"] = True
    guard = add_ark_agent_api(
        api,
        "/a2a",
        authority=idp.issuer,
        client_id="post-app",
        client_secret="post-secret",
        token_endpoint_auth_method="client_secret_post",
        require_https=False,
    )

    @api.post("/a2a/tasks")
    @guard.require(claims=["orders.read"])
    def tasks():
        return jsonify({"sub": current_ark.sub, "actors": current_ark.actors})

    web = confidential_client(idp)
    http = api.test_client()

    as_itself = web.agent_token("post-app").access_token
    answer = http.post("/a2a/tasks", headers={"Authorization": f"Bearer {as_itself}"})
    assert answer.status_code == 200
    assert answer.get_json() == {"sub": "confidential-app", "actors": []}

    for_alice = web.agent_token("post-app", subject_token=user_token(idp, web)).access_token
    answer = http.post("/a2a/tasks", headers={"Authorization": f"Bearer {for_alice}"})
    assert answer.get_json() == {"sub": "alice@example.com", "actors": ["confidential-app"]}

    elsewhere = web.agent_token("agent-c").access_token
    answer = http.post("/a2a/tasks", headers={"Authorization": f"Bearer {elsewhere}"})
    assert answer.status_code == 401
    assert "invalid_token" in answer.headers["WWW-Authenticate"]

    assert http.post("/a2a/tasks").status_code == 401
