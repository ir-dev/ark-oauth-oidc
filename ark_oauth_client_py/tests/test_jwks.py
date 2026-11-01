"""Key rotation, and the rate limit that keeps this client from amplifying requests at the IdP."""

from __future__ import annotations

import pytest

from ark_oauth_client import ArkTokenError, JwksCache


def jwks_url(idp):
    return f"{idp.issuer}/oauth2/keys"


def fetches(idp):
    return len([r for r in idp.requests if r["path"].endswith("/oauth2/keys")])


def test_keys_are_fetched_once_and_cached(idp):
    cache = JwksCache(jwks_url(idp))
    assert cache.keys()
    cache.keys()
    assert fetches(idp) == 1


def test_the_signing_key_is_chosen_by_kid(idp):
    cache = JwksCache(jwks_url(idp), min_refresh_interval=0)
    key = cache.get_signing_key(idp.active_key["kid"], "RS256")
    assert key["kid"] == idp.active_key["kid"]


def test_a_rotation_is_picked_up_on_the_first_token_signed_by_the_new_key(idp):
    cache = JwksCache(jwks_url(idp), min_refresh_interval=0)
    cache.keys()

    new_kid = idp.rotate_key("key-rotated")
    assert cache.get_signing_key(new_kid, "RS256")["kid"] == new_kid


def test_the_refetch_is_rate_limited_between_rotations(idp):
    cache = JwksCache(jwks_url(idp), min_refresh_interval=60)
    cache.keys()
    before = fetches(idp)

    with pytest.raises(ArkTokenError, match="no key with kid"):
        cache.get_signing_key("invented", "RS256")

    assert fetches(idp) == before, "a cooldown must suppress the refetch"


def test_a_kid_already_known_to_be_absent_never_refetches_again(idp):
    cache = JwksCache(jwks_url(idp), min_refresh_interval=0)
    cache.keys()

    with pytest.raises(ArkTokenError):
        cache.get_signing_key("bogus", "RS256")
    after_first = fetches(idp)

    with pytest.raises(ArkTokenError):
        cache.get_signing_key("bogus", "RS256")

    assert fetches(idp) == after_first, "the same bad kid must not cost a second fetch"


def test_a_token_with_no_kid_is_ambiguous_when_several_keys_are_published(idp):
    idp.rotate_key("key-second")
    cache = JwksCache(jwks_url(idp), min_refresh_interval=0)

    with pytest.raises(ArkTokenError, match="ambiguous"):
        cache.get_signing_key(None, "RS256")


def test_an_ec_algorithm_does_not_match_an_rsa_key(idp):
    cache = JwksCache(jwks_url(idp), min_refresh_interval=0)
    with pytest.raises(ArkTokenError):
        cache.get_signing_key(idp.active_key["kid"], "ES256")


def test_clear_forces_a_refetch(idp):
    cache = JwksCache(jwks_url(idp))
    cache.keys()
    before = fetches(idp)
    cache.clear()
    cache.keys()
    assert fetches(idp) == before + 1
