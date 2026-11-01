"""Token decoding, signature verification and claim validation."""

from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ark_oauth_client import (
    ArkTokenError,
    base64url_encode,
    decode_jwt,
    left_half_hash,
    sign_jwt,
    validate_claims,
    validate_token_hashes,
    verify_jwt,
    verify_signature,
)


class _Jwks:
    """The two-method interface verify_jwt expects."""

    def __init__(self, jwk):
        self.jwk = jwk

    def get_signing_key(self, kid, alg):
        return self.jwk


@pytest.fixture(scope="module")
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()

    def encode(value: int) -> str:
        return base64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    jwk = {
        "kty": "RSA",
        "n": encode(numbers.n),
        "e": encode(numbers.e),
        "kid": "test-key",
        "use": "sig",
        "alg": "RS256",
    }
    return private_key, jwk


def test_decode_reads_header_and_payload(keypair):
    private_key, _ = keypair
    token = sign_jwt({"sub": "alice"}, key=private_key, kid="test-key")
    decoded = decode_jwt(token)

    assert decoded.header["alg"] == "RS256"
    assert decoded.header["kid"] == "test-key"
    assert decoded.payload["sub"] == "alice"


def test_a_token_that_is_not_a_jws_is_refused():
    with pytest.raises(ArkTokenError, match="3 segments"):
        decode_jwt("not.a-jwt")


def test_signature_verifies_and_a_tampered_payload_does_not(keypair):
    private_key, jwk = keypair
    token = sign_jwt({"sub": "alice"}, key=private_key, kid="test-key")
    assert verify_signature(decode_jwt(token), jwk) is True

    header, _, signature = token.split(".")
    swapped = base64url_encode(json.dumps({"sub": "mallory"}))
    forged = f"{header}.{swapped}.{signature}"
    with pytest.raises(ArkTokenError, match="does not verify"):
        verify_signature(decode_jwt(forged), jwk)


def test_alg_none_is_never_accepted(keypair):
    _, jwk = keypair
    unsigned = (
        base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}))
        + "."
        + base64url_encode(json.dumps({"sub": "mallory"}))
        + "."
    )
    with pytest.raises(ArkTokenError, match="unsigned tokens are never accepted"):
        verify_signature(decode_jwt(unsigned + "AA"), jwk)


def test_an_algorithm_outside_the_allow_list_is_refused(keypair):
    private_key, jwk = keypair
    token = sign_jwt({"sub": "alice"}, key=private_key, kid="test-key")
    with pytest.raises(ArkTokenError, match="does not accept"):
        verify_signature(decode_jwt(token), jwk, algorithms=["ES256"])


def test_claim_validation_covers_iss_aud_and_expiry():
    now = int(time.time())
    payload = {"iss": "https://idp/t", "aud": "app", "exp": now + 60, "iat": now, "sub": "alice"}

    assert validate_claims(payload, issuer="https://idp/t", audience="app", now=now)

    with pytest.raises(ArkTokenError, match="was issued by"):
        validate_claims(payload, issuer="https://other", now=now)
    with pytest.raises(ArkTokenError, match="addressed to"):
        validate_claims(payload, audience="another-app", now=now)
    with pytest.raises(ArkTokenError, match="expired"):
        validate_claims(payload, now=now + 3600)


def test_a_missing_nonce_fails_as_hard_as_a_wrong_one():
    now = int(time.time())
    base = {"exp": now + 60, "iat": now}

    with pytest.raises(ArkTokenError, match="has no `nonce`"):
        validate_claims(base, nonce="expected", now=now)
    with pytest.raises(ArkTokenError, match="does not match"):
        validate_claims({**base, "nonce": "other"}, nonce="expected", now=now)
    assert validate_claims({**base, "nonce": "expected"}, nonce="expected", now=now)


def test_azp_must_name_us_when_there_are_several_audiences():
    now = int(time.time())
    payload = {"aud": ["app", "other"], "azp": "other", "exp": now + 60}

    with pytest.raises(ArkTokenError, match="authorized party"):
        validate_claims(payload, audience="app", now=now)


def test_max_age_is_checked_against_auth_time():
    now = int(time.time())
    payload = {"exp": now + 60, "auth_time": now - 600}

    with pytest.raises(ArkTokenError, match="max_age"):
        validate_claims(payload, max_age_seconds=60, now=now)


def test_token_hashes_tie_the_id_token_to_what_arrived_with_it():
    access_token = "an-access-token"
    payload = {"at_hash": left_half_hash(access_token)}

    assert validate_token_hashes(payload, access_token=access_token)

    with pytest.raises(ArkTokenError, match="does not cover"):
        validate_token_hashes(payload, access_token="a-substituted-token")
    with pytest.raises(ArkTokenError, match="has no `at_hash`"):
        validate_token_hashes({}, access_token=access_token)
    # ...unless the caller says the provider does not send them.
    assert validate_token_hashes({}, access_token=access_token, require=False) == {}


def test_verify_jwt_enforces_the_typ_header(keypair):
    private_key, jwk = keypair
    now = int(time.time())
    token = sign_jwt(
        {"iss": "https://idp/t", "aud": "app", "exp": now + 60, "iat": now},
        key=private_key,
        kid="test-key",
    )

    with pytest.raises(ArkTokenError, match="at\\+jwt"):
        verify_jwt(token, _Jwks(jwk), typ="at+jwt")

    access = sign_jwt(
        {"iss": "https://idp/t", "aud": "app", "exp": now + 60, "iat": now},
        key=private_key,
        kid="test-key",
        typ="at+jwt",
    )
    assert verify_jwt(access, _Jwks(jwk), typ="at+jwt", issuer="https://idp/t", audience="app")


def test_signing_round_trips_through_a_jwk(keypair):
    private_key, jwk = keypair
    token = sign_jwt({"sub": "alice"}, key=private_key, kid="test-key")
    assert verify_signature(decode_jwt(token), jwk) is True


def test_signing_accepts_a_pem(keypair):
    from cryptography.hazmat.primitives import serialization

    private_key, jwk = keypair
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    token = sign_jwt({"sub": "alice"}, key=pem, kid="test-key")
    assert verify_signature(decode_jwt(token), jwk) is True
