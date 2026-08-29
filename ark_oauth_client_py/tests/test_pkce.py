"""PKCE, the random values, the session store and the open-redirect guard."""

from __future__ import annotations

import base64
import hashlib

from ark_oauth_client import (
    MemorySessionStore,
    base64url_decode,
    base64url_encode,
    code_challenge_for,
    create_code_verifier,
    create_nonce,
    create_pkce_pair,
    create_session_id,
    create_state,
    left_half_hash,
    local_or_default,
    sign_session_id,
    unsign_session_id,
)
from ark_oauth_client.crypto import fixed_time_equal


# -- PKCE ------------------------------------------------------------------


def test_a_verifier_meets_rfc_7636():
    verifier = create_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert all(c.isalnum() or c in "-._~" for c in verifier)


def test_verifiers_are_never_repeated():
    """The predecessor derived this from a timestamp, so PKCE protected nothing."""
    assert len({create_code_verifier() for _ in range(500)}) == 500


def test_the_challenge_is_the_sha256_of_the_verifier():
    verifier = create_code_verifier()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert code_challenge_for(verifier) == expected


def test_the_pair_declares_s256():
    pair = create_pkce_pair()
    assert pair.code_challenge_method == "S256"
    assert pair.code_challenge == code_challenge_for(pair.code_verifier)


def test_state_and_nonce_are_random():
    assert len({create_state() for _ in range(200)}) == 200
    assert len({create_nonce() for _ in range(200)}) == 200


# -- encoding --------------------------------------------------------------


def test_base64url_round_trips_and_carries_no_padding():
    encoded = base64url_encode(b"\x00\x01\xfe\xff")
    assert "=" not in encoded
    assert base64url_decode(encoded) == b"\x00\x01\xfe\xff"
    # Padding some encoders leave on is tolerated on the way back in.
    assert base64url_decode(encoded + "==") == b"\x00\x01\xfe\xff"


def test_left_half_hash_is_half_the_digest():
    assert len(base64url_decode(left_half_hash("value"))) == 16


def test_fixed_time_equal_compares_correctly():
    assert fixed_time_equal("abc", "abc") is True
    assert fixed_time_equal("abc", "abd") is False
    assert fixed_time_equal("abc", None) is False


# -- sessions --------------------------------------------------------------


def test_a_session_signature_can_be_verified_and_not_forged():
    session_id = create_session_id()
    signed = sign_session_id(session_id, "a-secret")

    assert unsign_session_id(signed, "a-secret") == session_id
    assert unsign_session_id(signed, "another-secret") is None
    assert unsign_session_id(f"{session_id}.tampered", "a-secret") is None
    assert unsign_session_id("no-dot", "a-secret") is None
    assert unsign_session_id(None, "a-secret") is None


def test_the_memory_store_expires_entries():
    store = MemorySessionStore()
    store.set("id", {"a": 1}, ttl_seconds=60)
    assert store.get("id") == {"a": 1}

    store.set("gone", {"b": 2}, ttl_seconds=-1)
    assert store.get("gone") is None

    store.destroy("id")
    assert store.get("id") is None


def test_the_memory_store_can_be_touched():
    store = MemorySessionStore()
    store.set("id", {"a": 1}, ttl_seconds=-1)
    store.touch("id", 60)
    assert store.get("id") == {"a": 1}


# -- the open-redirect guard -----------------------------------------------


def test_only_same_origin_paths_are_followed():
    assert local_or_default("/billing", "/") == "/billing"
    assert local_or_default("/a?b=c", "/") == "/a?b=c"

    # Everything that could leave this application falls back to home.
    assert local_or_default("https://evil.example.com/", "/") == "/"
    assert local_or_default("//evil.example.com/", "/") == "/"
    assert local_or_default("/\\evil.example.com/", "/") == "/"
    assert local_or_default("/a\nb", "/") == "/"
    assert local_or_default(None, "/home") == "/home"
    assert local_or_default("", "/home") == "/home"
    assert local_or_default("/x", None) == "/x"
