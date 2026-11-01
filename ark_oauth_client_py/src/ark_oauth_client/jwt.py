"""
JWT decoding, signature verification and claim validation.

The Ark server signs with RS256 and publishes its keys at ``jwks_uri``, so that is the path this is
tuned for; the other JWS families are accepted so the same client can be pointed at Entra ID, Okta
or Auth0 without a second implementation.

The one algorithm deliberately not supported is ``none``. An unsigned token is a token anyone can
write, and every historical JWT library vulnerability of note comes from honouring the ``alg``
header without first deciding which algorithms are acceptable.

Signature work is delegated to :mod:`cryptography`. Verifying RS256 by hand is a page of modular
arithmetic that a library has no business shipping, and the ECDSA and PSS families are worse.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Mapping, NamedTuple, Optional, Sequence

from .crypto import base64url_decode, base64url_encode, left_half_hash
from .errors import ArkTokenError

__all__ = [
    "DecodedJwt",
    "SUPPORTED_ALGORITHMS",
    "decode_jwt",
    "verify_signature",
    "validate_claims",
    "validate_token_hashes",
    "verify_jwt",
    "sign_jwt",
]


class _Alg(NamedTuple):
    hash_name: str
    kty: str
    pss: bool = False


SUPPORTED_ALGORITHMS: Dict[str, _Alg] = {
    "RS256": _Alg("sha256", "RSA"),
    "RS384": _Alg("sha384", "RSA"),
    "RS512": _Alg("sha512", "RSA"),
    "PS256": _Alg("sha256", "RSA", True),
    "PS384": _Alg("sha384", "RSA", True),
    "PS512": _Alg("sha512", "RSA", True),
    "ES256": _Alg("sha256", "EC"),
    "ES384": _Alg("sha384", "EC"),
    "ES512": _Alg("sha512", "EC"),
}


class DecodedJwt(NamedTuple):
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    signing_input: bytes


def _cryptography():
    try:
        import cryptography  # noqa: F401
    except ImportError as cause:  # pragma: no cover - import guard
        raise ArkTokenError(
            "the 'cryptography' package is required to verify token signatures. "
            "Install it with: pip install ark-oauth-client"
        ) from cause
    return cryptography


def decode_jwt(token: str) -> DecodedJwt:
    """
    Splits a compact JWS without verifying anything.

    Useful for reading ``kid`` before a key is chosen, or for logging a token's ``sub`` while
    diagnosing a failure — never for deciding anything. Nothing in this library authorises on the
    result of a decode.
    """
    if not isinstance(token, str):
        raise ArkTokenError("the token is not a string.")
    parts = token.split(".")
    if len(parts) != 3:
        raise ArkTokenError(
            f"the token is not a compact JWS: expected 3 segments, found {len(parts)}."
        )

    try:
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
    except (ValueError, TypeError) as cause:
        raise ArkTokenError("the token header or payload is not valid JSON.") from cause
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ArkTokenError("the token header or payload is not a JSON object.")

    try:
        # Decoded here rather than at the point of verification so that a malformed token fails as
        # an ArkTokenError like every other bad token, instead of as a base64 error out of a
        # library the caller never called.
        signature = base64url_decode(parts[2])
    except (ValueError, TypeError) as cause:
        raise ArkTokenError("the token signature is not valid base64url.") from cause

    return DecodedJwt(
        header=header,
        payload=payload,
        signature=signature,
        signing_input=f"{parts[0]}.{parts[1]}".encode("ascii"),
    )


def _hash_algorithm(name: str):
    from cryptography.hazmat.primitives import hashes

    return {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[name]


def _public_key_from_jwk(jwk: Mapping[str, Any]):
    """Imports a JWK as a cryptography public key object."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    def num(name: str) -> int:
        return int.from_bytes(base64url_decode(jwk[name]), "big")

    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(e=num("e"), n=num("n")).public_key()
    if kty == "EC":
        curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
        curve = curves.get(str(jwk.get("crv")))
        if curve is None:
            raise ArkTokenError(f"the published key uses curve '{jwk.get('crv')}', which is not supported.")
        return ec.EllipticCurvePublicNumbers(x=num("x"), y=num("y"), curve=curve).public_key()
    raise ArkTokenError(f"the published key is of type '{kty}', which is not supported.")


def verify_signature(
    decoded: DecodedJwt,
    jwk: Mapping[str, Any],
    *,
    algorithms: Optional[Sequence[str]] = None,
) -> bool:
    """Verifies the signature of an already-decoded token against one JWK."""
    _cryptography()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    alg = decoded.header.get("alg")
    if not alg or alg == "none":
        raise ArkTokenError(
            f"the token declares alg '{alg or 'missing'}'; unsigned tokens are never accepted."
        )

    allowed = list(algorithms) if algorithms else list(SUPPORTED_ALGORITHMS)
    if alg not in allowed:
        raise ArkTokenError(
            f"the token is signed with {alg}, which this client does not accept "
            f"(allowed: {', '.join(allowed)})."
        )

    spec = SUPPORTED_ALGORITHMS.get(alg)
    if spec is None:
        raise ArkTokenError(f"unsupported signing algorithm '{alg}'.")
    if jwk.get("kty") != spec.kty:
        raise ArkTokenError(
            f"the signing key is a {jwk.get('kty')} key but the token declares {alg}."
        )
    if jwk.get("alg") and jwk.get("alg") != alg:
        raise ArkTokenError(
            f"the key published for kid '{jwk.get('kid')}' is registered for {jwk.get('alg')}, not {alg}."
        )

    try:
        key = _public_key_from_jwk(jwk)
    except ArkTokenError:
        raise
    except Exception as cause:
        raise ArkTokenError(
            f"the published key for kid '{jwk.get('kid')}' could not be imported: {cause}"
        ) from cause

    digest = _hash_algorithm(spec.hash_name)
    try:
        if spec.kty == "EC":
            # JWS carries an EC signature as raw r||s, not the DER sequence cryptography verifies.
            half = len(decoded.signature) // 2
            der = utils.encode_dss_signature(
                int.from_bytes(decoded.signature[:half], "big"),
                int.from_bytes(decoded.signature[half:], "big"),
            )
            key.verify(der, decoded.signing_input, ec.ECDSA(digest))
        elif spec.pss:
            key.verify(
                decoded.signature,
                decoded.signing_input,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                digest,
            )
        else:
            key.verify(decoded.signature, decoded.signing_input, padding.PKCS1v15(), digest)
    except InvalidSignature as cause:
        raise ArkTokenError("the token signature does not verify against the published key.") from cause

    return True


def validate_claims(
    payload: Mapping[str, Any],
    *,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    subject: Optional[str] = None,
    nonce: Optional[str] = None,
    max_age_seconds: Optional[int] = None,
    clock_tolerance_seconds: int = 60,
    require_exp: bool = True,
    require_iat: bool = False,
    now: Optional[int] = None,
    **_ignored: Any,
) -> Mapping[str, Any]:
    """
    Validates the registered claims.

    Order matters less than completeness here: skipping any single one of these is how a token
    meant for a different application, a different provider or a different moment ends up
    authorising a request.
    """
    now = int(time.time()) if now is None else now

    def fail(message: str, claim: str) -> None:
        raise ArkTokenError(message, claim=claim)

    def moment(value: Any) -> str:
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(value)))
        except (TypeError, ValueError):
            return str(value)

    if issuer:
        if not payload.get("iss"):
            fail("the token has no `iss` claim.", "iss")
        if payload.get("iss") != issuer:
            fail(f"the token was issued by '{payload.get('iss')}', not by '{issuer}'.", "iss")

    if audience:
        raw_aud = payload.get("aud")
        auds = list(raw_aud) if isinstance(raw_aud, (list, tuple)) else ([raw_aud] if raw_aud else [])
        if not auds:
            fail("the token has no `aud` claim.", "aud")
        if audience not in auds:
            listed = ", ".join(f"'{a}'" for a in auds)
            fail(f"the token is addressed to {listed}, not to '{audience}'.", "aud")
        # OIDC Core §3.1.3.7: with several audiences, `azp` must name the party the token is for.
        if len(auds) > 1 and payload.get("azp") and payload.get("azp") != audience:
            fail(
                f"the token names '{payload.get('azp')}' as its authorized party, not '{audience}'.",
                "azp",
            )

    if subject and payload.get("sub") != subject:
        fail(f"the token belongs to subject '{payload.get('sub')}', not '{subject}'.", "sub")

    exp = payload.get("exp")
    if exp is None:
        if require_exp:
            fail("the token has no `exp` claim.", "exp")
    elif not isinstance(exp, (int, float)) or now >= exp + clock_tolerance_seconds:
        fail(f"the token expired at {moment(exp)}.", "exp")

    nbf = payload.get("nbf")
    if nbf is not None and now + clock_tolerance_seconds < nbf:
        fail(f"the token is not valid before {moment(nbf)}.", "nbf")

    iat = payload.get("iat")
    if iat is None:
        if require_iat:
            fail("the token has no `iat` claim.", "iat")
    elif now + clock_tolerance_seconds < iat:
        fail(f"the token was issued in the future, at {moment(iat)}.", "iat")

    if nonce is not None:
        # A missing nonce is as bad as a wrong one: it means the ID token was not bound to our
        # authorization request and could have been minted for someone else's session.
        if not payload.get("nonce"):
            fail("the ID token has no `nonce`, so it cannot be tied to this sign-in.", "nonce")
        if payload.get("nonce") != nonce:
            fail(
                "the ID token `nonce` does not match the one sent with the authorization request.",
                "nonce",
            )

    if max_age_seconds is not None:
        auth_time = payload.get("auth_time")
        if not isinstance(auth_time, (int, float)):
            fail("`max_age` was requested but the ID token carries no `auth_time`.", "auth_time")
        elif now - auth_time > max_age_seconds + clock_tolerance_seconds:
            fail(
                f"the user authenticated {int(now - auth_time)}s ago, beyond the requested "
                f"max_age of {max_age_seconds}s.",
                "auth_time",
            )

    return payload


def validate_token_hashes(
    payload: Mapping[str, Any],
    *,
    access_token: Optional[str] = None,
    code: Optional[str] = None,
    require: bool = True,
) -> Mapping[str, Any]:
    """
    Checks ``at_hash`` / ``c_hash`` (OIDC Core §3.1.3.6).

    These are what stop an attacker swapping in an access token or an authorization code of their
    own alongside a genuine ID token — the substitution attack the hashes exist for. The Ark server
    always issues both, so a missing one is worth surfacing rather than skipping quietly.
    """

    def check(claim: str, value: Optional[str]) -> None:
        if not value:
            return
        present = payload.get(claim)
        if not present:
            if require:
                thing = "access token" if claim == "at_hash" else "authorization code"
                raise ArkTokenError(
                    f"the ID token has no `{claim}`, so the {thing} it arrived with cannot be "
                    "tied to it.",
                    claim=claim,
                )
            return
        if present != left_half_hash(value):
            raise ArkTokenError(
                f"the ID token `{claim}` does not cover the value it arrived with — it may have "
                "been substituted.",
                claim=claim,
            )

    check("at_hash", access_token)
    check("c_hash", code)
    return payload


def verify_jwt(token: str, jwks: Any, **options: Any) -> Dict[str, Any]:
    """
    The whole check for one token: signature against the provider's published keys, then claims.

    ``jwks`` is anything with ``get_signing_key(kid, alg)`` — normally a
    :class:`~ark_oauth_client.jwks.JwksCache`.
    """
    decoded = decode_jwt(token)

    typ_expected = options.get("typ")
    if typ_expected:
        # RFC 9068 §4: an access token declares `at+jwt`, which is how a resource server refuses an
        # ID token presented in its place. Both spellings are seen in the wild.
        typ = str(decoded.header.get("typ") or "").lower()
        expected = str(typ_expected).lower()
        if typ != expected and typ != f"application/{expected}":
            raise ArkTokenError(
                f"expected a token of type '{typ_expected}' but the header declares "
                f"'{decoded.header.get('typ') or 'none'}'."
            )

    jwk = jwks.get_signing_key(decoded.header.get("kid"), decoded.header.get("alg"))
    verify_signature(decoded, jwk, algorithms=options.get("algorithms"))
    validate_claims(decoded.payload, **options)
    if options.get("access_token") or options.get("code"):
        validate_token_hashes(
            decoded.payload,
            access_token=options.get("access_token"),
            code=options.get("code"),
            require=options.get("require_token_hashes", True),
        )
    return decoded.payload


def sign_jwt(
    payload: Mapping[str, Any],
    *,
    key: Any,
    alg: str = "RS256",
    kid: Optional[str] = None,
    typ: str = "JWT",
    header: Optional[Mapping[str, Any]] = None,
) -> str:
    """
    Signs a compact JWS.

    Needed for exactly one thing on the client side: the ``private_key_jwt`` client assertion (OIDC
    Core §9), where the client proves who it is with a signature instead of a shared secret that has
    to be stored, rotated and kept out of logs on both ends.

    ``key`` may be a PEM string or bytes, a JWK dict, or a :mod:`cryptography` private key object.
    """
    _cryptography()
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    spec = SUPPORTED_ALGORITHMS.get(alg)
    if spec is None:
        raise ArkTokenError(
            f"cannot sign with '{alg}'; supported: {', '.join(SUPPORTED_ALGORITHMS)}."
        )

    try:
        private_key = _load_private_key(key)
    except ArkTokenError:
        raise
    except Exception as cause:
        raise ArkTokenError(f"the signing key could not be imported: {cause}") from cause

    head: Dict[str, Any] = {"alg": alg, "typ": typ}
    if kid:
        head["kid"] = kid
    head.update(header or {})

    segments = (
        base64url_encode(json.dumps(head, separators=(",", ":")))
        + "."
        + base64url_encode(json.dumps(dict(payload), separators=(",", ":")))
    )
    signing_input = segments.encode("ascii")
    digest = _hash_algorithm(spec.hash_name)

    if spec.kty == "EC":
        from cryptography.hazmat.primitives.asymmetric import utils

        der = private_key.sign(signing_input, ec.ECDSA(digest))
        r, s = utils.decode_dss_signature(der)
        size = (private_key.curve.key_size + 7) // 8
        signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif spec.pss:
        signature = private_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
            digest,
        )
    else:
        signature = private_key.sign(signing_input, padding.PKCS1v15(), digest)

    return f"{segments}.{base64url_encode(signature)}"


def _load_private_key(key: Any):
    """Accepts a PEM string/bytes, a JWK mapping, or an already-loaded cryptography key."""
    from cryptography.hazmat.primitives import serialization

    if hasattr(key, "sign") and hasattr(key, "public_key"):
        return key
    if isinstance(key, Mapping):
        return _private_key_from_jwk(key)
    if isinstance(key, str):
        key = key.encode("utf-8")
    return serialization.load_pem_private_key(key, password=None)


def _private_key_from_jwk(jwk: Mapping[str, Any]):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    def num(name: str) -> int:
        return int.from_bytes(base64url_decode(jwk[name]), "big")

    kty = jwk.get("kty")
    if kty == "RSA":
        public = rsa.RSAPublicNumbers(e=num("e"), n=num("n"))
        p, q, d = num("p"), num("q"), num("d")
        return rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            # The CRT parameters are optional in a JWK (RFC 7518 §6.3.2); derive them when absent.
            dmp1=num("dp") if "dp" in jwk else rsa.rsa_crt_dmp1(d, p),
            dmq1=num("dq") if "dq" in jwk else rsa.rsa_crt_dmq1(d, q),
            iqmp=num("qi") if "qi" in jwk else rsa.rsa_crt_iqmp(p, q),
            public_numbers=public,
        ).private_key()
    if kty == "EC":
        curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
        curve = curves.get(str(jwk.get("crv")))
        if curve is None:
            raise ArkTokenError(f"the signing key uses curve '{jwk.get('crv')}', which is not supported.")
        return ec.derive_private_key(num("d"), curve)
    raise ArkTokenError(f"the signing key is of type '{kty}', which is not supported.")
