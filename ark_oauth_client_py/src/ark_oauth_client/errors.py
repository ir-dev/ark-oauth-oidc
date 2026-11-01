"""
The error types this library raises.

Every failure that came from the authorization server arrives as an :class:`ArkOAuthError`
carrying the ``error`` code the spec defines, because that code is the only part a caller can
branch on. A library that collapses ``invalid_grant`` and a DNS failure into one raised string
forces the application to parse English to decide whether to retry, re-authenticate, or give up.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

__all__ = [
    "ArkError",
    "ArkConfigError",
    "ArkOAuthError",
    "ArkTokenError",
    "ArkCallbackError",
    "ArkNetworkError",
]


class ArkError(Exception):
    """Base class, so ``except ArkError:`` covers everything raised from here."""


class ArkConfigError(ArkError):
    """
    The client is misconfigured — a missing authority, a redirect_uri that is not absolute, a
    ``private_key_jwt`` method with no key. Raised at construction time wherever possible, so the
    mistake surfaces at startup rather than on the first user's sign-in.
    """


class ArkOAuthError(ArkError):
    """
    An RFC 6749 §5.2 error response: a JSON body with ``error`` and, usually,
    ``error_description``.

    ``error`` is the machine-readable code (``invalid_grant``, ``invalid_client``, ``slow_down``,
    …); ``status`` is the HTTP status it arrived with; ``endpoint`` is the URL that produced it,
    which is what makes the difference between "the token endpoint rejected the code" and "the
    userinfo endpoint rejected the token" readable in a log.
    """

    def __init__(
        self,
        error: str,
        description: Optional[str] = None,
        *,
        status: int = 0,
        endpoint: Optional[str] = None,
        error_uri: Optional[str] = None,
        body: Any = None,
    ) -> None:
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error
        self.error_description = description
        self.error_uri = error_uri
        self.status = status
        self.endpoint = endpoint
        self.body = body

    @classmethod
    def from_response(cls, status: int, body: Any, endpoint: Optional[str]) -> "ArkOAuthError":
        """Builds the error from a parsed response body, falling back to the HTTP status."""
        if isinstance(body, Mapping) and isinstance(body.get("error"), str):
            return cls(
                body["error"],
                body.get("error_description"),
                status=status,
                endpoint=endpoint,
                error_uri=body.get("error_uri"),
                body=body,
            )
        return cls(
            "server_error",
            f"the endpoint returned HTTP {status}.",
            status=status,
            endpoint=endpoint,
            body=body,
        )


class ArkTokenError(ArkError):
    """
    A token was received but did not survive validation: a bad signature, the wrong issuer or
    audience, an expired ``exp``, a ``nonce`` that does not match the one sent, an ``at_hash`` that
    does not cover the access token that came with it.

    Kept separate from :class:`ArkOAuthError` on purpose. An OAuth error means the server refused;
    this means the server answered and the answer cannot be trusted, which is the more serious of
    the two and should never be retried.
    """

    def __init__(self, message: str, *, claim: Optional[str] = None, token: Optional[str] = None) -> None:
        super().__init__(message)
        self.claim = claim
        self.token = token


class ArkCallbackError(ArkError):
    """
    The authorization response could not be tied back to a request this client started — an unknown
    or missing ``state``, an expired login transaction, an ``iss`` that is not the provider we sent
    the user to (RFC 9207). Treat it as an attempted CSRF or mix-up attack rather than a user error.
    """


class ArkNetworkError(ArkError):
    """The remote call did not complete: connection refused, DNS failure, timeout, aborted."""
