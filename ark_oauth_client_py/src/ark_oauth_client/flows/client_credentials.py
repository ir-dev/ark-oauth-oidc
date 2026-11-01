"""
The client credentials grant (RFC 6749 §4.4) — a service authenticating as itself.

There is no user in this flow and no browser: the client sends its own credentials to the token
endpoint and gets back an access token that says nothing about a person. Use it for scheduled jobs,
service-to-service calls and daemons; never to act on behalf of a signed-in user, because the
resulting token carries the service's authority rather than theirs, and nothing downstream can tell
the difference.

The token endpoint is read from the provider's discovery document, so this class needs the issuer
and nothing else.

One thing to know before reaching for it: like the .NET class it mirrors, this authenticates with
``client_secret_post`` — the secret in the form rather than in an ``Authorization: Basic`` header.
Both are standard and this one is easier to read in a trace, but the server matches the *registered*
method exactly, so the client used here must be registered for ``client_secret_post``. For a client
registered any other way, use :meth:`ArkOAuthClient.client_credentials
<ark_oauth_client.client.ArkOAuthClient.client_credentials>`, which applies whichever method the
client is configured for.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..diagnostics import ArkJson, ArkJwt
from ..http import post_form
from ..probe import ArkSetupProbe

__all__ = ["ArkClientCredentials", "ArkTokenResult"]

REDACTED = "•" * 8


@dataclass
class ArkTokenResult:
    """The outcome of a token request, success or failure, with enough to diagnose it."""

    token_endpoint: str = ""
    status_code: int = 0

    access_token: Optional[str] = None
    token_type: Optional[str] = None
    scope: Optional[str] = None
    expires_in: int = 0
    expires_at: float = 0.0

    error: Optional[str] = None
    error_description: Optional[str] = None

    #: The posted form, with the secret redacted.
    request_form: List[Tuple[str, str]] = field(default_factory=list)
    raw_response: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return bool(self.access_token) and not self.error

    @property
    def access_token_payload(self) -> Optional[str]:
        """The token's payload, decoded for display only."""
        return ArkJwt.decode_payload(self.access_token)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_endpoint": self.token_endpoint,
            "status_code": self.status_code,
            "access_token": self.access_token,
            "token_type": self.token_type,
            "scope": self.scope,
            "expires_in": self.expires_in,
            "expires_at": self.expires_at,
            "error": self.error,
            "error_description": self.error_description,
            "request_form": [list(pair) for pair in self.request_form],
            "raw_response": self.raw_response,
            "succeeded": self.succeeded,
        }


class ArkClientCredentials:
    """Performs the grant, with a cache so a service does not re-request a token per call."""

    # Cached per authority + client_id + scope: a service that asks for a token on every outbound
    # call turns one request into two and rate-limits itself against its own IdP.
    _cache: Dict[str, ArkTokenResult] = {}
    _cache_lock = threading.Lock()
    RENEW_BEFORE_SECONDS = 60

    def __init__(self, config: Any, probe: Optional[ArkSetupProbe] = None, **http: Any) -> None:
        self._config = config
        self._probe = probe or ArkSetupProbe(config, **http)
        self._http = http or {"timeout": 15.0}

    def get_token(
        self,
        client_id: str,
        client_secret: str,
        scopes: Optional[Sequence[str]] = None,
        authority: Optional[str] = None,
    ) -> ArkTokenResult:
        """
        Returns a cached token when one is still valid, and requests a new one otherwise.

        This is what production code should call. A client credentials token is not tied to a
        session and typically lasts an hour, so re-requesting it per call is pure overhead.
        """
        scope_value = " ".join(scopes or ())
        key = f"{authority or self._config.resolve_authority()}|{client_id}|{scope_value}"

        with self._cache_lock:
            cached = self._cache.get(key)
        if (
            cached
            and cached.succeeded
            and cached.expires_at - time.time() > self.RENEW_BEFORE_SECONDS
        ):
            return cached

        result = self.request_token(client_id, client_secret, scopes, authority)
        if result.succeeded:
            with self._cache_lock:
                self._cache[key] = result
        return result

    def request_token(
        self,
        client_id: str,
        client_secret: str,
        scopes: Optional[Sequence[str]] = None,
        authority: Optional[str] = None,
    ) -> ArkTokenResult:
        """
        Performs the grant, bypassing the cache, and reports the exchange in full — request form,
        HTTP status and response body — so a failure can be read rather than guessed at.
        """
        result = ArkTokenResult()

        if not client_id or not client_secret:
            result.error = "invalid_client"
            result.error_description = (
                "the client_credentials grant needs a client_id and a client_secret."
            )
            return result

        try:
            metadata = self._probe.read_metadata(authority)
            if not metadata.token_endpoint:
                result.error = "server_error"
                result.error_description = (
                    "the provider's discovery document has no token_endpoint."
                )
                return result

            result.token_endpoint = metadata.token_endpoint

            form: Dict[str, str] = {
                "grant_type": "client_credentials",
                # client_secret_post rather than an Authorization: Basic header. Both are standard;
                # this one is easier to read in a trace, and Ark accepts either.
                "client_id": client_id,
                "client_secret": client_secret,
            }
            scope_value = " ".join(scopes or ())
            if scope_value:
                form["scope"] = scope_value

            # What gets shown to an operator: never the secret itself.
            result.request_form = [
                (key, REDACTED if key == "client_secret" else value)
                for key, value in form.items()
            ]

            payload = post_form(metadata.token_endpoint, form, **self._http)
            result.status_code = 200
            result.raw_response = ArkJson.prettify(_dump(payload))

            result.access_token = _text(payload, "access_token")
            result.token_type = _text(payload, "token_type")
            result.scope = _text(payload, "scope")
            lifetime = payload.get("expires_in")
            lifetime = int(lifetime) if isinstance(lifetime, (int, float)) else 3600
            result.expires_in = lifetime
            result.expires_at = time.time() + lifetime
        except Exception as error:
            status = getattr(error, "status", 0)
            body = getattr(error, "body", None)
            result.status_code = status or 0
            if body is not None:
                result.raw_response = ArkJson.prettify(_dump(body))
            result.error = getattr(error, "error", None) or "request_failed"
            result.error_description = getattr(error, "error_description", None) or str(error)

        return result

    @classmethod
    def clear_cache(cls) -> None:
        """Clears the cache — for a screen that wants to show a live exchange."""
        with cls._cache_lock:
            cls._cache.clear()


def _text(payload: Any, name: str) -> Optional[str]:
    value = payload.get(name) if hasattr(payload, "get") else None
    return value if isinstance(value, str) else None


def _dump(value: Any) -> str:
    import json

    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)
