"""
The discovery document (OpenID Connect Discovery 1.0 / RFC 8414).

There is one URL to configure — the issuer — and every endpoint this client uses comes from here.
That is not indirection for its own sake: it is what lets the provider move an endpoint, turn PAR
on, or start advertising the device grant without every application redeploying, and it is why the
issuer is the only thing an Ark application has to be told.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from .errors import ArkConfigError, ArkOAuthError
from .http import get_json

__all__ = ["MetadataResolver", "discovery_urls", "ArkDiscoveryCache"]

DEFAULT_TTL = 300.0  # the server sends Cache-Control: max-age=300


def discovery_urls(authority: str) -> Tuple[str, str]:
    """Both spellings of the metadata URL: OIDC appends the well-known path, RFC 8414 inserts it."""
    base = authority.rstrip("/")
    parts = urlsplit(base)
    path = parts.path.rstrip("/")
    origin = f"{parts.scheme}://{parts.netloc}"
    return (
        f"{base}/.well-known/openid-configuration",
        f"{origin}/.well-known/oauth-authorization-server{path}",
    )


class MetadataResolver:
    """
    Fetches and caches provider metadata, one entry per authority.

    Instances are shared through the client, so an application that creates one
    :class:`~ark_oauth_client.client.ArkOAuthClient` makes one discovery request per five minutes no
    matter how many sign-ins it serves.
    """

    def __init__(self, *, ttl: float = DEFAULT_TTL, **http: Any) -> None:
        self._ttl = ttl
        self._http = http
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = threading.Lock()

    def get(self, authority: str, *, force: bool = False) -> Dict[str, Any]:
        if not authority:
            raise ArkConfigError(
                "no authority was given; set `authority` to the issuer URL of your Ark tenant."
            )
        key = authority.rstrip("/")

        hit = self._cache.get(key)
        if hit and not force and time.monotonic() - hit[1] <= self._ttl:
            return hit[0]

        with self._lock:
            hit = self._cache.get(key)
            if hit and not force and time.monotonic() - hit[1] <= self._ttl:
                return hit[0]
            # A failed lookup is not cached, or one restart during a provider outage would wedge
            # the application for the whole TTL.
            metadata = self._fetch(key)
            self._cache[key] = (metadata, time.monotonic())
            return metadata

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def _fetch(self, authority: str) -> Dict[str, Any]:
        primary, fallback = discovery_urls(authority)
        try:
            metadata = get_json(primary, **self._http)
        except ArkOAuthError as error:
            # Ark serves the OIDC spelling. The RFC 8414 form is tried second so the same client
            # can be pointed at a provider that only publishes that one.
            if error.status == 404:
                metadata = get_json(fallback, **self._http)
            else:
                raise

        if not metadata.get("issuer"):
            raise ArkOAuthError(
                "server_error",
                f"{primary} returned a document with no 'issuer'.",
                endpoint=primary,
            )

        # OIDC Discovery §4.3: the issuer in the document must equal the one used to look it up.
        # A mismatch means the URL is not the authority it claims to be — the shape of a mix-up
        # attack, and much more often a stray /auth or a missing tenant id in configuration.
        if str(metadata["issuer"]).rstrip("/") != authority:
            raise ArkConfigError(
                f"the provider at {primary} identifies itself as '{metadata['issuer']}', but this "
                f"client is configured for '{authority}'. Set `authority` to exactly the issuer "
                "value — for Ark that is the base URL and the tenant id joined."
            )

        return metadata


class ArkDiscoveryCache:
    """
    A process-wide discovery cache, mirroring the .NET client's static ``ArkDiscoveryCache``.

    The token refresher and the account endpoints both need the token endpoint without holding a
    client instance, and re-reading the document per refresh would turn every silent renewal into
    two requests. Unlike :class:`MetadataResolver` it serves a stale document rather than raising
    when the provider is briefly unreachable, because a refresh that fails signs a user out.
    """

    _lock = threading.Lock()
    _cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
    _ttl = 1800.0  # 30 minutes, as in the .NET client

    @classmethod
    def get(cls, authority: str, **http: Any) -> Optional[Dict[str, Any]]:
        if not authority:
            return None
        with cls._lock:
            hit = cls._cache.get(authority)
            if hit and time.monotonic() - hit[1] < cls._ttl:
                return hit[0]
            try:
                metadata = get_json(discovery_urls(authority)[0], **http)
            except Exception:
                return hit[0] if hit else None
            cls._cache[authority] = (metadata, time.monotonic())
            return metadata

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._cache.clear()
