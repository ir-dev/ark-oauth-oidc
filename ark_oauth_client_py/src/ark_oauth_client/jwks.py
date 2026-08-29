"""
The provider's signing keys, cached and refreshed on rotation.

Ark rotates in two phases: the new key becomes ``active`` and starts signing, the previous one
moves to ``rollover`` and stays published until the last token it signed has expired. Both are in
the JWKS at once, so a client that caches the document keeps validating tokens across the change —
provided it refreshes when it meets a ``kid`` it has never seen. That refresh is the whole point of
this class, and it is what the old Ark client could not do at all: its public key was a base64
string pasted into appsettings.json, so a rotation broke every deployment by hand.

The refresh is rate-limited. Without a cooldown, a stream of tokens bearing a bogus ``kid`` would
turn into a stream of requests to the provider's JWKS endpoint — a denial-of-service amplifier
pointed at your own identity server.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set

from .errors import ArkTokenError
from .http import get_json

__all__ = ["JwksCache"]

_KTY_FOR_ALG = {"RS": "RSA", "PS": "RSA", "ES": "EC"}

#: Stands in for an absent ``kid`` in the negative cache, so "no kid" is remembered as its own
#: distinct miss rather than colliding with a key actually named that.
_NO_KID = "<none>"


class JwksCache:
    """Caches one ``jwks_uri``. Safe to share across threads."""

    def __init__(
        self,
        jwks_uri: str,
        *,
        ttl: float = 300.0,
        min_refresh_interval: float = 10.0,
        **http: Any,
    ) -> None:
        self._uri = jwks_uri
        self._ttl = ttl
        self._cooldown = min_refresh_interval
        self._http = http
        self._keys: Optional[List[Dict[str, Any]]] = None
        self._fetched_at = 0.0
        self._missing: Set[str] = set()
        # Collapses concurrent misses into one request: a burst of traffic arriving just after a
        # rotation should cost the provider one JWKS fetch, not one per request.
        self._lock = threading.Lock()

    @property
    def uri(self) -> str:
        return self._uri

    def keys(self, *, force: bool = False) -> List[Dict[str, Any]]:
        """Every published key, fetching or refreshing as needed."""
        stale = time.monotonic() - self._fetched_at > self._ttl
        if self._keys is not None and not force and not stale:
            return self._keys
        return self._load(force=force)

    def get_signing_key(self, kid: Optional[str], alg: Optional[str]) -> Dict[str, Any]:
        """
        The key that signed a token, chosen by ``kid`` and constrained to the algorithm's key type.

        A token with no ``kid`` is resolved only when the provider publishes exactly one usable key
        — guessing among several would mean trying each until one verifies, which turns an
        unauthenticated caller into an oracle for which keys are live.
        """
        candidates = self._select(self.keys(), kid, alg)

        if not candidates:
            # An unknown kid is the normal signal that the provider has rotated, so the first sight
            # of one earns a refetch. The second sight of the *same* unknown kid does not: it is
            # either a token from another provider or a probe, and re-reading JWKS for each one
            # would point a request amplifier at the identity server. The rate limit covers the
            # remaining case, a flood of tokens each carrying a different invented kid.
            marker = kid or _NO_KID
            if marker not in self._missing and time.monotonic() - self._fetched_at >= self._cooldown:
                candidates = self._select(self.keys(force=True), kid, alg)
            if not candidates:
                self._missing.add(marker)

        if not candidates:
            raise ArkTokenError(
                f"no key with kid '{kid}' is published at {self._uri}; the token may have been "
                "signed by a different provider."
                if kid
                else f"the token carries no 'kid' and {self._uri} publishes more than one key, so "
                "the signing key is ambiguous."
            )
        return candidates[0]

    def clear(self) -> None:
        """Drops the cache — for tests, and for a deployment that knows a rotation just happened."""
        with self._lock:
            self._keys = None
            self._fetched_at = 0.0
            self._missing.clear()

    # ------------------------------------------------------------------

    @staticmethod
    def _select(
        keys: Sequence[Dict[str, Any]], kid: Optional[str], alg: Optional[str]
    ) -> List[Dict[str, Any]]:
        wanted_kty = _KTY_FOR_ALG.get(str(alg or "")[:2])
        usable = [
            k
            for k in keys
            if (not k.get("use") or k.get("use") == "sig")
            and (not wanted_kty or k.get("kty") == wanted_kty)
            and (not k.get("alg") or not alg or k.get("alg") == alg)
        ]
        if kid:
            return [k for k in usable if k.get("kid") == kid]
        return usable if len(usable) == 1 else []

    def _load(self, *, force: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            # Another thread may have loaded while this one waited for the lock.
            if (
                self._keys is not None
                and not force
                and time.monotonic() - self._fetched_at <= self._ttl
            ):
                return self._keys

            document = get_json(self._uri, **self._http)
            keys = document.get("keys")
            if not isinstance(keys, list) or not keys:
                raise ArkTokenError(f"{self._uri} published no keys.")
            self._keys = keys
            self._fetched_at = time.monotonic()
            # A fresh document may well contain the kid that was missing a moment ago.
            self._missing.clear()
            return keys
