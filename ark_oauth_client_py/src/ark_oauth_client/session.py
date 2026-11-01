"""
Where a signed-in user's tokens live between requests.

The tokens themselves never go to the browser. The cookie carries an opaque session id and a
signature over it, and everything else — access token, refresh token, ID token claims — stays in the
store on the server. That ordering is the point: a cookie the client can read is a cookie an XSS bug
can exfiltrate, and a refresh token in one is a session that outlives the fix.
"""

from __future__ import annotations

import hmac
import threading
import time
from hashlib import sha256 as _sha256
from typing import Any, Dict, Optional, Tuple

from .crypto import base64url_encode, fixed_time_equal, random_token

__all__ = [
    "SessionStore",
    "MemorySessionStore",
    "create_session_id",
    "sign_session_id",
    "unsign_session_id",
]


class SessionStore:
    """
    The four methods a session store owes this library.

    Supply your own — Redis, a database table, ``flask-session`` — for anything that runs more than
    once. The values handed to :meth:`set` are plain JSON-safe dicts.
    """

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def set(self, session_id: str, data: Dict[str, Any], ttl_seconds: int) -> None:  # pragma: no cover
        raise NotImplementedError

    def destroy(self, session_id: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def touch(self, session_id: str, ttl_seconds: int) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class MemorySessionStore(SessionStore):
    """
    The default store: a dict with expiry, good for one process.

    Fine for a single instance and for development. Behind a load balancer, or across a restart,
    every session lives in one process's heap and disappears with it — supply a shared store with
    the same four methods for anything that runs more than once.

    Expiry is swept lazily rather than on a timer: a background thread in a library is a thread the
    application did not ask for and cannot see.
    """

    def __init__(self, *, sweep_interval_seconds: float = 60.0) -> None:
        self._entries: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = threading.Lock()
        self._sweep_interval = sweep_interval_seconds
        self._last_sweep = time.monotonic()

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._maybe_sweep()
            entry = self._entries.get(session_id)
            if entry is None:
                return None
            if entry[1] <= time.monotonic():
                del self._entries[session_id]
                return None
            return entry[0]

    def set(self, session_id: str, data: Dict[str, Any], ttl_seconds: int) -> None:
        with self._lock:
            self._maybe_sweep()
            self._entries[session_id] = (data, time.monotonic() + ttl_seconds)

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._entries.pop(session_id, None)

    def touch(self, session_id: str, ttl_seconds: int) -> None:
        with self._lock:
            entry = self._entries.get(session_id)
            if entry is not None:
                self._entries[session_id] = (entry[0], time.monotonic() + ttl_seconds)

    def sweep(self) -> None:
        with self._lock:
            self._sweep()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ------------------------------------------------------------------

    def _maybe_sweep(self) -> None:
        now = time.monotonic()
        if now - self._last_sweep >= self._sweep_interval:
            self._sweep()

    def _sweep(self) -> None:
        now = time.monotonic()
        self._last_sweep = now
        for key in [k for k, (_, expires) in self._entries.items() if expires <= now]:
            del self._entries[key]


def create_session_id() -> str:
    """A fresh session id: 32 random bytes, never derived from anything about the user."""
    return random_token(32)


def sign_session_id(session_id: str, secret: Any) -> str:
    """
    Signs a session id for the cookie.

    The signature is not confidentiality — the id is opaque and means nothing on its own. It stops
    the store being probed with guessed ids, so an attacker cannot mine for a live session by
    sending a stream of cookies and watching which ones take longer to come back.
    """
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    mac = hmac.new(key, session_id.encode("utf-8"), _sha256).digest()
    return f"{session_id}.{base64url_encode(mac)}"


def unsign_session_id(value: Any, secret: Any) -> Optional[str]:
    """Verifies a cookie value and returns the session id, or ``None`` when the signature does not hold."""
    if not isinstance(value, str):
        return None
    dot = value.rfind(".")
    if dot <= 0:
        return None
    session_id = value[:dot]
    return session_id if fixed_time_equal(value, sign_session_id(session_id, secret)) else None
