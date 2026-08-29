"""
The guards the three account endpoints need, kept away from any one web framework.

The endpoints themselves are registered by :mod:`ark_oauth_client.flask`; what lives here is the
part that has to be right no matter who serves them — the open-redirect guard on a return URL, and
the same-origin check on the two POSTs.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

__all__ = ["local_or_default", "check_same_origin", "read_field"]


def local_or_default(url: Optional[str], fallback: Optional[str]) -> str:
    """
    Keeps a return URL inside this application. Echoing an arbitrary one would turn the
    access-denied page into an open redirect, which is a phishing primitive.
    """
    home = fallback if fallback and fallback.strip() else "/"
    if not url or not url.strip():
        return home
    candidate = url.strip()
    if not candidate.startswith("/"):
        return home
    if candidate.startswith("//"):  # protocol-relative
        return home
    if candidate.startswith("/\\"):  # backslash variant
        return home
    if any(ord(c) < 32 or ord(c) == 127 for c in candidate):
        return home
    return candidate


def check_same_origin(
    method: str,
    headers: Mapping[str, str],
    origin_of_this_request: str,
) -> Tuple[bool, int, str]:
    """
    POST, from this origin.

    Neither endpoint is a security boundary — the worst a forged request achieves is an unwanted
    sign-out — but a cross-site page should not be able to end a user's session, and requiring a
    POST from the same origin costs nothing. Returns ``(ok, status, message)``.
    """
    if method.upper() != "POST":
        return False, 405, "POST required."

    def header(name: str) -> str:
        for key, value in headers.items():
            if key.lower() == name:
                return value or ""
        return ""

    fetch_site = header("sec-fetch-site")
    if fetch_site:
        if fetch_site not in ("same-origin", "none"):
            return False, 400, "cross-site request rejected."
        return True, 200, ""

    origin = header("origin")
    if not origin:
        return True, 200, ""  # not a browser form post
    if origin.rstrip("/").lower() == origin_of_this_request.rstrip("/").lower():
        return True, 200, ""
    return False, 400, "cross-site request rejected."


def read_field(form: Optional[Mapping[str, Any]], query: Optional[Mapping[str, Any]], name: str):
    """
    Form first, then the query string.

    A null-coalescing chain would stop at an empty form value and never look at the query, which is
    how the return URL goes missing on the one request that needs it.
    """
    value = (form or {}).get(name)
    if value:
        return str(value)
    value = (query or {}).get(name)
    return str(value) if value else None
