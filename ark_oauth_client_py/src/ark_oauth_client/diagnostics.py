"""
Display helpers for tokens and JSON, and the reader for Ark's own authorization claims.

None of this is a security boundary. :func:`ArkJwt.decode_payload` deliberately does not validate a
token: validation belongs to the code that received it, and re-checking a signature here would
suggest an application is supposed to inspect its own access token — which it is not. The access
token is for the API that receives it, and an application that reasons about its contents is
coupling itself to a format the provider is free to change.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

from .crypto import base64url_decode

__all__ = ["ArkJwt", "ArkJson", "ArkClaimReader"]


class ArkJson:
    """Indents JSON for display, returning the input unchanged if it is not JSON."""

    @staticmethod
    def prettify(value: Optional[str]) -> str:
        if not value or not value.strip():
            return ""
        try:
            return json.dumps(json.loads(value), indent=2)
        except ValueError:
            return value


class ArkJwt:
    """Renders a JWT payload for a page or a log line."""

    @staticmethod
    def decode_payload(token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        parts = token.split(".")
        if len(parts) < 2:
            return "(not a JWT — the provider issued an opaque token)"
        try:
            return ArkJson.prettify(base64url_decode(parts[1]).decode("utf-8"))
        except Exception:
            return "(could not decode)"


class ArkClaimReader:
    """Reads Ark's ``ark_claims`` array out of an access token without validating it again."""

    @staticmethod
    def read_ark_claims(access_token: Optional[str]) -> List[str]:
        if not access_token:
            return []
        try:
            parts = access_token.split(".")
            if len(parts) < 2:
                return []
            payload: Any = json.loads(base64url_decode(parts[1]))
            claims = payload.get("ark_claims")
            if isinstance(claims, (list, tuple)):
                return [str(c) for c in claims]
            return [str(claims)] if claims else []
        except Exception:
            return []
