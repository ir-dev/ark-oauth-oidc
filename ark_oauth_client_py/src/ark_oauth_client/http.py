"""
The HTTP layer: one place that knows how this server answers, so nothing above it has to.

Two rules are worth stating because the rest of the library depends on them. Every non-2xx
response is turned into an :class:`~ark_oauth_client.errors.ArkOAuthError` carrying the server's
own ``error`` code — the Ark server never answers a protocol failure with HTTP 200 and a message in
the body, so there is no "success that is really an error" case to unpick. And every request is
bounded by a timeout, because a token endpoint that accepts a connection and then stops talking
would otherwise hang a worker thread until the client gives up, which it never does.

Everything here is the standard library. Pass ``transport=`` to route the calls through
``requests``, ``httpx``, a proxy or a test double instead; see :class:`Transport` for the shape.
"""

from __future__ import annotations

import base64
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .errors import ArkNetworkError, ArkOAuthError

__all__ = ["Response", "request", "get_json", "post_form", "basic_auth_header", "Transport"]

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "ark-oauth-client-python"

#: A transport is ``(url, method, headers, body, timeout) -> (status, headers, body_bytes)``.
#: It must return the response rather than raise on a non-2xx status; this module decides what a
#: status means.
Transport = Callable[..., Tuple[int, Mapping[str, str], bytes]]


class Response:
    """One HTTP response: the status, the headers, and the body already parsed when it is JSON."""

    __slots__ = ("status", "headers", "body", "text")

    def __init__(self, status: int, headers: Mapping[str, str], body: Any, text: str) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.text = text


class _NoRedirectOnWrite(urllib.request.HTTPRedirectHandler):
    """
    A GET of metadata or keys may follow a redirect — an http-to-https hop is common, and the
    issuer check on the document is what actually establishes trust. A POST may not: it carries a
    client secret or an authorization code, and a redirect would forward them somewhere else.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if req.get_method() != "GET":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_NoRedirectOnWrite)


def _urllib_transport(
    url: str,
    method: str,
    headers: Mapping[str, str],
    body: Optional[bytes],
    timeout: float,
) -> Tuple[int, Mapping[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for name, value in headers.items():
        req.add_header(name, value)
    try:
        with _opener.open(req, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:  # a status, not a failure to reach the server
        return error.code, dict(error.headers.items() if error.headers else {}), error.read()


def _parse(body: bytes, content_type: str) -> Tuple[Any, str]:
    text = body.decode("utf-8", errors="replace")
    if not text:
        return None, ""
    stripped = text.lstrip()
    if "json" in content_type.lower() or stripped.startswith("{") or stripped.startswith("["):
        try:
            return json.loads(text), text
        except ValueError:
            return text, text
    return text, text


def request(
    url: str,
    *,
    method: str = "GET",
    form: Optional[Mapping[str, Any]] = None,
    json_body: Any = None,
    headers: Optional[Mapping[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    transport: Optional[Transport] = None,
) -> Response:
    """
    Performs one request and returns the parsed body.

    ``form`` entries that are ``None`` or empty are dropped, so a caller can build a body with
    optional parameters without filtering it first.
    """
    send: Transport = transport or _urllib_transport

    sent: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        # A token response must never be cached, and neither must a userinfo response keyed on a
        # bearer token that will be a different user's tomorrow.
        "Cache-Control": "no-store",
    }
    sent.update(headers or {})

    body: Optional[bytes] = None
    if form is not None:
        pairs = [(k, str(v)) for k, v in form.items() if v is not None and v != ""]
        body = urllib.parse.urlencode(pairs).encode("utf-8")
        sent["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        sent["Content-Type"] = "application/json"

    try:
        status, response_headers, raw = send(url, method, sent, body, timeout)
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as cause:
        reason = getattr(cause, "reason", cause)
        timed_out = isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason)
        raise ArkNetworkError(
            f"{method} {url} timed out after {timeout}s."
            if timed_out
            else f"{method} {url} failed: {reason}"
        ) from cause

    content_type = ""
    for name, value in (response_headers or {}).items():
        if name.lower() == "content-type":
            content_type = value
            break

    parsed, text = _parse(raw, content_type)
    if not 200 <= status < 300:
        raise ArkOAuthError.from_response(status, parsed, url)
    return Response(status, response_headers or {}, parsed, text)


def get_json(url: str, **options: Any) -> Dict[str, Any]:
    """GET returning a JSON object."""
    response = request(url, method="GET", **options)
    if not isinstance(response.body, dict):
        raise ArkOAuthError(
            "server_error",
            f"{url} did not return a JSON object.",
            endpoint=url,
            body=response.body,
        )
    return response.body


def post_form(url: str, form: Mapping[str, Any], **options: Any) -> Dict[str, Any]:
    """POST a form-urlencoded body, returning the JSON response."""
    response = request(url, method="POST", form=form, **options)
    # Revocation answers 200 with an empty body (RFC 7009 §2.2) — that is a success, not a shape error.
    if response.body is None:
        return {}
    if not isinstance(response.body, dict):
        raise ArkOAuthError(
            "server_error",
            f"{url} returned HTTP {response.status} with a non-JSON body.",
            status=response.status,
            endpoint=url,
            body=response.body,
        )
    return response.body


def basic_auth_header(client_id: str, client_secret: Optional[str]) -> str:
    """
    The ``Authorization: Basic`` value for ``client_secret_basic``.

    RFC 6749 §2.3.1 requires both halves to be form-urlencoded *before* they are joined and
    base64'd, which matters the moment a generated client secret contains a ``+`` or a ``:``. The
    Ark server URL-decodes both halves on the way in, so a client that skips the encoding
    authenticates fine until the day it is issued a secret with a reserved character in it.
    """
    quote = lambda value: urllib.parse.quote_plus(value, safe="")  # noqa: E731
    raw = f"{quote(client_id)}:{quote(client_secret or '')}"
    return "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
