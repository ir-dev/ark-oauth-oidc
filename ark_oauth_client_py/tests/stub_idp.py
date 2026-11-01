"""
A stand-in for the Ark identity server, close enough on the wire to test a client against.

It mirrors what ``Ark.oAuth.Oidc`` actually does rather than what the specs merely permit: the same
paths under ``/{tenant}/oauth2/…``, RS256 with a ``kid`` and two published keys across a rotation,
``at+jwt`` access tokens carrying ``ark_claims``, ID tokens with ``at_hash``/``c_hash``, ``iss`` on
the authorization response (RFC 9207), refresh-token rotation where replaying a retired token
revokes the family, and RFC 6749 §5.2 error bodies with the right status codes.

The tests are only worth as much as this file's fidelity, so where it differs from the server it
does so by being stricter, never by being more forgiving.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa

from ark_oauth_client.crypto import base64url_encode, left_half_hash, sha256
from ark_oauth_client.jwt import sign_jwt


def _jwk_for(private_key: rsa.RSAPrivateKey, kid: str) -> Dict[str, Any]:
    numbers = private_key.public_key().public_numbers()

    def encode(value: int) -> str:
        return base64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {
        "kty": "RSA",
        "n": encode(numbers.n),
        "e": encode(numbers.e),
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
    }


class StubIdp:
    """Start with ``with StubIdp() as idp:`` and point a client at ``idp.issuer``."""

    def __init__(self, tenant: str = "test_idp", clients: Optional[Dict[str, Any]] = None) -> None:
        self.tenant = tenant
        self.keys: List[Dict[str, Any]] = []
        self.add_key("key-1")
        self.codes: Dict[str, Any] = {}
        self.refresh_tokens: Dict[str, Any] = {}
        self.families: Dict[str, Any] = {}
        self.device_codes: Dict[str, Any] = {}
        self.par_requests: Dict[str, Any] = {}
        self.requests: List[Dict[str, Any]] = []
        self.revoked: List[str] = []
        self.user = {
            "sub": "alice@example.com",
            "name": "Alice Example",
            "email": "alice@example.com",
            "email_verified": True,
        }
        self.ark_claims: List[str] = ["billing.admin", "reports.read"]
        #: Shortened by tests that need to drive the silent-refresh path.
        self.access_token_lifetime = 3600
        self.clients: Dict[str, Any] = clients or {
            "web-app": {
                "secret": None,
                "method": "none",
                "grants": ["authorization_code", "refresh_token"],
            },
            "confidential-app": {
                "secret": "top-secret",
                "method": "client_secret_basic",
                "grants": [
                    "authorization_code",
                    "refresh_token",
                    "client_credentials",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ],
            },
            "post-app": {
                "secret": "post-secret",
                "method": "client_secret_post",
                "grants": ["client_credentials"],
            },
        }
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- keys ----------------------------------------------------------

    def add_key(self, kid: str) -> str:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys.insert(0, {"kid": kid, "private_key": private_key, "jwk": _jwk_for(private_key, kid)})
        return kid

    def rotate_key(self, kid: Optional[str] = None) -> str:
        """Two-phase rotation: the new key signs, the old one stays published until its tokens expire."""
        kid = kid or f"key-{len(self.keys) + 1}"
        self.add_key(kid)
        self.keys = self.keys[:2]
        return kid

    @property
    def active_key(self) -> Dict[str, Any]:
        return self.keys[0]

    # -- lifecycle -----------------------------------------------------

    def __enter__(self) -> "StubIdp":
        return self.listen()

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def listen(self) -> "StubIdp":
        idp = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:  # keep the test output readable
                pass

            def do_GET(self) -> None:
                idp._handle(self, "GET")

            def do_POST(self) -> None:
                idp._handle(self, "POST")

            def do_DELETE(self) -> None:
                idp._handle(self, "DELETE")

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.issuer = f"{self.base_url}/{self.tenant}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # -- routing -------------------------------------------------------

    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        url = urlparse(handler.path)
        path = url.path
        query = {k: v[0] for k, v in parse_qs(url.query).items()}

        body: Dict[str, Any] = {}
        raw = b""
        length = int(handler.headers.get("Content-Length") or 0)
        if length:
            raw = handler.rfile.read(length)
            if "json" in (handler.headers.get("Content-Type") or ""):
                body = json.loads(raw or b"{}")
            else:
                body = {k: v[0] for k, v in parse_qs(raw.decode("utf-8")).items()}

        self.requests.append({"method": method, "path": path, "query": query, "form": body})
        prefix = f"/{self.tenant}"

        try:
            if path == f"{prefix}/.well-known/openid-configuration":
                return self._json(handler, 200, self._metadata())
            if path == f"{prefix}/oauth2/keys":
                return self._json(handler, 200, {"keys": [k["jwk"] for k in self.keys]})
            if path == f"{prefix}/oauth2/authorize":
                return self._authorize(handler, query)
            if path == f"{prefix}/oauth2/token":
                return self._token(handler, body)
            if path == f"{prefix}/oauth2/userinfo":
                return self._userinfo(handler)
            if path == f"{prefix}/oauth2/par":
                return self._par(handler, body)
            if path == f"{prefix}/oauth2/device":
                return self._device(handler, body)
            if path == f"{prefix}/oauth2/revoke":
                token = body.get("token")
                if token:
                    self.revoked.append(token)
                    self.refresh_tokens.pop(token, None)
                return self._empty(handler, 200)
            if path == f"{prefix}/oauth2/introspect":
                token = body.get("token")
                return self._json(
                    handler, 200, {"active": bool(token) and token not in self.revoked}
                )
            if path.startswith(f"{prefix}/oauth2/register"):
                return self._register(handler, method, path, body)
        except _OAuthFailure as failure:
            return self._json(
                handler,
                failure.status,
                {"error": failure.error, "error_description": failure.description},
            )

        return self._json(handler, 404, {"error": "not_found", "error_description": path})

    def _metadata(self) -> Dict[str, Any]:
        base = f"{self.base_url}/{self.tenant}"
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth2/authorize",
            "token_endpoint": f"{base}/oauth2/token",
            "userinfo_endpoint": f"{base}/oauth2/userinfo",
            "jwks_uri": f"{base}/oauth2/keys",
            "end_session_endpoint": f"{base}/oauth2/logout",
            "revocation_endpoint": f"{base}/oauth2/revoke",
            "introspection_endpoint": f"{base}/oauth2/introspect",
            "device_authorization_endpoint": f"{base}/oauth2/device",
            "pushed_authorization_request_endpoint": f"{base}/oauth2/par",
            "registration_endpoint": f"{base}/oauth2/register",
            "scopes_supported": ["openid", "profile", "email", "offline_access", "reports.read"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "form_post"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none",
            ],
            "id_token_signing_alg_values_supported": ["RS256"],
            "claims_supported": ["sub", "name", "email", "ark_claims"],
            "authorization_response_iss_parameter_supported": True,
        }

    # -- endpoints -----------------------------------------------------

    def _authorize(self, handler: BaseHTTPRequestHandler, query: Dict[str, str]) -> None:
        if query.get("request_uri"):
            pushed = self.par_requests.pop(query["request_uri"], None)
            if pushed is None:
                raise _OAuthFailure("invalid_request_uri", "unknown request_uri", 400)
            query = pushed

        client_id = query.get("client_id")
        if client_id not in self.clients:
            raise _OAuthFailure("invalid_client", "unknown client", 400)
        if query.get("code_challenge_method") != "S256":
            raise _OAuthFailure("invalid_request", "PKCE with S256 is required", 400)

        code = uuid.uuid4().hex
        self.codes[code] = {
            "client_id": client_id,
            "redirect_uri": query.get("redirect_uri"),
            "code_challenge": query.get("code_challenge"),
            "nonce": query.get("nonce"),
            "scope": query.get("scope", ""),
            "auth_time": int(time.time()),
        }
        location = (
            f"{query.get('redirect_uri')}?code={code}"
            f"&state={query.get('state', '')}&iss={self.issuer}"
        )
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def _token(self, handler: BaseHTTPRequestHandler, form: Dict[str, Any]) -> None:
        client_id, _ = self._authenticate_client(handler, form)
        grant = form.get("grant_type")

        if grant == "authorization_code":
            record = self.codes.pop(form.get("code", ""), None)
            if record is None:
                raise _OAuthFailure("invalid_grant", "the code is unknown or already redeemed", 400)
            verifier = form.get("code_verifier", "")
            if base64url_encode(sha256(verifier)) != record["code_challenge"]:
                raise _OAuthFailure("invalid_grant", "the PKCE verifier does not match", 400)
            if record["redirect_uri"] != form.get("redirect_uri"):
                raise _OAuthFailure("invalid_grant", "the redirect_uri does not match", 400)
            return self._json(
                handler,
                200,
                self._issue(client_id, record["scope"], nonce=record["nonce"], code=form.get("code")),
            )

        if grant == "refresh_token":
            presented = form.get("refresh_token", "")
            record = self.refresh_tokens.get(presented)
            if record is None:
                # Replaying a retired token revokes the whole family — the point of rotation.
                family = self.families.get(presented)
                if family:
                    for token in list(self.refresh_tokens):
                        if self.refresh_tokens[token]["family"] == family:
                            del self.refresh_tokens[token]
                raise _OAuthFailure("invalid_grant", "the refresh token is unknown or retired", 400)
            del self.refresh_tokens[presented]
            self.families[presented] = record["family"]
            return self._json(
                handler,
                200,
                self._issue(client_id, record["scope"], family=record["family"]),
            )

        if grant == "client_credentials":
            return self._json(
                handler, 200, self._issue(client_id, form.get("scope", ""), with_id_token=False)
            )

        if grant == "urn:ietf:params:oauth:grant-type:device_code":
            record = self.device_codes.get(form.get("device_code", ""))
            if record is None:
                raise _OAuthFailure("invalid_grant", "unknown device_code", 400)
            if not record["approved"]:
                raise _OAuthFailure("authorization_pending", "the user has not approved yet", 400)
            return self._json(handler, 200, self._issue(client_id, record["scope"]))

        raise _OAuthFailure("unsupported_grant_type", str(grant), 400)

    def _userinfo(self, handler: BaseHTTPRequestHandler) -> None:
        header = handler.headers.get("Authorization") or ""
        if not header.lower().startswith("bearer "):
            raise _OAuthFailure("invalid_token", "an access token is required", 401)
        self._json(handler, 200, dict(self.user))

    def _par(self, handler: BaseHTTPRequestHandler, form: Dict[str, Any]) -> None:
        self._authenticate_client(handler, form)
        request_uri = f"urn:ietf:params:oauth:request_uri:{uuid.uuid4().hex}"
        self.par_requests[request_uri] = dict(form)
        self._json(handler, 201, {"request_uri": request_uri, "expires_in": 90})

    def _device(self, handler: BaseHTTPRequestHandler, form: Dict[str, Any]) -> None:
        self._authenticate_client(handler, form)
        device_code = uuid.uuid4().hex
        self.device_codes[device_code] = {
            "approved": False,
            "scope": form.get("scope", ""),
        }
        self._json(
            handler,
            200,
            {
                "device_code": device_code,
                "user_code": "WDJB-MJHT",
                "verification_uri": f"{self.issuer}/device",
                "verification_uri_complete": f"{self.issuer}/device?user_code=WDJB-MJHT",
                "expires_in": 600,
                "interval": 1,
            },
        )

    def approve_device(self, device_code: str) -> None:
        self.device_codes[device_code]["approved"] = True

    def _register(
        self, handler: BaseHTTPRequestHandler, method: str, path: str, body: Dict[str, Any]
    ) -> None:
        header = handler.headers.get("Authorization") or ""
        if not header.lower().startswith("bearer "):
            raise _OAuthFailure("invalid_token", "an initial access token is required", 401)
        if method == "DELETE":
            return self._empty(handler, 204)
        if method == "GET":
            client_id = path.rsplit("/", 1)[-1]
            return self._json(handler, 200, {"client_id": client_id, "client_name": "read back"})
        client_id = f"generated-{uuid.uuid4().hex[:8]}"
        self.clients[client_id] = {"secret": "generated-secret", "method": "client_secret_basic", "grants": []}
        self._json(
            handler,
            201,
            {
                "client_id": client_id,
                "client_secret": "generated-secret",
                "client_name": body.get("client_name", ""),
                "registration_access_token": uuid.uuid4().hex,
                "registration_client_uri": f"{self.issuer}/oauth2/register/{client_id}",
            },
        )

    # -- issuing -------------------------------------------------------

    def _issue(
        self,
        client_id: str,
        scope: str,
        *,
        nonce: Optional[str] = None,
        code: Optional[str] = None,
        with_id_token: bool = True,
        family: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = int(time.time())
        key = self.active_key
        scopes = [s for s in scope.split(" ") if s]

        lifetime = self.access_token_lifetime
        access_token = sign_jwt(
            {
                "iss": self.issuer,
                "sub": self.user["sub"],
                "aud": client_id,
                "client_id": client_id,
                "scope": scope,
                "ark_claims": list(self.ark_claims),
                "iat": now,
                "nbf": now,
                "exp": now + lifetime,
                "jti": uuid.uuid4().hex,
            },
            key=key["private_key"],
            kid=key["kid"],
            typ="at+jwt",
        )

        response: Dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": lifetime,
            "scope": scope,
        }

        if with_id_token and "openid" in scopes:
            payload = {
                "iss": self.issuer,
                "sub": self.user["sub"],
                "aud": client_id,
                "iat": now,
                "nbf": now,
                "exp": now + 3600,
                "auth_time": now,
                "at_hash": left_half_hash(access_token),
                **{k: v for k, v in self.user.items() if k != "sub"},
            }
            if nonce:
                payload["nonce"] = nonce
            if code:
                payload["c_hash"] = left_half_hash(code)
            response["id_token"] = sign_jwt(payload, key=key["private_key"], kid=key["kid"])

        if "offline_access" in scopes:
            refresh = uuid.uuid4().hex
            self.refresh_tokens[refresh] = {
                "client_id": client_id,
                "scope": scope,
                "family": family or uuid.uuid4().hex,
            }
            response["refresh_token"] = refresh

        return response

    # -- client authentication -----------------------------------------

    def _authenticate_client(self, handler: BaseHTTPRequestHandler, form: Dict[str, Any]):
        """Mirrors the server's authenticator: one method only, and the registered method must match."""
        header = handler.headers.get("Authorization") or ""
        has_basic = header.startswith("Basic ")
        has_post = bool(form.get("client_secret"))
        has_assertion = bool(form.get("client_assertion"))
        if sum([has_basic, has_post, has_assertion]) > 1:
            raise _OAuthFailure(
                "invalid_request", "more than one client authentication method was used", 400
            )

        secret = None
        if has_basic:
            from urllib.parse import unquote_plus

            decoded = base64.b64decode(header[6:]).decode("utf-8")
            raw_id, _, raw_secret = decoded.partition(":")
            client_id = unquote_plus(raw_id)
            secret = unquote_plus(raw_secret)
            method = "client_secret_basic"
        elif has_post:
            client_id = form.get("client_id")
            secret = form.get("client_secret")
            method = "client_secret_post"
        elif has_assertion:
            client_id = form.get("client_id")
            method = "private_key_jwt"
        else:
            client_id = form.get("client_id")
            method = "none"

        record = self.clients.get(client_id)
        if record is None:
            raise _OAuthFailure("invalid_client", "unknown client", 401)
        if record["method"] != method:
            raise _OAuthFailure(
                "invalid_client",
                f"this client is registered for {record['method']}, not {method}",
                401,
            )
        if method in ("client_secret_basic", "client_secret_post") and secret != record["secret"]:
            raise _OAuthFailure("invalid_client", "the client secret is wrong", 401)

        return client_id, record

    # -- responses -----------------------------------------------------

    @staticmethod
    def _json(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
        payload = json.dumps(body).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    @staticmethod
    def _empty(handler: BaseHTTPRequestHandler, status: int) -> None:
        handler.send_response(status)
        handler.send_header("Content-Length", "0")
        handler.end_headers()


class _OAuthFailure(Exception):
    def __init__(self, error: str, description: str, status: int) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status
