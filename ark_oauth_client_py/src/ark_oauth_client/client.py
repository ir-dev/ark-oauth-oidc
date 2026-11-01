"""
The Ark OAuth 2.1 / OpenID Connect client.

One object per application, holding the configuration, the cached discovery document and the cached
JWKS. It is stateless with respect to users: a sign-in produces a *transaction* the caller stores
(the ``state``, ``nonce`` and PKCE verifier), and a token set the caller stores. That is what makes
it safe to share one instance across every request in a process, and what lets the session live
wherever the application already keeps sessions rather than in this library.

For a Flask application, :func:`ark_oauth_client.flask.ark_flask` drives all of this — the
transaction, the session, the silent refresh — and is the thing to reach for first. Use this class
directly for CLIs, workers, Django, FastAPI, or any flow without a browser.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import parse_qsl, urlencode

from .config import ArkConfig, normalize_config
from .crypto import fixed_time_equal, random_token
from .discovery import MetadataResolver
from .errors import ArkCallbackError, ArkConfigError, ArkOAuthError, ArkTokenError
from .jwks import JwksCache
from .jwt import sign_jwt, verify_jwt
from .pkce import create_nonce, create_pkce_pair, create_state
from .tokens import TokenSet
from .http import basic_auth_header, get_json, post_form, request as http_request

__all__ = ["ArkOAuthClient", "AuthorizationRequest", "create_ark_client"]


@dataclass
class AuthorizationRequest:
    """
    The URL to send the browser to, and the transaction that has to survive until it comes back.

    ``state``, ``nonce`` and ``code_verifier`` are the entire security of the flow. Store them
    somewhere the user cannot read or edit — a server-side session, an encrypted cookie — and pass
    the same object to :meth:`ArkOAuthClient.handle_callback`. Putting them in a plain cookie or a
    hidden form field hands the attacker exactly the three values the checks are made of.
    """

    url: str
    state: str
    code_verifier: str
    redirect_uri: str
    nonce: Optional[str] = None
    scope: str = ""
    max_age: Optional[int] = None
    created_at: int = field(default_factory=lambda: int(time.time()))
    return_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "state": self.state,
            "code_verifier": self.code_verifier,
            "redirect_uri": self.redirect_uri,
            "nonce": self.nonce,
            "scope": self.scope,
            "max_age": self.max_age,
            "created_at": self.created_at,
            "return_to": self.return_to,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuthorizationRequest":
        return cls(
            url=data.get("url", ""),
            state=data.get("state", ""),
            code_verifier=data.get("code_verifier", ""),
            redirect_uri=data.get("redirect_uri", ""),
            nonce=data.get("nonce"),
            scope=data.get("scope", ""),
            max_age=data.get("max_age"),
            created_at=int(data.get("created_at") or time.time()),
            return_to=data.get("return_to"),
        )


class ArkOAuthClient:
    """The protocol client. Thread-safe; create one per application and share it."""

    def __init__(self, metadata_resolver: Optional[MetadataResolver] = None, **options: Any) -> None:
        self._config = normalize_config(**options)
        self._http = {"timeout": self._config.timeout, "transport": self._config.transport}
        self._metadata = metadata_resolver or MetadataResolver(
            ttl=self._config.metadata_ttl, **self._http
        )
        self._jwks: Dict[str, JwksCache] = {}
        self._service_tokens: Dict[str, TokenSet] = {}
        self._lock = threading.Lock()

    @property
    def config(self) -> ArkConfig:
        return self._config

    @property
    def authority(self) -> str:
        return self._config.authority

    def metadata(self, *, force: bool = False) -> Dict[str, Any]:
        """The provider's discovery document, cached. Every endpoint below is read from it."""
        return self._metadata.get(self._config.authority, force=force)

    def jwks(self) -> JwksCache:
        """The provider's published signing keys, cached and refreshed across key rotation."""
        uri = self.metadata().get("jwks_uri")
        if not uri:
            raise ArkOAuthError(
                "server_error",
                "the provider's metadata has no 'jwks_uri'.",
                endpoint=self._config.authority,
            )
        with self._lock:
            cache = self._jwks.get(uri)
            if cache is None:
                cache = JwksCache(
                    uri,
                    ttl=self._config.jwks_ttl,
                    min_refresh_interval=self._config.jwks_min_refresh_interval,
                    **self._http,
                )
                self._jwks[uri] = cache
            return cache

    # =================================================================
    # Interactive sign-in: authorization code + PKCE
    # =================================================================

    def create_authorization_url(
        self,
        *,
        redirect_uri: Optional[str] = None,
        scopes: Optional[Sequence[str]] = None,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
        max_age: Optional[int] = None,
        acr_values: Optional[str] = None,
        response_mode: Optional[str] = None,
        use_par: Optional[bool] = None,
        return_to: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> AuthorizationRequest:
        """Starts a sign-in: builds the URL to send the browser to, and returns the transaction."""
        config = self._config
        metadata = self.metadata()

        target = redirect_uri or config.redirect_uri
        if not target:
            raise ArkConfigError(
                "ark_oauth_client: no 'redirect_uri' is configured, and none was passed to "
                "create_authorization_url()."
            )

        chosen_scopes = list(scopes) if scopes else list(config.scopes)
        pkce = create_pkce_pair()
        state = state or create_state()
        scope_value = " ".join(chosen_scopes)
        wants_id_token = "openid" in chosen_scopes
        nonce = nonce or (create_nonce() if wants_id_token else None)

        params: Dict[str, Any] = {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": target,
            "scope": scope_value,
            "state": state,
            "code_challenge": pkce.code_challenge,
            "code_challenge_method": pkce.code_challenge_method,
            "response_mode": response_mode or config.response_mode,
        }
        if nonce:
            params["nonce"] = nonce
        if prompt or config.prompt:
            params["prompt"] = prompt or config.prompt
        if login_hint:
            params["login_hint"] = login_hint
        if max_age is not None:
            params["max_age"] = str(max_age)
        if acr_values or config.acr_values:
            params["acr_values"] = acr_values or config.acr_values
        params.update(config.extra_authorization_params)
        params.update(extra or {})

        authorization_endpoint = metadata.get("authorization_endpoint")
        if not authorization_endpoint:
            raise ArkOAuthError(
                "server_error",
                "the provider's metadata has no 'authorization_endpoint'.",
                endpoint=config.authority,
            )

        # Pushed authorization requests (RFC 9126): the parameters travel over the authenticated
        # back channel and the browser only carries a one-time reference to them, so nothing in the
        # URL can be logged, tampered with or replayed. Used when asked for, and when the tenant
        # requires it.
        wants_par = (
            use_par
            if use_par is not None
            else (config.use_par or metadata.get("require_pushed_authorization_requests") is True)
        )
        if wants_par:
            pushed = self.push_authorization_request(params)
            query = urlencode(
                {"client_id": config.client_id, "request_uri": pushed["request_uri"]}
            )
        else:
            query = urlencode(
                [(k, v) for k, v in params.items() if v is not None and v != ""]
            )

        return AuthorizationRequest(
            url=f"{authorization_endpoint}?{query}",
            state=state,
            nonce=nonce,
            code_verifier=pkce.code_verifier,
            redirect_uri=target,
            scope=scope_value,
            max_age=max_age,
            return_to=return_to,
        )

    @staticmethod
    def read_callback_params(source: Any) -> Dict[str, str]:
        """
        Reads the authorization response out of whatever the web framework handed you: a full URL,
        a query string, or the parsed query/body of a ``form_post`` callback.
        """
        if not source:
            return {}
        if isinstance(source, str):
            query = source[source.index("?") + 1 :] if "?" in source else source.lstrip("?#")
            return dict(parse_qsl(query, keep_blank_values=True))
        if hasattr(source, "items"):
            return {str(k): str(v) for k, v in source.items()}
        return {}

    def handle_callback(
        self,
        response_params: Any,
        transaction: Union[AuthorizationRequest, Mapping[str, Any]],
        *,
        redirect_uri: Optional[str] = None,
    ) -> TokenSet:
        """
        Completes a sign-in: checks the response against the transaction, redeems the code, and
        validates the ID token.

        Everything that makes the authorization code flow safe happens in this method, in this
        order: an error response is surfaced as an error rather than as a missing code; ``state`` is
        compared in constant time, so a response that belongs to no request of ours is refused
        before anything is redeemed; ``iss`` is checked (RFC 9207) so a response cannot be replayed
        from one provider to another; the code is exchanged with the PKCE verifier that only this
        process holds; and the ID token is verified against the provider's keys, its ``nonce``, and
        its ``at_hash``/``c_hash``.
        """
        params = ArkOAuthClient.read_callback_params(response_params)
        metadata = self.metadata()

        tx = (
            transaction
            if isinstance(transaction, AuthorizationRequest)
            else AuthorizationRequest.from_dict(transaction or {})
        )
        if not tx.state or not tx.code_verifier:
            raise ArkCallbackError(
                "no login transaction was supplied. The state, nonce and PKCE verifier from "
                "create_authorization_url() must be stored when the sign-in starts and passed "
                "back here."
            )

        # The user denied consent, the client is disabled, the tenant rejected the request: all
        # arrive here as a redirect carrying `error`, and all of them mean there is no code to
        # redeem.
        if params.get("error"):
            raise ArkOAuthError(
                params["error"],
                params.get("error_description"),
                endpoint=metadata.get("authorization_endpoint"),
                error_uri=params.get("error_uri"),
                body=params,
            )

        if not params.get("state"):
            raise ArkCallbackError("the authorization response carried no `state`.")
        if not fixed_time_equal(str(params["state"]), str(tx.state)):
            raise ArkCallbackError(
                "the authorization response `state` does not match the request. Treat this as a "
                "CSRF attempt."
            )

        # RFC 9207. Ark always sends `iss`; when the provider advertises it, a response without one
        # is as suspect as a wrong one, because stripping the parameter is how a mix-up attack hides.
        if params.get("iss") or metadata.get("authorization_response_iss_parameter_supported"):
            if not params.get("iss"):
                raise ArkCallbackError(
                    "the provider advertises `iss` in authorization responses but this one has none."
                )
            if params["iss"] != metadata.get("issuer"):
                raise ArkCallbackError(
                    f"the authorization response came from '{params['iss']}', not from "
                    f"'{metadata.get('issuer')}'."
                )

        if not params.get("code"):
            raise ArkCallbackError("the authorization response carried no `code`.")

        return self.exchange_code(
            code=params["code"],
            code_verifier=tx.code_verifier,
            redirect_uri=redirect_uri or tx.redirect_uri or self._config.redirect_uri,
            nonce=tx.nonce,
            max_age=tx.max_age,
        )

    def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: Optional[str],
        nonce: Optional[str] = None,
        max_age: Optional[int] = None,
    ) -> TokenSet:
        """The bare ``authorization_code`` exchange, for callers doing their own callback handling."""
        metadata = self.metadata()
        response = self._token_request(
            metadata["token_endpoint"],
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )
        return self._to_token_set(response, nonce=nonce, code=code, max_age=max_age)

    def refresh(self, refresh_token: str, *, scopes: Optional[Sequence[str]] = None) -> TokenSet:
        """
        Exchanges a refresh token for a new access token.

        Rotation is on by default on this server: the response carries a *new* refresh token and the
        one just presented is retired. Store what comes back. Presenting a retired token is treated
        as theft and revokes the entire family, which is the point of rotation, and also the reason
        a client that keeps re-sending its original token locks itself out on the second refresh.
        """
        if not refresh_token:
            raise ArkConfigError("refresh() needs a refresh token.")
        metadata = self.metadata()

        body: Dict[str, Any] = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        # RFC 6749 §6: scope may be narrowed here, never widened. The server rejects a widening.
        if scopes:
            body["scope"] = " ".join(scopes)

        response = self._token_request(metadata["token_endpoint"], body)
        return self._to_token_set(response, nonce=None)

    def client_credentials(
        self,
        *,
        scopes: Sequence[str] = (),
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        force: bool = False,
        renew_before_seconds: int = 60,
    ) -> TokenSet:
        """
        The client credentials grant — the service authenticating as itself, with no user involved.

        Tokens are cached per client and scope set until shortly before they expire. A service that
        asks for a fresh token on every outbound call turns one request into two and rate-limits
        itself against its own identity provider.
        """
        if self._config.token_endpoint_auth_method == "none" and not client_secret:
            raise ArkConfigError(
                "the client_credentials grant requires client authentication; a public client "
                "cannot use it. Register a confidential client (client_secret_basic or "
                "private_key_jwt) for service-to-service calls."
            )

        identifier = client_id or self._config.client_id
        scope_value = " ".join(scopes)
        key = f"{self._config.authority}|{identifier}|{scope_value}"

        cached = self._service_tokens.get(key)
        if not force and cached and not cached.expired(renew_before_seconds):
            return cached

        metadata = self.metadata()
        body: Dict[str, Any] = {"grant_type": "client_credentials"}
        if scope_value:
            body["scope"] = scope_value

        response = self._token_request(
            metadata["token_endpoint"],
            body,
            client_id=identifier,
            client_secret=client_secret,
        )
        tokens = TokenSet(response)
        self._service_tokens[key] = tokens
        return tokens

    # =================================================================
    # Device authorization grant (RFC 8628)
    # =================================================================

    def device_authorization(self, *, scopes: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        """Step one of the device grant: ask for a code, then show the user ``verification_uri_complete``."""
        metadata = self.metadata()
        endpoint = metadata.get("device_authorization_endpoint")
        if not endpoint:
            raise ArkOAuthError(
                "unsupported_grant_type",
                "this tenant does not serve the device authorization grant.",
                endpoint=self._config.authority,
            )
        scope_value = " ".join(scopes if scopes is not None else self._config.scopes)
        form, headers = self._client_authentication({"scope": scope_value}, endpoint)
        return post_form(endpoint, form, headers=headers, **self._http)

    def poll_device_token(
        self,
        device_authorization: Union[Mapping[str, Any], str],
        *,
        on_pending: Optional[Callable[[ArkOAuthError], None]] = None,
        interval_seconds: Optional[float] = None,
        timeout_seconds: Optional[float] = None,
        cancel: Optional[threading.Event] = None,
    ) -> TokenSet:
        """
        Step two: poll the token endpoint until the user approves on their other device.

        The two error codes that are not failures are handled here — ``authorization_pending`` means
        keep waiting, and ``slow_down`` means the server wants a longer interval and will keep
        saying so until it gets one (RFC 8628 §3.5). Everything else ends the wait.
        """
        metadata = self.metadata()
        authorization: Mapping[str, Any] = (
            {"device_code": device_authorization}
            if isinstance(device_authorization, str)
            else device_authorization
        )
        device_code = authorization.get("device_code")
        interval = float(
            interval_seconds if interval_seconds is not None else authorization.get("interval", 5)
        )
        deadline = time.monotonic() + float(
            timeout_seconds if timeout_seconds is not None else authorization.get("expires_in", 600)
        )

        while True:
            if cancel is not None and cancel.is_set():
                raise ArkOAuthError(
                    "access_denied",
                    "the device flow was cancelled.",
                    endpoint=metadata["token_endpoint"],
                )
            if time.monotonic() >= deadline:
                raise ArkOAuthError(
                    "expired_token",
                    "the device code expired before the user approved it.",
                    endpoint=metadata["token_endpoint"],
                )

            if cancel is not None:
                cancel.wait(interval)
            else:
                time.sleep(interval)

            try:
                response = self._token_request(
                    metadata["token_endpoint"],
                    {
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code,
                    },
                )
                return self._to_token_set(response, nonce=None)
            except ArkOAuthError as error:
                if error.error == "authorization_pending":
                    if on_pending:
                        on_pending(error)
                    continue
                if error.error == "slow_down":
                    interval += 5  # §3.5: add five seconds and keep going
                    if on_pending:
                        on_pending(error)
                    continue
                raise

    # =================================================================
    # Pushed authorization requests (RFC 9126)
    # =================================================================

    def push_authorization_request(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        metadata = self.metadata()
        endpoint = metadata.get("pushed_authorization_request_endpoint")
        if not endpoint:
            raise ArkOAuthError(
                "invalid_request",
                "this tenant does not serve pushed authorization requests.",
                endpoint=self._config.authority,
            )
        body = {k: v for k, v in params.items() if v is not None and v != ""}
        form, headers = self._client_authentication(body, endpoint)
        return post_form(endpoint, form, headers=headers, **self._http)

    # =================================================================
    # Using and inspecting tokens
    # =================================================================

    def user_info(self, access_token: str) -> Dict[str, Any]:
        """
        The UserInfo endpoint (OIDC Core §5.3).

        Returns only the claims the presented token was granted scope for. Worth calling when a
        claim is needed that the ID token did not carry; not worth calling on every request, since
        the ID token already holds what the scopes unlocked at sign-in.
        """
        if not access_token:
            raise ArkConfigError("user_info() needs an access token.")
        metadata = self.metadata()
        return get_json(
            metadata["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access_token}"},
            **self._http,
        )

    def introspect(self, token: str, *, token_type_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Token introspection (RFC 7662). Requires client authentication, so a public client cannot
        use it — which is deliberate on the server side: an unauthenticated introspection endpoint
        is an oracle for testing captured tokens.

        For a JWT access token from this server, :meth:`verify_access_token` answers the same
        question locally and without a network call; reach for introspection to learn whether a
        *refresh* token is still live, or when the token is opaque.
        """
        metadata = self.metadata()
        endpoint = metadata["introspection_endpoint"]
        body: Dict[str, Any] = {"token": token}
        if token_type_hint:
            body["token_type_hint"] = token_type_hint
        form, headers = self._client_authentication(body, endpoint)
        return post_form(endpoint, form, headers=headers, **self._http)

    def revoke(self, token: str, *, token_type_hint: str = "refresh_token") -> bool:
        """
        Token revocation (RFC 7009). Revoking a refresh token takes down its whole rotation family,
        so this is the call that really ends a session's access — sign-out should make it.

        An unknown token is a success (§2.2): the caller's goal is already met.
        """
        metadata = self.metadata()
        endpoint = metadata["revocation_endpoint"]
        body: Dict[str, Any] = {"token": token}
        if token_type_hint:
            body["token_type_hint"] = token_type_hint
        form, headers = self._client_authentication(body, endpoint)
        post_form(endpoint, form, headers=headers, **self._http)
        return True

    def end_session_url(
        self,
        *,
        id_token_hint: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
        state: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> str:
        """
        The RP-initiated logout URL.

        ``id_token_hint`` is what lets the provider know which session to end and which client
        asked, and without it the ``post_logout_redirect_uri`` cannot be matched against a
        registration — so the user is left on the provider's "signed out" page instead of coming
        back to the application.
        """
        metadata = self.metadata()
        endpoint = metadata.get("end_session_endpoint")
        if not endpoint:
            raise ArkOAuthError(
                "server_error",
                "the provider's metadata has no 'end_session_endpoint'.",
                endpoint=self._config.authority,
            )

        params: Dict[str, str] = {"client_id": client_id or self._config.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        target = post_logout_redirect_uri or self._config.post_logout_redirect_uri
        if target:
            params["post_logout_redirect_uri"] = target
        if state:
            params["state"] = state
        return f"{endpoint}?{urlencode(params)}"

    def verify_id_token(
        self,
        id_token: str,
        *,
        nonce: Optional[str] = None,
        access_token: Optional[str] = None,
        code: Optional[str] = None,
        max_age: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Verifies an ID token against the provider's keys and the values from the sign-in transaction."""
        metadata = self.metadata()
        return verify_jwt(
            id_token,
            self.jwks(),
            issuer=metadata["issuer"],
            audience=self._config.client_id,
            nonce=nonce,
            access_token=access_token,
            code=code,
            max_age_seconds=max_age,
            require_token_hashes=self._config.require_token_hashes,
            require_iat=True,
            clock_tolerance_seconds=self._config.clock_tolerance_seconds,
            algorithms=self._config.id_token_signing_algorithms,
        )

    def verify_access_token(
        self,
        token: str,
        *,
        audience: Optional[str] = None,
        scopes: Sequence[str] = (),
        ark_claims: Sequence[str] = (),
        require_type_header: bool = True,
    ) -> Dict[str, Any]:
        """
        Verifies an access token this server issued — the resource-server side of the library.

        Local verification against the cached JWKS, so protecting an API costs no network call per
        request. ``scopes`` and ``ark_claims`` are checked here rather than left to the caller,
        because "the token is valid" and "the token is allowed to do this" are different questions
        and only the second one is the authorization decision.
        """
        metadata = self.metadata()
        payload = verify_jwt(
            token,
            self.jwks(),
            issuer=metadata["issuer"],
            audience=audience or self._config.audience,
            typ="at+jwt" if require_type_header else None,
            require_iat=True,
            clock_tolerance_seconds=self._config.clock_tolerance_seconds,
        )

        granted = {s for s in str(payload.get("scope") or "").split(" ") if s}
        missing_scopes = [s for s in scopes if s not in granted]
        if missing_scopes:
            raise ArkOAuthError(
                "insufficient_scope",
                f"the token is missing the scope(s): {', '.join(missing_scopes)}.",
                status=403,
            )

        raw_claims = payload.get("ark_claims")
        held = set(raw_claims if isinstance(raw_claims, (list, tuple)) else ([raw_claims] if raw_claims else []))
        missing_claims = [c for c in ark_claims if c not in held]
        if missing_claims:
            raise ArkOAuthError(
                "insufficient_scope",
                f"the token is missing the authorization claim(s): {', '.join(missing_claims)}.",
                status=403,
            )

        return payload

    # =================================================================
    # Dynamic client registration (RFC 7591 / 7592)
    # =================================================================

    def register_client(
        self, client_metadata: Mapping[str, Any], initial_access_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Registers a client. Off by default on the server, and when on it wants an initial access
        token carrying the ``client.register`` scope — which itself comes from the client
        credentials grant, so registration is a two-step chain rather than an open endpoint.

        The response carries ``client_secret`` exactly once; it is stored only as a hash and cannot
        be read back afterwards.
        """
        metadata = self.metadata()
        endpoint = metadata.get("registration_endpoint")
        if not endpoint:
            raise ArkOAuthError(
                "registration_not_supported",
                "this tenant does not serve dynamic client registration.",
                endpoint=self._config.authority,
            )
        response = http_request(
            endpoint,
            method="POST",
            json_body=dict(client_metadata),
            headers={"Authorization": f"Bearer {initial_access_token}"}
            if initial_access_token
            else {},
            **self._http,
        )
        return response.body if isinstance(response.body, dict) else {}

    def read_registration(self, client_id: str, registration_access_token: str) -> Dict[str, Any]:
        """Reads a registration back (RFC 7592 §2.1), using the registration access token from creation."""
        metadata = self.metadata()
        return get_json(
            f"{str(metadata['registration_endpoint']).rstrip('/')}/{client_id}",
            headers={"Authorization": f"Bearer {registration_access_token}"},
            **self._http,
        )

    def delete_registration(self, client_id: str, registration_access_token: str) -> bool:
        """Deletes a registration (RFC 7592 §2.3)."""
        metadata = self.metadata()
        http_request(
            f"{str(metadata['registration_endpoint']).rstrip('/')}/{client_id}",
            method="DELETE",
            headers={"Authorization": f"Bearer {registration_access_token}"},
            **self._http,
        )
        return True

    # =================================================================
    # Diagnostics
    # =================================================================

    def check_setup(self, *, origin: Optional[str] = None) -> Dict[str, Any]:
        """
        Pairs this application's configuration with the provider's live metadata and reports what
        does not line up.

        The same idea as ``ArkSetupProbe`` in the .NET client — and
        :class:`ark_oauth_client.probe.ArkSetupProbe` here is the fuller, renderable version. This
        one returns a plain dict for a health endpoint or a CI check. Without it, the first symptom
        of a wrong port, a stopped provider, a missing tenant id or a scope the client was never
        registered for is ``invalid_request`` on a page the user is looking at.
        """
        config = self._config
        report: Dict[str, Any] = {
            "authority": config.authority,
            "client_id": config.client_id,
            "is_confidential": config.is_confidential,
            "token_endpoint_auth_method": config.token_endpoint_auth_method,
            "scopes": list(config.scopes),
            "redirect_uri": config.redirect_uri
            or (f"{origin.rstrip('/')}/signin-oidc" if origin else None),
            "post_logout_redirect_uri": config.post_logout_redirect_uri,
            "discovery_url": config.discovery_url,
            "discovery_ok": False,
            "discovery_error": None,
            "provider": None,
            "signing_keys": [],
            "problems": [],
        }
        problems: List[str] = report["problems"]

        try:
            metadata = self.metadata(force=True)
            report["discovery_ok"] = True
        except Exception as error:
            report["discovery_error"] = str(error)
            problems.append(f"The provider's discovery document could not be read: {error}")
            return report

        report["provider"] = {
            "issuer": metadata.get("issuer"),
            "authorization_endpoint": metadata.get("authorization_endpoint"),
            "token_endpoint": metadata.get("token_endpoint"),
            "userinfo_endpoint": metadata.get("userinfo_endpoint"),
            "jwks_uri": metadata.get("jwks_uri"),
            "end_session_endpoint": metadata.get("end_session_endpoint"),
            "device_authorization_endpoint": metadata.get("device_authorization_endpoint"),
            "pushed_authorization_request_endpoint": metadata.get(
                "pushed_authorization_request_endpoint"
            ),
            "registration_endpoint": metadata.get("registration_endpoint"),
            "scopes_supported": metadata.get("scopes_supported", []),
            "grant_types_supported": metadata.get("grant_types_supported", []),
            "code_challenge_methods_supported": metadata.get("code_challenge_methods_supported", []),
            "response_modes_supported": metadata.get("response_modes_supported", []),
            "token_endpoint_auth_methods_supported": metadata.get(
                "token_endpoint_auth_methods_supported", []
            ),
            "require_pushed_authorization_requests": metadata.get(
                "require_pushed_authorization_requests"
            )
            is True,
        }

        try:
            report["signing_keys"] = [
                {"kid": k.get("kid"), "kty": k.get("kty"), "alg": k.get("alg"), "use": k.get("use")}
                for k in self.jwks().keys(force=True)
            ]
        except Exception as error:
            problems.append(f"The provider's signing keys could not be read: {error}")

        supported = set(metadata.get("scopes_supported") or [])
        unknown = [s for s in config.scopes if s not in supported] if supported else []
        if unknown:
            problems.append(
                f"The tenant does not publish the scope(s) {', '.join(unknown)}. A scope this "
                "client is not registered for is rejected outright, not dropped."
            )

        if "S256" not in (metadata.get("code_challenge_methods_supported") or []):
            problems.append(
                "The tenant does not advertise the S256 PKCE method, which this client always sends."
            )

        methods = metadata.get("token_endpoint_auth_methods_supported") or []
        if methods and config.token_endpoint_auth_method not in methods:
            problems.append(
                f"This client authenticates with '{config.token_endpoint_auth_method}', which the "
                f"tenant does not list ({', '.join(methods)})."
            )

        if config.use_par and not metadata.get("pushed_authorization_request_endpoint"):
            problems.append("use_par is on, but the tenant does not serve pushed authorization requests.")
        if metadata.get("require_pushed_authorization_requests") is True and not config.use_par:
            problems.append(
                "The tenant requires pushed authorization requests; set use_par=True or plain "
                "/authorize calls will be refused."
            )

        if not report["redirect_uri"]:
            problems.append(
                "No redirect_uri is configured, so an interactive sign-in cannot be started."
            )

        return report

    # =================================================================
    # internals
    # =================================================================

    def _token_request(
        self,
        endpoint: str,
        body: Mapping[str, Any],
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POSTs to the token endpoint with whatever client authentication this client is registered for."""
        form, headers = self._client_authentication(
            body, endpoint, client_id=client_id, client_secret=client_secret
        )
        return post_form(endpoint, form, headers=headers, **self._http)

    def _client_authentication(
        self,
        body: Mapping[str, Any],
        endpoint: str,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        """
        Applies the client's registered authentication method.

        RFC 6749 §2.3 forbids presenting more than one set of credentials in a single request and
        the Ark server rejects rather than resolves that, so exactly one of these branches may
        contribute a credential. ``client_id`` in the body is not a credential and always goes
        along: the ``none`` method needs it, and with Basic the server reads the header regardless.
        """
        config = self._config
        identifier = client_id or config.client_id
        secret = client_secret or config.client_secret
        method = (
            "client_secret_basic"
            if client_secret and config.token_endpoint_auth_method == "none"
            else config.token_endpoint_auth_method
        )

        form: Dict[str, Any] = dict(body)
        form["client_id"] = identifier
        headers: Dict[str, str] = {}

        if method == "client_secret_basic":
            headers["Authorization"] = basic_auth_header(identifier, secret)
        elif method == "client_secret_post":
            form["client_secret"] = secret
        elif method == "private_key_jwt":
            form["client_assertion_type"] = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            form["client_assertion"] = self._client_assertion(identifier, endpoint)

        return form, headers

    def _client_assertion(self, client_id: str, endpoint: str) -> str:
        """
        A ``private_key_jwt`` client assertion (OIDC Core §9).

        ``jti`` is random and the lifetime is short because the server refuses a ``jti`` it has
        already seen — a captured assertion is worth nothing on its second use.
        """
        key = self._config.private_key_jwt
        if key is None:  # pragma: no cover - normalize_config refuses this combination
            raise ArkConfigError("private_key_jwt was selected but no key is configured.")
        now = int(time.time())
        return sign_jwt(
            {
                "iss": client_id,
                "sub": client_id,  # §9: both must be the client id
                "aud": endpoint,
                "jti": random_token(16),
                "iat": now,
                "nbf": now,
                "exp": now + key.lifetime_seconds,
            },
            key=key.private_key,
            alg=key.alg,
            kid=key.kid,
        )

    def _to_token_set(
        self,
        response: Mapping[str, Any],
        *,
        nonce: Optional[str],
        code: Optional[str] = None,
        max_age: Optional[int] = None,
    ) -> TokenSet:
        """Turns a token response into a TokenSet, validating the ID token when there is one."""
        claims = None

        if response.get("id_token"):
            claims = self.verify_id_token(
                response["id_token"],
                nonce=nonce,
                access_token=response.get("access_token"),
                code=code,
                max_age=max_age,
            )
        elif nonce is not None and "openid" in str(response.get("scope") or "").split(" "):
            # openid was granted but nothing came back to prove who signed in.
            raise ArkTokenError(
                "the token response contains no id_token, although the openid scope was granted."
            )

        return TokenSet(response, claims=claims)


def create_ark_client(**options: Any) -> ArkOAuthClient:
    """Convenience factory, for callers who prefer a function to a constructor."""
    return ArkOAuthClient(**options)
