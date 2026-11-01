"""
Interactive sign-in and API protection for Flask.

This is the Python counterpart of ``AddArkOidcClient`` / ``UseArkOidcClient`` in the .NET package.
One call in the app factory plus an authority and a client id, and ``@auth.require_auth()`` works::

    from flask import Flask
    from ark_oauth_client.flask import add_ark_oidc_client

    app = Flask(__name__)
    auth = add_ark_oidc_client(app, {
        "authority": "https://idp.example.com/my_idp",
        "client_id": "my-app",
        "client_secret": os.environ["ARK_CLIENT_SECRET"],
    })

    @app.get("/billing")
    @auth.require_claims("billing.admin")
    def billing():
        return f"hello {current_ark.user['name']}"

What it takes care of, all of which is easy to get subtly wrong by hand:

* the login transaction — ``state``, ``nonce`` and the PKCE verifier, stored server-side, one per
  concurrent sign-in, so two tabs do not overwrite each other;
* the callback checks, in the order that makes them meaningful;
* silent refresh shortly before the access token expires, serialised per session, because this
  server rotates refresh tokens and treats a reused one as theft of the whole family;
* sign-out that actually ends the session — the refresh token revoked at the provider, the
  server-side session destroyed, the cookie cleared, and only then the redirect to the IdP;
* the shared-browser case: the entitlement check at the callback, the access-denied page, and the
  ``prompt=login`` switch that is the only way out of it.

The six paths it claims are served from a ``before_request`` hook rather than as routed views. That
is deliberate, and it is what the .NET client does too: the access-denied page has to render for a
user who is not signed in and may not be allowed to be, so it must not sit behind the application's
own authentication guard. Short-circuiting ahead of the view sidesteps that entirely, and means the
host does not have to register anything.
"""

from __future__ import annotations

import threading
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .access import (
    ArkAccessDeniedPage,
    ArkAccessDeniedReasons,
    ArkAccessDeniedState,
    ArkAccessGate,
    ArkAccountSwitchOptions,
    ArkChallengeProperties,
    ArkClientEvents,
    ArkClientOptions,
    ArkDeniedAccount,
    check_same_origin,
    local_or_default,
    read_field,
)
from .auth_config import ArkAuthConfig
from .client import ArkOAuthClient, AuthorizationRequest
from .context import ArkAuthContext
from .errors import ArkCallbackError, ArkConfigError, ArkOAuthError
from .flows import ArkClientCredentials, ArkRegistration
from .helper import AuthClientHelper
from .probe import ArkSetupProbe
from .session import (
    MemorySessionStore,
    SessionStore,
    create_session_id,
    sign_session_id,
    unsign_session_id,
)
from .tokens import TokenSet

__all__ = [
    "ArkFlask",
    "ArkBearer",
    "add_ark_oidc_client",
    "add_ark_oidc_api",
    "ark_flask",
    "ark_bearer",
    "use_ark_account_endpoints",
    "current_ark",
    "get_ark_access_token",
    "get_ark_id_token",
    "get_ark_refresh_token",
    "with_ark_token",
    "ark_switch_user",
    "ark_sign_out_everywhere",
    "ark_sign_out_locally",
    "ark_denied_account",
]

DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60  # matches the server's default SessionLifetimeMinutes
TRANSACTION_TTL_SECONDS = 10 * 60
MAX_CONCURRENT_TRANSACTIONS = 5

#: Refresh a little before expiry so a request in flight never carries a dead token. The .NET
#: client uses the same two-minute window.
REFRESH_WINDOW_SECONDS = 120

_EXTENSION_KEY = "ark_oauth_client"


# ---------------------------------------------------------------------------
# the request-scoped view of the caller
# ---------------------------------------------------------------------------


class ArkRequest:
    """What ``current_ark`` exposes: who is signed in, and the tokens behind them."""

    def __init__(
        self,
        ark: "ArkFlask",
        session_id: Optional[str],
        session: Optional[Dict[str, Any]],
        tokens: Optional[TokenSet],
    ) -> None:
        self._ark = ark
        self._session = session
        self.client = ark.client
        self.store = ark.store
        self.is_authenticated = bool(session and session.get("tokens") and tokens)
        self.session_id = session_id if self.is_authenticated else None
        self.user: Optional[Dict[str, Any]] = (
            session.get("user") if self.is_authenticated and session else None
        )
        self.sub: Optional[str] = session.get("sub") if self.is_authenticated and session else None
        self.claims: List[str] = (
            list(session.get("ark_claims") or []) if self.is_authenticated and session else []
        )
        self.tokens: Optional[TokenSet] = tokens if self.is_authenticated else None
        self.scopes: List[str] = tokens.scopes() if tokens else []
        self.id_token: Optional[str] = tokens.id_token if self.is_authenticated and tokens else None

    def access_token(self) -> Optional[str]:
        """The current access token, refreshed first if it is about to expire."""
        if not self.is_authenticated or self.session_id is None or self._session is None:
            return None
        current = self._ark._fresh_tokens(self.session_id, self._session)
        return current.access_token if current else None

    def authorize(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Attaches the access token to a downstream request's headers."""
        headers = dict(headers or {})
        token = self.access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def has_claim(self, *wanted: str) -> bool:
        held = set(self.claims)
        return all(claim in held for claim in wanted)

    def has_scope(self, *wanted: str) -> bool:
        held = set(self.scopes)
        return all(scope in held for scope in wanted)

    def context(self) -> ArkAuthContext:
        """The :class:`~ark_oauth_client.context.ArkAuthContext` for this request."""
        from flask import request

        return ArkAuthContext(
            self._ark.config,
            claims=self.user,
            ark_claims=self.claims,
            client_id=self._ark.config.client_id,
            ip=request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
            or None,
            is_authenticated=self.is_authenticated,
        )

    def login(self, **options: Any):
        """Starts a sign-in from a view of your own."""
        return self._ark._start_login(**options)

    def logout(self, **options: Any):
        """Ends the session from a view of your own."""
        return self._ark._end_session(**options)


def _current() -> ArkRequest:
    from flask import g

    ark = getattr(g, "ark", None)
    if ark is None:
        raise ArkConfigError(
            "there is no Ark context on this request — call add_ark_oidc_client(app) during "
            "application setup."
        )
    return ark


def _make_current_ark():
    try:
        from werkzeug.local import LocalProxy
    except ImportError:  # pragma: no cover - Flask always brings Werkzeug
        return _current
    return LocalProxy(_current)


#: The signed-in user for the current request, in the manner of Flask's ``current_app``.
current_ark = _make_current_ark()


# ---------------------------------------------------------------------------
# the integration
# ---------------------------------------------------------------------------


class ArkFlask:
    """Interactive sign-in for a Flask application. Create one and keep it on the app."""

    def __init__(
        self,
        app: Any = None,
        config: Any = None,
        *,
        client: Optional[ArkOAuthClient] = None,
        events: Optional[ArkClientEvents] = None,
        secret: Any = None,
        store: Optional[SessionStore] = None,
        cookie_name: Optional[str] = None,
        cookie_secure: Optional[bool] = None,
        cookie_samesite: str = "Lax",
        cookie_domain: Optional[str] = None,
        session_ttl_seconds: Optional[int] = None,
        refresh_leeway_seconds: int = REFRESH_WINDOW_SECONDS,
        fetch_user_info: bool = False,
        return_to_param: str = "returnTo",
        default_return_to: str = "/",
        trust_proxy: bool = True,
        service_token: Optional[str] = None,
        **client_options: Any,
    ) -> None:
        self.config = _as_auth_config(config, client_options)
        self.events = events or ArkClientEvents()
        self.switch: ArkAccountSwitchOptions = (
            self.config.account_switch or ArkAccountSwitchOptions()
        )

        self._explicit_client = client
        self._client: Optional[ArkOAuthClient] = client
        self._client_options = client_options

        self.store: SessionStore = store or MemorySessionStore()
        self._secret = secret
        self.cookie_name = cookie_name or self.config.resolve_cookie_name()
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_domain = cookie_domain or (
            self.config.domain if self.config.domain and self.config.domain != "localhost" else None
        )
        self.session_ttl_seconds = session_ttl_seconds or max(
            60, int(self.config.expire_mins or 480) * 60
        )
        self.refresh_leeway_seconds = refresh_leeway_seconds
        self.fetch_user_info = fetch_user_info
        self.return_to_param = return_to_param
        self.default_return_to = default_return_to
        self.trust_proxy = trust_proxy

        # Refreshes in flight, keyed by session id. With rotation on, two requests refreshing the
        # same session at once would present the same refresh token twice — which the server reads
        # as theft and answers by revoking the entire family, signing the user out of everything.
        # Within one process this collapses them into a single exchange; across processes, a shared
        # store needs a lock of its own.
        self._refresh_locks: Dict[str, threading.Lock] = {}
        self._refresh_guard = threading.Lock()

        http = {"timeout": 15.0}
        self.probe = ArkSetupProbe(self.config, **http)
        self.client_credentials = ArkClientCredentials(self.config, self.probe, **http)
        self.registration = ArkRegistration(self.probe, **http)
        self.onboarding = AuthClientHelper(self.config, service_token, **http)

        self.app = app
        if app is not None:
            self.init_app(app)

    # -- setup ---------------------------------------------------------

    def init_app(self, app: Any) -> "ArkFlask":
        if not self._secret:
            self._secret = app.config.get("SECRET_KEY") or app.secret_key
        if not self._secret or len(str(self._secret)) < 16:
            raise ArkConfigError(
                "ark_oauth_client: a session secret of at least 16 characters is required. It "
                "signs the session cookie; set Flask's SECRET_KEY, or pass secret=…, and use the "
                "same value across every instance behind a load balancer."
            )

        if self.cookie_secure is None:
            # Plain http is only ever local development, and a Secure cookie is simply not stored
            # there — which looks exactly like a broken sign-in loop.
            self.cookie_secure = bool(app.config.get("SESSION_COOKIE_SECURE", True))

        app.extensions = getattr(app, "extensions", {})
        app.extensions[_EXTENSION_KEY] = self

        # Registered before any guard the application adds of its own, so the pages that explain a
        # failed sign-in are never themselves redirected away.
        app.before_request(self._before_request)
        # A session that dies mid-request (a spent refresh token) leaves a cookie the browser would
        # keep presenting; clearing it here means the next request is cleanly anonymous.
        app.after_request(self._after_request)
        self.app = app
        return self

    @property
    def client(self) -> ArkOAuthClient:
        """The protocol client, built lazily so configuration can be completed after construction."""
        if self._client is None:
            self._client = _build_client(self.config, self._client_options)
        return self._client

    # -- paths ---------------------------------------------------------

    @property
    def login_path(self) -> str:
        return self.config.login_path

    @property
    def callback_path(self) -> str:
        return self.config.resolve_callback_path()

    @property
    def logout_path(self) -> str:
        return self.config.logout_path

    # -- the hook ------------------------------------------------------

    def _before_request(self):
        from flask import request

        path = request.path
        switch = self.switch

        # The account endpoints first: they must answer even when everything else refuses to.
        if switch and switch.enabled and switch.auto_register_endpoints:
            response = self._serve_account_endpoints(path)
            if response is not None:
                return response

        if path == self.login_path:
            return self._start_login()
        if path == self.callback_path:
            return self._complete_login()
        if path == self.logout_path:
            return self._end_session()

        self._attach_context()
        return None

    def _after_request(self, response):
        from flask import g

        if getattr(g, "ark_drop_cookie", False):
            response.delete_cookie(
                self.cookie_name, domain=self.cookie_domain, path="/", samesite=self.cookie_samesite
            )
        return response

    def _drop_cookie_after_request(self) -> None:
        from flask import g, has_request_context

        if has_request_context():
            g.ark_drop_cookie = True

    def _serve_account_endpoints(self, path: str):
        from flask import Response, request

        switch = self.switch
        if _same_path(path, switch.switch_user_path):
            ok, status, message = check_same_origin(
                request.method, request.headers, self._origin()
            )
            if not ok:
                headers = {"Allow": "POST"} if status == 405 else {}
                return Response(message, status=status, headers=headers, mimetype="text/plain")
            return self.switch_user(
                read_field(request.form, request.args, "returnUrl"),
                read_field(request.form, request.args, "login_hint"),
            )

        if _same_path(path, switch.sign_out_path):
            if not switch.allow_full_sign_out:
                return Response("Not Found", status=404, mimetype="text/plain")
            ok, status, message = check_same_origin(
                request.method, request.headers, self._origin()
            )
            if not ok:
                headers = {"Allow": "POST"} if status == 405 else {}
                return Response(message, status=status, headers=headers, mimetype="text/plain")
            return self.sign_out_everywhere(read_field(request.form, request.args, "returnUrl"))

        if switch.serve_default_page and _same_path(path, switch.access_denied_path):
            self._attach_context()
            return self._render_access_denied()

        return None

    # -- the three flows -----------------------------------------------

    def _start_login(
        self,
        *,
        return_to: Optional[str] = None,
        prompt: Optional[str] = None,
        login_hint: Optional[str] = None,
        scopes: Optional[Sequence[str]] = None,
        max_age: Optional[int] = None,
        fresh_session: bool = False,
    ):
        from flask import redirect, request

        transaction = self.client.create_authorization_url(
            redirect_uri=self._redirect_uri(),
            return_to=return_to
            or local_or_default(request.args.get(self.return_to_param), None)
            or self.default_return_to,
            prompt=prompt,
            login_hint=login_hint or request.args.get("login_hint"),
            scopes=scopes,
            max_age=max_age,
        )

        # A switch starts from nothing: the previous account's session has just been destroyed, so
        # loading it back would resurrect a dead id.
        session_id, session = (None, None) if fresh_session else self._load_session()
        session = session or {"created_at": int(time.time()), "txs": {}}
        transactions = dict(session.get("txs") or {})
        transactions[transaction.state] = transaction.to_dict()
        session["txs"] = _prune_transactions(transactions)

        response = redirect(transaction.url)
        self._save_session(response, session_id, session)
        return response

    def _complete_login(self):
        from flask import redirect, request

        params = request.form.to_dict() if request.method == "POST" else request.args.to_dict()
        session_id, session = self._load_session()
        state = params.get("state")
        stored = (session or {}).get("txs", {}).get(state) if state else None

        if not stored:
            # No transaction means the response cannot be tied to a sign-in this browser started:
            # an expired login, a session lost to a restart with an in-memory store, or a forged
            # callback.
            return self._fail(
                ArkCallbackError(
                    "this sign-in could not be matched to a request from this browser. It may have "
                    "expired — start again from the login page."
                )
            )

        transaction = AuthorizationRequest.from_dict(stored)
        try:
            tokens = self.client.handle_callback(
                params, transaction, redirect_uri=self._redirect_uri()
            )
        except Exception as error:
            assert session is not None
            session["txs"].pop(state, None)
            response = self._fail(error)
            self._save_session(response, session_id, session)
            return response

        ark_claims = tokens.ark_claims()

        # The last point before the session cookie is written. Refusing here rather than at the
        # first protected page is the whole difference: the browser never ends up holding a session
        # for an account that cannot use this application.
        if self.switch.require_ark_claims or self.events.on_evaluate_access is not None:
            if not ArkAccessGate.allowed(
                self.switch, self.events, tokens.claims, ark_claims, tokens=tokens
            ):
                return self._deny(
                    ArkAccessDeniedReasons.NO_APP_ACCESS,
                    tokens.claims,
                    ark_claims,
                    local_or_default(transaction.return_to, self.switch.home_path),
                )

        # A fresh session id at the moment privileges change, so a session id an attacker planted
        # before sign-in is not the one that ends up authenticated (session fixation).
        #
        # Sign-ins still outstanding in other tabs move across to the new session. They are bound to
        # this browser and nothing else — dropping them along with the old session id is what turns
        # a second open tab into "this sign-in could not be matched to a request from this browser".
        carried = _prune_transactions(dict((session or {}).get("txs") or {}))
        carried.pop(state, None)
        if session_id:
            self.store.destroy(session_id)

        user: Dict[str, Any] = dict(tokens.claims or {})
        if self.fetch_user_info and tokens.access_token and tokens.has_scope("openid"):
            try:
                user.update(self.client.user_info(tokens.access_token))
            except Exception:
                # UserInfo is supplementary; the ID token already carries what the scopes unlocked.
                pass

        fresh = {
            "created_at": int(time.time()),
            "txs": carried,
            "tokens": tokens.to_dict(),
            "user": user,
            "ark_claims": ark_claims,
            "sub": tokens.subject,
        }

        response = redirect(local_or_default(transaction.return_to, self.default_return_to))
        self._save_session(response, None, fresh, replace_cookie=True)
        return response

    def _end_session(self, *, return_to: Optional[str] = None):
        from flask import redirect

        session_id, session = self._load_session()
        tokens = TokenSet.from_dict((session or {}).get("tokens"))

        if tokens and tokens.refresh_token:
            try:
                # Ending the local session leaves the refresh token live at the provider until it
                # expires; revoking takes down its whole family, which is what "sign out" is
                # expected to mean.
                self.client.revoke(tokens.refresh_token, token_type_hint="refresh_token")
            except Exception:
                # Best effort: a provider that is down must not prevent a local sign-out.
                pass

        target = local_or_default(return_to, self.config.signed_out_redirect_uri) or self.default_return_to
        try:
            target = self.client.end_session_url(
                id_token_hint=tokens.id_token if tokens else None,
                post_logout_redirect_uri=self.client.config.post_logout_redirect_uri
                or self._absolute(local_or_default(return_to, self.default_return_to)),
            )
        except Exception:
            # A tenant with no end_session_endpoint still gets a clean local sign-out.
            pass

        response = redirect(target)
        self._drop_session(response, session_id)
        return response

    # -- account switching ---------------------------------------------

    def switch_user(self, return_url: Optional[str] = None, login_hint: Optional[str] = None):
        """
        Abandons the account this application is signed in as and asks the provider for the sign-in
        form, so the person at the keyboard can enter their own credentials.

        The local session is dropped first. Without that, a user who abandons the sign-in at the
        provider comes back to a browser still holding the previous person's session.
        """
        target = local_or_default(return_url, self.switch.home_path)

        if self.switch.end_provider_session_on_switch:
            # Ends the provider session as well, which signs the previous user out of every
            # application they had open. They land back here unauthenticated, and the next
            # protected page draws the sign-in form because there is no session left to answer it.
            return self._end_session(return_to=target)

        # Dropped before the challenge is built, not after: _start_login stores the new login
        # transaction in the session, so destroying the old session afterwards would take the
        # transaction with it and the callback would have nothing to match against.
        session_id, _ = self._load_session()
        if session_id:
            self.store.destroy(session_id)

        properties = ArkChallengeProperties.switch_user(target, login_hint, self.switch.prompt)
        response = self._start_login(
            return_to=properties["return_to"],
            prompt=properties["prompt"],
            login_hint=properties.get("login_hint"),
            fresh_session=True,
        )
        ArkAccessDeniedState.clear(response)
        return response

    def sign_out_everywhere(self, return_url: Optional[str] = None):
        """
        RP-initiated logout: this application's session and the provider's. Other applications
        signed in through the same provider session are told through back-channel logout.
        """
        response = self._end_session(return_to=local_or_default(return_url, self.switch.home_path))
        ArkAccessDeniedState.clear(response)
        return response

    def sign_out_locally(self, return_url: Optional[str] = None):
        """Ends this application's session only, leaving the provider session intact."""
        from flask import redirect

        session_id, _ = self._load_session()
        response = redirect(local_or_default(return_url, self.switch.home_path))
        self._drop_session(response, session_id)
        ArkAccessDeniedState.clear(response)
        return response

    def denied_account(self) -> Optional[ArkDeniedAccount]:
        """
        What the last denial was about, for a host rendering its own access-denied page.

        ``None`` when the user did not arrive from one — read ``current_ark`` instead.
        """
        from flask import request

        return ArkAccessDeniedState.read(request, self._secret)

    def _deny(
        self,
        reason: str,
        claims: Optional[Mapping[str, Any]],
        ark_claims: Sequence[str],
        return_url: Optional[str],
    ):
        from flask import redirect

        denied = ArkAccessGate.describe(reason, claims, ark_claims, return_url)

        if self.events.on_access_denied is not None:
            result = self.events.on_access_denied(denied)
            if result is not None:
                return result
            if denied.handled:
                return denied.response

        response = redirect(ArkAccessGate.denied_url(self.switch, return_url))
        ArkAccessDeniedState.write(
            response,
            self._secret,
            ArkAccessGate.to_account(denied),
            secure=bool(self.cookie_secure),
        )
        return response

    def _render_access_denied(self):
        from flask import Response, request

        denied = ArkAccessDeniedState.read(request, self._secret)

        email = denied.email if denied else None
        name = denied.name if denied else None
        if email is None and name is None:
            # Arrived from a 403 rather than from a refused callback, so there is a session to read
            # the account off.
            user = getattr(_current_or_none(), "user", None) or {}
            email = user.get("email") or user.get("preferred_username")
            name = user.get("name")

        account = (email or name) if self.switch.show_signed_in_account else None
        app_name = self.switch.app_display_name or self.config.client_id
        return_url = local_or_default(
            request.args.get("returnUrl") or (denied.return_url if denied else None),
            self.switch.home_path,
        )

        html = ArkAccessDeniedPage.build(self.switch, app_name, account, return_url)
        response = Response(html, status=403, mimetype="text/html")
        response.headers["Cache-Control"] = "no-store, no-cache"
        response.headers["Pragma"] = "no-cache"
        # Spent on read: a stale cookie must not name the wrong account on a later visit.
        ArkAccessDeniedState.clear(response)
        return response

    # -- guards --------------------------------------------------------

    def require_auth(
        self,
        claims: Sequence[str] = (),
        scopes: Sequence[str] = (),
    ) -> Callable[[Callable], Callable]:
        """
        Guards a view.

        An unauthenticated browser request is sent to the login page with a ``returnTo``; an API or
        fetch request gets 401 and an RFC 6750 challenge, because redirecting XHR to a sign-in page
        produces a CORS error rather than anything the caller can act on. A signed-in user missing a
        claim gets 403 — the access-denied page, not a redirect loop.
        """

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any):
                from flask import redirect, request
                from urllib.parse import quote

                ark = _current_or_none()
                if ark is None:
                    raise ArkConfigError(
                        "there is no Ark context on this request — call add_ark_oidc_client(app) "
                        "during application setup."
                    )

                if not ark.is_authenticated:
                    wants_html = "text/html" in (
                        request.headers.get("Accept") or ""
                    ) and request.method == "GET"
                    if not wants_html:
                        return _challenge(401, "invalid_token", "authentication is required.")
                    target = quote(request.full_path.rstrip("?") or "/", safe="")
                    return redirect(f"{self.login_path}?{self.return_to_param}={target}")

                missing_claims = [c for c in claims if c not in ark.claims]
                missing_scopes = [s for s in scopes if s not in ark.scopes]
                if missing_claims or missing_scopes:
                    wants_html = "text/html" in (request.headers.get("Accept") or "")
                    if wants_html and self.switch.enabled:
                        return self._deny(
                            ArkAccessDeniedReasons.FORBIDDEN,
                            ark.user,
                            ark.claims,
                            request.full_path.rstrip("?") or "/",
                        )
                    description = "; ".join(
                        part
                        for part in (
                            f"missing claim(s): {', '.join(missing_claims)}"
                            if missing_claims
                            else "",
                            f"missing scope(s): {', '.join(missing_scopes)}"
                            if missing_scopes
                            else "",
                        )
                        if part
                    )
                    return _challenge(403, "insufficient_scope", description)

                return view(*args, **kwargs)

            return wrapper

        return decorator

    def require_claims(self, *claims: str) -> Callable[[Callable], Callable]:
        """Shorthand for :meth:`require_auth` on Ark authorization claims — the thing to authorise on."""
        return self.require_auth(claims=_flatten(claims))

    def require_scopes(self, *scopes: str) -> Callable[[Callable], Callable]:
        return self.require_auth(scopes=_flatten(scopes))

    # -- diagnostics ---------------------------------------------------

    def setup_model(self):
        """An :class:`~ark_oauth_client.probe.ArkSetupModel` for the current request."""
        from flask import request

        ark = _current_or_none()
        user = (ark.user if ark else None) or {}
        return self.probe.probe(
            origin=self._origin(),
            is_authenticated=bool(ark and ark.is_authenticated),
            signed_in_as=user.get("name") or user.get("email"),
            auth_error=request.args.get("auth_error"),
        )

    # -- session plumbing ----------------------------------------------

    def _load_session(self) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        from flask import request

        signed = request.cookies.get(self.cookie_name)
        session_id = unsign_session_id(signed, self._secret)
        if not session_id:
            return None, None
        data = self.store.get(session_id)
        return (session_id, data) if data else (None, None)

    def _save_session(
        self,
        response: Any,
        session_id: Optional[str],
        data: Dict[str, Any],
        *,
        replace_cookie: bool = False,
    ) -> str:
        new_id = session_id or create_session_id()
        data["updated_at"] = int(time.time())
        self.store.set(new_id, data, self.session_ttl_seconds)
        if session_id is None or replace_cookie:
            response.set_cookie(
                self.cookie_name,
                sign_session_id(new_id, self._secret),
                max_age=self.session_ttl_seconds,
                httponly=True,
                secure=bool(self.cookie_secure),
                samesite=self.cookie_samesite,
                domain=self.cookie_domain,
                path="/",
            )
        return new_id

    def _drop_session(
        self, response: Any, session_id: Optional[str], *, keep_new_cookie: bool = False
    ) -> None:
        if session_id:
            self.store.destroy(session_id)
        if not keep_new_cookie:
            response.delete_cookie(
                self.cookie_name, domain=self.cookie_domain, path="/", samesite=self.cookie_samesite
            )

    def _attach_context(self) -> None:
        from flask import g

        session_id, session = self._load_session()
        tokens = None
        if session_id and session:
            tokens = self._fresh_tokens(session_id, session)
            if tokens is None:
                session = None
                session_id = None
        g.ark = ArkRequest(self, session_id, session, tokens)

    def _fresh_tokens(self, session_id: str, session: Dict[str, Any]) -> Optional[TokenSet]:
        """
        Keeps the access token fresh.

        Without this a session survives only as long as its first access token, and the user is
        bounced back to the IdP the moment it expires.
        """
        tokens = TokenSet.from_dict(session.get("tokens"))
        if tokens is None or not tokens.expired(self.refresh_leeway_seconds) or not tokens.refresh_token:
            return tokens

        with self._refresh_guard:
            lock = self._refresh_locks.setdefault(session_id, threading.Lock())

        with lock:
            # Another thread may have refreshed while this one waited, so the freshest answer is
            # whatever is in the store now -- not the copy this request loaded a moment ago.
            stored = self.store.get(session_id) or {}
            current = TokenSet.from_dict(stored.get("tokens"))
            if current and not current.expired(self.refresh_leeway_seconds):
                session["tokens"] = current.to_dict()
                return current

            try:
                refreshed = self.client.refresh(tokens.refresh_token)
            except ArkOAuthError as error:
                # invalid_grant means the refresh token is spent, revoked, or its session ended at
                # the provider. There is nothing to retry: the user has to sign in again.
                if error.error == "invalid_grant":
                    self.store.destroy(session_id)
                    self._drop_cookie_after_request()
                    return None
                # A transient failure must not sign the user out; the next request retries.
                return tokens
            except Exception:
                return tokens
            finally:
                with self._refresh_guard:
                    self._refresh_locks.pop(session_id, None)

            session["tokens"] = refreshed.to_dict()
            # The ID token is reissued on refresh; keep the identity in step with it.
            if refreshed.claims:
                session["user"] = {**(session.get("user") or {}), **refreshed.claims}
            session["ark_claims"] = refreshed.ark_claims()
            self.store.set(session_id, session, self.session_ttl_seconds)
            return refreshed

    # -- helpers -------------------------------------------------------

    def _origin(self) -> str:
        from flask import request

        if self.trust_proxy:
            proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
            host = (request.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
            if proto and host:
                return f"{proto}://{host}{request.script_root}"
        return f"{request.scheme}://{request.host}{request.script_root}"

    def _absolute(self, path: str) -> str:
        return f"{self._origin()}{path}" if path.startswith("/") else path

    def _redirect_uri(self) -> str:
        configured = self.client.config.redirect_uri
        return configured or self._absolute(self.callback_path)

    def _fail(self, error: Exception):
        from flask import Response, redirect
        from urllib.parse import quote

        if self.config.auth_error_path:
            return redirect(
                f"{self.config.auth_error_path}?auth_error={quote(str(error), safe='')}"
            )
        status = 403 if isinstance(error, ArkOAuthError) and error.status == 403 else 400
        return Response(f"Sign-in failed: {error}", status=status, mimetype="text/plain")


# ---------------------------------------------------------------------------
# the API side
# ---------------------------------------------------------------------------


class ArkBearer:
    """
    Bearer-token authentication for an API — the resource-server half, and the counterpart of
    ``AddArkOidcApi``.

    Verification is local, against the cached JWKS, so this costs no network call per request once
    the keys are loaded. Failures follow RFC 6750: a ``WWW-Authenticate`` challenge naming the
    reason, 401 when the token is missing or bad, 403 when it is valid but not allowed to do this.
    """

    def __init__(
        self,
        client: Optional[ArkOAuthClient] = None,
        *,
        scopes: Sequence[str] = (),
        claims: Sequence[str] = (),
        audience: Optional[str] = None,
        optional: bool = False,
        require_type_header: bool = True,
        **client_options: Any,
    ) -> None:
        self.client = client or ArkOAuthClient(**client_options)
        self.scopes = list(scopes)
        self.claims = list(claims)
        self.audience = audience
        self.optional = optional
        self.require_type_header = require_type_header

    def protect(self, app: Any, prefix: str = "") -> "ArkBearer":
        """Protects every path under ``prefix``, in the manner of ``app.use('/api', bearer)``."""

        @app.before_request
        def _verify():  # pragma: no cover - exercised through the app
            from flask import request

            if prefix and not request.path.startswith(prefix):
                return None
            return self._authenticate()

        return self

    def __call__(self, view: Callable) -> Callable:
        """Used directly as a decorator, verifying with the scopes and claims given at construction."""
        return self.require()(view)

    def require(
        self, scopes: Sequence[str] = (), claims: Sequence[str] = ()
    ) -> Callable[[Callable], Callable]:
        """A per-route guard, for when different endpoints need different scopes or claims."""

        def decorator(view: Callable) -> Callable:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any):
                failure = self._authenticate(
                    extra_scopes=list(scopes), extra_claims=list(claims)
                )
                if failure is not None:
                    return failure
                return view(*args, **kwargs)

            return wrapper

        return decorator

    # ------------------------------------------------------------------

    def _authenticate(
        self, *, extra_scopes: Sequence[str] = (), extra_claims: Sequence[str] = ()
    ):
        from flask import g, request

        header = request.headers.get("Authorization") or ""
        token = header[7:].strip() if header[:7].lower() == "bearer " else None

        if not token:
            if self.optional:
                g.ark = _AnonymousBearer(self.client)
                return None
            return _challenge(401, "invalid_token", "an access token is required.")

        try:
            payload = self.client.verify_access_token(
                token,
                audience=self.audience,
                scopes=list(self.scopes) + list(extra_scopes),
                ark_claims=list(self.claims) + list(extra_claims),
                require_type_header=self.require_type_header,
            )
        except ArkOAuthError as error:
            if error.error == "insufficient_scope":
                return _challenge(
                    403, "insufficient_scope", error.error_description or str(error)
                )
            return _challenge(401, "invalid_token", str(error))
        except Exception as error:
            return _challenge(401, "invalid_token", str(error))

        g.ark = _BearerIdentity(self.client, token, payload)
        return None


class _BearerIdentity:
    """``current_ark`` for a request authenticated by a bearer token rather than a session."""

    def __init__(self, client: ArkOAuthClient, token: str, payload: Mapping[str, Any]) -> None:
        raw = payload.get("ark_claims")
        self.client = client
        self.is_authenticated = True
        self.token = token
        self.payload = dict(payload)
        self.sub = payload.get("sub")
        self.client_id = payload.get("client_id")
        self.session_id = payload.get("sid")
        self.scopes = [s for s in str(payload.get("scope") or "").split(" ") if s]
        self.claims = list(raw) if isinstance(raw, (list, tuple)) else ([raw] if raw else [])
        self.user = dict(payload)

    def has_claim(self, *wanted: str) -> bool:
        held = set(self.claims)
        return all(claim in held for claim in wanted)

    def has_scope(self, *wanted: str) -> bool:
        held = set(self.scopes)
        return all(scope in held for scope in wanted)


class _AnonymousBearer:
    def __init__(self, client: ArkOAuthClient) -> None:
        self.client = client
        self.is_authenticated = False
        self.token = None
        self.payload = None
        self.sub = None
        self.claims: List[str] = []
        self.scopes: List[str] = []
        self.user = None

    def has_claim(self, *wanted: str) -> bool:
        return False

    def has_scope(self, *wanted: str) -> bool:
        return False


# ---------------------------------------------------------------------------
# module-level API, mirroring the .NET extension methods
# ---------------------------------------------------------------------------


def add_ark_oidc_client(
    app: Any,
    config: Any = None,
    configure: Optional[Callable[[ArkClientOptions], None]] = None,
    **options: Any,
) -> ArkFlask:
    """
    Registers Ark authentication for this application.

    ``config`` is the ``ark_oauth_client`` section — an :class:`~ark_oauth_client.auth_config.
    ArkAuthConfig`, a dict in either the C# or the Python spelling, or omitted in favour of keyword
    arguments. ``configure`` receives an :class:`~ark_oauth_client.access.ArkClientOptions` so the
    bound configuration can be adjusted in code and the events attached::

        auth = add_ark_oidc_client(app, config, lambda o: (
            setattr(o.config.account_switch, "require_ark_claims", True),
            setattr(o.events, "on_access_denied", log_it),
        ))
    """
    resolved = _as_auth_config(config, options)
    client_options = ArkClientOptions(config=resolved)
    if configure is not None:
        configure(client_options)
    return ArkFlask(
        app,
        client_options.config,
        events=client_options.events,
        **{k: v for k, v in options.items() if k in _ARKFLASK_OPTIONS},
    )


def ark_flask(app: Any = None, **options: Any) -> ArkFlask:
    """The friendlier constructor, for applications configured in Python rather than from a file."""
    return ArkFlask(app, **options)


def add_ark_oidc_api(app: Any = None, prefix: str = "", **options: Any) -> ArkBearer:
    """
    Adds JWT bearer validation for API endpoints, with signing keys taken from the provider's JWKS
    document rather than a statically configured public key.
    """
    bearer = ArkBearer(**options)
    if app is not None:
        bearer.protect(app, prefix)
    return bearer


def ark_bearer(**options: Any) -> ArkBearer:
    """An :class:`ArkBearer` to use as a decorator, without registering it on an app."""
    return ArkBearer(**options)


def use_ark_account_endpoints(app: Any) -> Any:
    """
    Serves the access-denied page and the switch-user / sign-out posts.

    Idempotent: ``add_ark_oidc_client`` already registers them when
    ``account_switch.auto_register_endpoints`` is on, and calling this again is a no-op rather than
    a second copy.
    """
    ark = app.extensions.get(_EXTENSION_KEY) if hasattr(app, "extensions") else None
    if ark is None:
        raise ArkConfigError(
            "use_ark_account_endpoints(app) needs add_ark_oidc_client(app) to have run first."
        )
    if ark.switch and ark.switch.enabled:
        ark.switch.auto_register_endpoints = True
    return app


# -- token accessors, mirroring ArkTokenAccessors ---------------------------


def get_ark_access_token() -> Optional[str]:
    """The caller's access token, refreshed first if it is about to expire."""
    return _current().access_token()


def get_ark_id_token() -> Optional[str]:
    return _current().id_token


def get_ark_refresh_token() -> Optional[str]:
    tokens = _current().tokens
    return tokens.refresh_token if tokens else None


def with_ark_token(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Attaches the caller's access token to an outgoing request to a downstream API."""
    return _current().authorize(headers)


# -- account operations, mirroring ArkAccountExtensions ---------------------


def _extension() -> ArkFlask:
    from flask import current_app

    ark = getattr(current_app, "extensions", {}).get(_EXTENSION_KEY)
    if ark is None:
        raise ArkConfigError(
            "Ark authentication is not registered on this application — call "
            "add_ark_oidc_client(app) during setup."
        )
    return ark


def ark_switch_user(return_url: Optional[str] = None, login_hint: Optional[str] = None):
    """Abandons the current account and asks the provider for its sign-in form."""
    return _extension().switch_user(return_url, login_hint)


def ark_sign_out_everywhere(return_url: Optional[str] = None):
    """Ends this application's session and the provider's."""
    return _extension().sign_out_everywhere(return_url)


def ark_sign_out_locally(return_url: Optional[str] = None):
    """Ends this application's session only, leaving the provider session intact."""
    return _extension().sign_out_locally(return_url)


def ark_denied_account() -> Optional[ArkDeniedAccount]:
    """The account that was refused, for a host rendering its own access-denied page."""
    return _extension().denied_account()


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------

_ARKFLASK_OPTIONS = {
    "client",
    "secret",
    "store",
    "cookie_name",
    "cookie_secure",
    "cookie_samesite",
    "cookie_domain",
    "session_ttl_seconds",
    "refresh_leeway_seconds",
    "fetch_user_info",
    "return_to_param",
    "default_return_to",
    "trust_proxy",
    "service_token",
}

#: Keys that belong to ArkOAuthClient rather than to ArkAuthConfig.
_CLIENT_ONLY_OPTIONS = {
    "token_endpoint_auth_method",
    "private_key_jwt",
    "post_logout_redirect_uri",
    "response_mode",
    "use_par",
    "prompt",
    "acr_values",
    "extra_authorization_params",
    "clock_tolerance_seconds",
    "require_token_hashes",
    "id_token_signing_algorithms",
    "timeout",
    "metadata_ttl",
    "jwks_ttl",
    "jwks_min_refresh_interval",
    "transport",
    "audience",
}


def _as_auth_config(config: Any, options: Mapping[str, Any]) -> ArkAuthConfig:
    """Accepts an ArkAuthConfig, a mapping in either spelling, or bare keyword arguments."""
    if isinstance(config, ArkAuthConfig):
        return config
    if config is not None:
        return ArkAuthConfig.from_mapping(config)
    bare = {
        k: v
        for k, v in options.items()
        if k not in _ARKFLASK_OPTIONS and k not in _CLIENT_ONLY_OPTIONS
    }
    return ArkAuthConfig.from_mapping(bare)


def _build_client(config: ArkAuthConfig, options: Mapping[str, Any]) -> ArkOAuthClient:
    """Builds the protocol client from the bound ``ark_oauth_client`` section."""
    passthrough = {k: v for k, v in options.items() if k in _CLIENT_ONLY_OPTIONS}
    return ArkOAuthClient(
        authority=config.resolve_authority(),
        client_id=config.client_id,
        client_secret=config.client_secret or None,
        scopes=config.resolve_scopes(),
        # The redirect URI is derived per request from this application's own origin, exactly as
        # the .NET handler builds it from CallbackPath.
        redirect_uri=passthrough.pop("redirect_uri", None),
        require_https=config.require_https_metadata,
        role_claim=config.resolve_role_claim_type(),
        **passthrough,
    )


def _same_path(path: str, configured: Optional[str]) -> bool:
    return bool(configured) and path.rstrip("/").lower() == str(configured).rstrip("/").lower()


def _prune_transactions(transactions: Dict[str, Any]) -> Dict[str, Any]:
    """Prunes expired and surplus login transactions, so a bot hitting /login cannot grow a session forever."""
    now = int(time.time())
    live = [
        (state, tx)
        for state, tx in transactions.items()
        if now - int(tx.get("created_at") or 0) < TRANSACTION_TTL_SECONDS
    ]
    live.sort(key=lambda item: int(item[1].get("created_at") or 0), reverse=True)
    return dict(live[:MAX_CONCURRENT_TRANSACTIONS])


def _challenge(status: int, error: str, description: str):
    from flask import jsonify

    response = jsonify({"error": error, "error_description": description})
    response.status_code = status
    response.headers["WWW-Authenticate"] = (
        f'Bearer realm="ark", error="{error}", error_description="{description.replace(chr(34), chr(39))}"'
    )
    return response


def _current_or_none() -> Optional[ArkRequest]:
    from flask import g

    return getattr(g, "ark", None)


def _flatten(values: Sequence[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        if isinstance(value, (list, tuple, set)):
            out.extend(_flatten(list(value)))
        elif value is not None:
            out.append(str(value))
    return out
