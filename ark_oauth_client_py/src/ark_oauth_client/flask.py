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

import logging
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
    ArkSignOutPage,
    check_same_origin,
    is_cross_site,
    local_or_default,
    read_field,
)
from .auth_config import ArkAuthConfig
from .client import ArkOAuthClient, AuthorizationRequest
from .context import ArkAuthContext
from .errors import ArkCallbackError, ArkConfigError, ArkOAuthError, ArkTokenError
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
from .tokens import TokenSet, agent_actors

# Silent unless the application configures logging; the best-effort calls below report here
# instead of disappearing.
_log = logging.getLogger(__name__)

__all__ = [
    "ArkFlask",
    "ArkBearer",
    "add_ark_oidc_client",
    "add_ark_oidc_api",
    "ark_flask",
    "ark_bearer",
    "add_ark_agent_api",
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

    def agent_token(self, audience: str, *, scopes: Sequence[str] = ()) -> Optional[str]:
        """
        An access token for calling the agent ``audience`` (its client_id) on behalf of the
        signed-in user — see :meth:`ArkOAuthClient.agent_token`. ``None`` when nobody is signed in.
        """
        subject_token = self.access_token()
        if not subject_token:
            return None
        return self.client.agent_token(
            audience, subject_token=subject_token, scopes=scopes
        ).access_token

    def has_claim(self, *wanted: str) -> bool:
        held = set(self.claims)
        return all(claim in held for claim in wanted)

    def has_scope(self, *wanted: str) -> bool:
        held = set(self.scopes)
        return all(scope in held for scope in wanted)

    def context(self) -> ArkAuthContext:
        """The :class:`~ark_oauth_client.context.ArkAuthContext` for this request."""
        return ArkAuthContext(
            self._ark.config,
            claims=self.user,
            ark_claims=self.claims,
            client_id=self._ark.config.client_id,
            ip=self._ark._client_ip(),
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
        # store needs a lock of its own. Each entry is the lock and how many requests hold or wait
        # for it. The guard covers that table, and the moment a session is written or destroyed.
        self._refresh_locks: Dict[str, List[Any]] = {}
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
            # Secure unless the caller passes cookie_secure=False, as the Node and .NET ports do
            # and as the README always said. This used to read SESSION_COOKIE_SECURE with a True
            # fallback, but Flask pre-populates that key as False, so the fallback never applied
            # and the session cookie went out on plain http by default. Browsers store a Secure
            # cookie for http://localhost, so local development is unaffected; pass
            # cookie_secure=False only for a plain-http host that is not localhost.
            self.cookie_secure = True

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
            return self._serve_logout()

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

    def _serve_logout(self):
        """
        Signs out from a link, a typed address or a form on this site, as it always has.

        A request another site started is asked about first. Taken at its word it ended the session
        here and, with the ``id_token_hint`` the redirect carries, the provider's session for every
        other application too, because somebody followed a link.
        """
        from flask import Response, request

        if is_cross_site(request.headers, self._origin()):
            if request.method == "POST":
                return Response("cross-site request rejected.", status=400, mimetype="text/plain")
            html = ArkSignOutPage.build(
                self.switch,
                self.switch.app_display_name or self.config.client_id,
                f"{request.script_root}{self.logout_path}",
            )
            response = Response(html, status=200, mimetype="text/html")
            response.headers["Cache-Control"] = "no-store, no-cache"
            response.headers["Pragma"] = "no-cache"
            response.headers["Content-Security-Policy"] = ArkSignOutPage.CSP
            response.headers["X-Frame-Options"] = "DENY"
            return response
        return self._end_session()

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
            # `stored` came out of this session, so it is never None here. The check is for the
            # type checker and, unlike an assert, it survives `python -O`.
            if session is not None:
                session["txs"].pop(state, None)
            response = self._fail(error)
            if session is not None:
                self._save_session(response, session_id, session)
            return response

        ark_claims = tokens.ark_claims()

        # The last point before the session cookie is written. Refusing here rather than at the
        # first protected page is the whole difference: the browser never ends up holding a session
        # for an account that cannot use this application.
        if not self._allowed(tokens.claims, ark_claims, tokens):
            if session is not None and session_id:
                session["txs"].pop(state, None)
                self._store_session(session_id, session)
            self._revoke_quietly(tokens)
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
            self._destroy_session(session_id)

        user: Dict[str, Any] = dict(tokens.claims or {})
        if self.fetch_user_info and tokens.access_token and tokens.has_scope("openid"):
            try:
                info = self.client.user_info(tokens.access_token)
                # OIDC Core §5.3.2: claims about anybody but the ID token's subject are not used.
                if info.get("sub") == tokens.subject:
                    user.update(info)
                else:
                    _log.warning("userinfo answered for another subject; its claims were not used")
            except Exception as error:
                # UserInfo is supplementary; the ID token already carries what the scopes unlocked.
                _log.debug("userinfo lookup failed; continuing with the ID token's claims: %s", error)

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
        self._revoke_quietly(tokens)

        target = local_or_default(return_to, self.config.signed_out_redirect_uri) or self.default_return_to
        try:
            target = self.client.end_session_url(
                id_token_hint=tokens.id_token if tokens else None,
                post_logout_redirect_uri=self.client.config.post_logout_redirect_uri
                or self._absolute(local_or_default(return_to, self.default_return_to)),
            )
        except Exception as error:
            # A tenant with no end_session_endpoint still gets a clean local sign-out.
            _log.debug("no provider sign-out URL; signing out locally only: %s", error)

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
        session_id, session = self._load_session()
        self._revoke_quietly(TokenSet.from_dict((session or {}).get("tokens")))
        if session_id:
            self._destroy_session(session_id)

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

        session_id, session = self._load_session()
        self._revoke_quietly(TokenSet.from_dict((session or {}).get("tokens")))
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

    def _store_session(self, session_id: str, data: Dict[str, Any]) -> int:
        """
        Writes a session and returns how long it is kept.

        One that holds nothing but sign-ins still under way is kept for as long as a sign-in may
        take. Kept for a signed-in session's eight hours, every visit to the login page by a caller
        that keeps no cookie was another entry in the store until the evening.
        """
        data["updated_at"] = int(time.time())
        ttl = self.session_ttl_seconds if data.get("tokens") else TRANSACTION_TTL_SECONDS
        self.store.set(session_id, data, ttl)
        return ttl

    def _save_session(
        self,
        response: Any,
        session_id: Optional[str],
        data: Dict[str, Any],
        *,
        replace_cookie: bool = False,
    ) -> str:
        new_id = session_id or create_session_id()
        ttl = self._store_session(new_id, data)
        # A sign-in under way moves its cookie along with it: a second one, started in another tab,
        # has its own ten minutes.
        if session_id is None or replace_cookie or not data.get("tokens"):
            response.set_cookie(
                self.cookie_name,
                sign_session_id(new_id, self._secret),
                max_age=ttl,
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
            self._destroy_session(session_id)
        if not keep_new_cookie:
            response.delete_cookie(
                self.cookie_name, domain=self.cookie_domain, path="/", samesite=self.cookie_samesite
            )

    def _destroy_session(self, session_id: str) -> None:
        # Under the guard, so that a refresh coming back at this very moment either wrote before
        # and is destroyed here, or finds the session gone and does not write it back to life.
        with self._refresh_guard:
            self.store.destroy(session_id)

    def _revoke_quietly(self, tokens: Optional[TokenSet]) -> None:
        """
        Revokes a session's refresh token at the provider. Without it, a session ended here leaves a
        live refresh token behind until it expires; revoking takes its whole rotation family down,
        which is what "sign out" is expected to mean.
        """
        if not tokens or not tokens.refresh_token:
            return
        try:
            # token_type_hint names the kind of token (RFC 7009), it is not a credential.
            self.client.revoke(tokens.refresh_token, token_type_hint="refresh_token")  # nosec B106
        except Exception as error:
            # Best effort: a provider that is down must not prevent a local sign-out. Logged,
            # because the refresh token then stays live at the provider until it expires.
            _log.warning("refresh token revocation at sign-out failed: %s", error)

    def _allowed(
        self,
        claims: Optional[Mapping[str, Any]],
        ark_claims: Sequence[str],
        tokens: TokenSet,
    ) -> bool:
        """Whether the account these tokens are for may use this application."""
        if not self.switch.require_ark_claims and self.events.on_evaluate_access is None:
            return True
        return ArkAccessGate.allowed(self.switch, self.events, claims, ark_claims, tokens=tokens)

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

        # Held until the answer is in the store, by everybody who asked. Given up any earlier, the
        # next request loads the tokens this one has just spent and presents them again.
        with self._refresh_guard:
            entry = self._refresh_locks.setdefault(session_id, [threading.Lock(), 0])
            entry[1] += 1
        try:
            with entry[0]:
                return self._refresh_session(session_id, session, tokens)
        finally:
            with self._refresh_guard:
                entry[1] -= 1
                if entry[1] == 0:
                    self._refresh_locks.pop(session_id, None)

    def _refresh_session(
        self, session_id: str, session: Dict[str, Any], tokens: TokenSet
    ) -> Optional[TokenSet]:
        """Runs one refresh. The answer is new tokens, the old ones, or ``None``: signed out."""
        # The store is the source of truth: another request may have refreshed while this one
        # waited, or signed out, and the copy loaded a moment ago knows of neither.
        stored = self.store.get(session_id)
        if stored is None:
            return self._signed_out(session_id)
        current = TokenSet.from_dict(stored.get("tokens")) or tokens
        if not current.expired(self.refresh_leeway_seconds) or not current.refresh_token:
            session.update(stored)
            return current

        try:
            refreshed = self.client.refresh(current.refresh_token, subject=stored.get("sub"))
        except ArkOAuthError as error:
            # invalid_grant means the refresh token is spent, revoked, or its session ended at
            # the provider. There is nothing to retry: the user has to sign in again.
            if error.error == "invalid_grant":
                return self._signed_out(session_id)
            # A transient failure must not sign the user out; the next request retries.
            return current
        except ArkTokenError as error:
            # The provider answered and the answer cannot be trusted, which no retry changes.
            _log.warning("a refreshed token set was refused; the session was ended: %s", error)
            self._revoke_quietly(current)
            return self._signed_out(session_id)
        except Exception:
            return current

        user = stored.get("user")
        # The ID token is reissued on refresh; keep the identity in step with it.
        if refreshed.claims:
            user = {**(user or {}), **refreshed.claims}
        # Not reissued by every provider; the last one still serves as id_token_hint at sign-out.
        refreshed.id_token = refreshed.id_token or current.id_token
        ark_claims = refreshed.ark_claims()

        # Asked again with the claims just issued. Asked only at the callback, an account that lost
        # its access kept the session it already had for as long as it could be refreshed.
        try:
            allowed = self._allowed(refreshed.claims or user, ark_claims, refreshed)
        except Exception as error:
            # An entitlement rule that cannot answer has not said yes. The sign-in that follows
            # asks it again, where the failure is seen.
            _log.warning("the access check failed on refresh; the session was ended: %s", error)
            allowed = False
        if not allowed:
            self._revoke_quietly(refreshed)
            return self._signed_out(session_id)

        refreshed.claims = refreshed.claims or current.claims
        with self._refresh_guard:
            # Signed out while the provider was answering: writing now would undo it.
            latest = self.store.get(session_id)
            if latest is not None:
                fresh = {
                    **latest,
                    "tokens": refreshed.to_dict(),
                    "user": user,
                    "ark_claims": ark_claims,
                }
                self._store_session(session_id, fresh)
        if latest is None:
            self._revoke_quietly(refreshed)
            return self._signed_out(session_id)
        session.update(fresh)
        return refreshed

    def _signed_out(self, session_id: str) -> None:
        """The session is over: gone from the store, and its cookie cleared with the response."""
        self._destroy_session(session_id)
        self._drop_cookie_after_request()

    # -- helpers -------------------------------------------------------

    def _origin(self) -> str:
        from flask import request

        if self.trust_proxy:
            proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
            host = (request.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
            if proto and host:
                # An origin used to build redirect URLs, never a response body.
                return f"{proto}://{host}{request.script_root}"  # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
        return f"{request.scheme}://{request.host}{request.script_root}"

    def _client_ip(self) -> Optional[str]:
        """
        The caller's address. Behind a proxy that is the last entry of ``X-Forwarded-For``, the one
        the proxy wrote itself; whatever stands before it arrived with the request and is what the
        caller typed. With ``trust_proxy`` off the header is not read at all.
        """
        from flask import request

        if self.trust_proxy:
            forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[-1].strip()
            if forwarded:
                return forwarded
        return request.remote_addr or None

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
        agent: bool = False,
        **client_options: Any,
    ) -> None:
        self.client = client or ArkOAuthClient(**client_options)
        self.scopes = list(scopes)
        self.claims = list(claims)
        # An agent (A2A) accepts only tokens addressed to it: the audience is its own client_id.
        self.audience = audience or (self.client.config.client_id if agent else None)
        self.optional = optional
        # Always on for an agent: its own ID tokens and logout tokens carry its audience too.
        self.require_type_header = require_type_header or agent

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
        #: Agents acting for ``sub`` (A2A), newest first; empty when the caller acts as itself.
        self.actors = agent_actors(payload)

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
        self.actors: List[str] = []

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


def add_ark_agent_api(app: Any = None, prefix: str = "", **options: Any) -> ArkBearer:
    """
    Protects an agent's endpoints (A2A): :func:`add_ark_oidc_api` that accepts only tokens
    addressed to this agent — ``aud`` is its own client_id — so a token another agent was given for
    somebody else is refused here. ``current_ark.actors`` names the agents acting for the caller.
    """
    return add_ark_oidc_api(app, prefix, agent=True, **options)


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


def _header_text(value: Any) -> str:
    """
    Makes text safe for a quoted-string in a header. A token's ``kid`` reaches error messages, and a
    CR or LF in one made the header refuse to be written: a 500, where the answer is a 401.
    """
    return "".join(
        "?" if not " " <= char <= "~" else "'" if char in '"\\' else char for char in str(value)
    )[:200]


def _challenge(status: int, error: str, description: str):
    from flask import jsonify

    text = _header_text(description)
    response = jsonify({"error": error, "error_description": text})
    response.status_code = status
    response.headers["WWW-Authenticate"] = (
        f'Bearer realm="ark", error="{error}", error_description="{text}"'
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
