"""
Account switching, and the page a user lands on when they are signed in as somebody who cannot use
this application.

The problem it solves is a shared browser. Single sign-on is a browser-wide session: once one
person signs in to client-a, the identity provider's session cookie answers for every other tab.
When a second person opens client-b, the authorize request is satisfied silently by the first
person's session, client-b receives a perfectly valid token for an account that has no mapping to
client-b, and the second person is shown "you do not have access to this application" for an account
that is not even theirs. Nothing on that page helps, because the sign-in link goes back to the same
silent session and returns the same answer — the loop only ends when somebody knows to clear
cookies.

Breaking that loop needs two things, and both live here:

* A dead end that is honest about whose session it is. The user is told which account is signed in,
  and given a button rather than a link, because the way out is an action.
* A challenge that says ``prompt=login``. That is the one parameter the provider must honour by
  ignoring the existing session and drawing the sign-in form (OIDC Core §3.1.2.1), which is what
  lets the second person enter their own credentials.

Everything is opt-in and overridable: paths, wording, whether the previous account is named, whether
switching also ends the provider session, and — for hosts that want their own page — events that
take the whole thing over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

__all__ = [
    "ArkAccountSwitchOptions",
    "ArkAccessDeniedReasons",
    "ArkAccessDeniedContext",
    "ArkAccessEvaluationContext",
    "ArkClientEvents",
    "ArkClientOptions",
    "ArkChallengeProperties",
    "ArkDeniedAccount",
]


@dataclass
class ArkAccountSwitchOptions:
    """Paths, wording and behaviour for the shared-browser case."""

    #: Serve the endpoints below. Off leaves the helper functions usable from your own views.
    enabled: bool = True

    #: Put the endpoints into the application automatically, so an existing app factory needs no
    #: edit. Turn it off to register them yourself with ``use_ark_account_endpoints()`` — behind a
    #: proxy fix or an HTTPS redirect, for instance.
    auto_register_endpoints: bool = True

    #: Refuse the sign-in when the provider issues no ``ark_claims`` for this client.
    #:
    #: This is the check that turns the shared-browser case into something recoverable. Left off
    #: (the default, so an upgrade changes no behaviour) the wrong account is signed in and every
    #: protected page answers 403. Turned on, the callback is stopped before the cookie is written
    #: — the wrong person never gets a session here at all — and the user is sent to
    #: :attr:`access_denied_path` where they can switch accounts.
    require_ark_claims: bool = False

    #: Narrow the check further: the user must carry at least one of these claim values. Empty
    #: means any ``ark_claims`` value will do. Ignored unless :attr:`require_ark_claims` is set.
    required_claims: Optional[List[str]] = None

    #: Where a denied user lands. Point it at your own view to take the UI over.
    access_denied_path: str = "/ark/no-access"

    #: Accepts the POST that abandons the current account and asks for the sign-in form.
    switch_user_path: str = "/ark/switch-user"

    #: Accepts the POST that ends this application's session and the provider's.
    sign_out_path: str = "/ark/sign-out"

    #: Render the built-in access-denied page at :attr:`access_denied_path`. Set false when that
    #: path is one of your own routes — the library then leaves the request alone.
    serve_default_page: bool = True

    #: Name of this application as the user knows it. Defaults to the client id.
    app_display_name: Optional[str] = None

    #: Show which account is currently signed in. On a shared browser that is somebody else's
    #: address; it is what makes the page make sense, but a deployment that would rather not print
    #: it can turn it off and still get the button.
    show_signed_in_account: bool = True

    #: Offer "sign out completely" alongside "sign in as a different user".
    allow_full_sign_out: bool = True

    #: Make switching a full RP-initiated logout instead of a re-prompt.
    #:
    #: Off (the default) the switch is local: this application drops its cookie and challenges with
    #: ``prompt=login``, so the person at the keyboard signs in as themselves while the other
    #: applications the previous user has open are left alone. On, the provider session is ended
    #: too, which signs the previous user out of everything — correct for a kiosk or a shared
    #: terminal, heavy-handed for a laptop.
    end_provider_session_on_switch: bool = False

    #: Sent as the ``prompt`` parameter when switching. ``login`` is the one every provider honours.
    prompt: str = "login"

    #: Where "back to safety" goes, and the fallback for an absent or non-local return URL.
    home_path: str = "/"

    #: Optional "who can give me access" link on the page.
    support_url: Optional[str] = None

    #: Optional support address on the page.
    support_email: Optional[str] = None


class ArkAccessDeniedReasons:
    """Why a user was sent to the access-denied page."""

    #: The provider authenticated them, but they hold no authorization claims for this client.
    NO_APP_ACCESS = "no_app_access"

    #: They are signed in here, but an authorization rule refused the page they asked for.
    FORBIDDEN = "forbidden"


@dataclass
class ArkDeniedAccount:
    """The account that was refused, as recorded when the denial happened."""

    subject: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    reason: Optional[str] = None
    return_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "email": self.email,
            "name": self.name,
            "reason": self.reason,
            "return_url": self.return_url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ArkDeniedAccount":
        return cls(
            subject=data.get("subject"),
            email=data.get("email"),
            name=data.get("name"),
            reason=data.get("reason"),
            return_url=data.get("return_url"),
        )


@dataclass
class ArkAccessEvaluationContext:
    """The decision the library is about to make about a completed sign-in."""

    claims: Dict[str, Any] = field(default_factory=dict)
    ark_claims: Sequence[str] = ()

    #: What the configured rules concluded, before your handler ran.
    allowed_by_configuration: bool = True

    #: The token set from the sign-in, for a rule that needs the access token itself.
    tokens: Any = None


@dataclass
class ArkAccessDeniedContext:
    """What the library knows about a denial. Handed to :attr:`ArkClientEvents.on_access_denied`."""

    #: One of :class:`ArkAccessDeniedReasons`.
    reason: str = ArkAccessDeniedReasons.NO_APP_ACCESS

    subject: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None

    #: The authorization claims the provider did issue — empty in the usual case.
    ark_claims: Sequence[str] = ()

    #: Where the user was trying to go, when that is known.
    return_url: Optional[str] = None

    #: Set from the handler to keep the library from redirecting — you have written the response
    #: yourself. When you return a response object from the handler this is set for you.
    handled: bool = False

    #: The response your handler wants sent instead of the redirect.
    response: Any = None


@dataclass
class ArkClientEvents:
    """Hooks for hosts that need more than configuration. All are optional."""

    #: Decide entitlement yourself — a group claim, a licence lookup, a row in your own database.
    #: Return true to let the sign-in complete. Runs only when
    #: :attr:`ArkAccountSwitchOptions.require_ark_claims` is on, or when this handler is the only
    #: rule there is.
    on_evaluate_access: Optional[Callable[[ArkAccessEvaluationContext], bool]] = None

    #: Called before the user is redirected to the access-denied page. Log it, raise a
    #: request-access ticket, or return a response of your own to render it instead.
    on_access_denied: Optional[Callable[[ArkAccessDeniedContext], Any]] = None


@dataclass
class ArkClientOptions:
    """Passed to the ``add_ark_oidc_client(app, config, configure=...)`` overload."""

    config: Any
    events: ArkClientEvents = field(default_factory=ArkClientEvents)


class ArkChallengeProperties:
    """
    The authorization-request parameters that make "sign in as a different user" work.

    Without ``prompt=login`` the provider answers the challenge from the session it already has, and
    the wrong person is signed in again. These helpers build the keyword arguments that
    ``create_authorization_url`` and the Flask ``login()`` helper accept.
    """

    PROMPT_ITEM = "ark:prompt"
    LOGIN_HINT_ITEM = "ark:login_hint"
    MAX_AGE_ITEM = "ark:max_age"

    @staticmethod
    def switch_user(
        return_url: Optional[str] = None,
        login_hint: Optional[str] = None,
        prompt: str = "login",
    ) -> Dict[str, Any]:
        """
        A challenge that refuses to be answered by the existing session: ``prompt=login`` makes the
        provider draw the sign-in form even though its cookie is still valid.
        """
        properties: Dict[str, Any] = {
            "return_to": return_url or "/",
            "prompt": prompt or "login",
        }
        if login_hint:
            properties["login_hint"] = login_hint
        return properties

    @staticmethod
    def select_account(return_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Asks the provider for its account picker. Providers that do not implement one fall back to
        their sign-in form, so this is only preferable where you know the picker exists.
        """
        return ArkChallengeProperties.switch_user(return_url, None, "select_account")

    @staticmethod
    def with_ark_prompt(properties: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        properties["prompt"] = prompt
        return properties

    @staticmethod
    def with_ark_login_hint(properties: Dict[str, Any], login_hint: str) -> Dict[str, Any]:
        properties["login_hint"] = login_hint
        return properties

    @staticmethod
    def with_ark_max_age(properties: Dict[str, Any], seconds: int) -> Dict[str, Any]:
        """
        Adds ``max_age``. Zero is a second way of saying "authenticate again now", useful against a
        provider that ignores ``prompt``.
        """
        properties["max_age"] = seconds
        return properties
