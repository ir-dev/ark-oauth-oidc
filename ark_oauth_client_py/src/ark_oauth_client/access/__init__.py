"""
Account switching on a shared browser, and the access-denied page that makes it recoverable.

Mirrors the ``Access/`` folder of the .NET client: the options, the entitlement gate, the encrypted
denial cookie, the built-in page and the guards its two POST endpoints need. The endpoints are
served by :mod:`ark_oauth_client.flask`.
"""

from .denied_page import ArkAccessDeniedPage, ArkSignOutPage
from .endpoints import check_same_origin, is_cross_site, local_or_default, read_field
from .gate import ArkAccessGate
from .options import (
    ArkAccessDeniedContext,
    ArkAccessDeniedReasons,
    ArkAccessEvaluationContext,
    ArkAccountSwitchOptions,
    ArkChallengeProperties,
    ArkClientEvents,
    ArkClientOptions,
    ArkDeniedAccount,
)
from .state import ArkAccessDeniedState

__all__ = [
    "ArkAccessDeniedContext",
    "ArkAccessDeniedPage",
    "ArkAccessDeniedReasons",
    "ArkAccessDeniedState",
    "ArkAccessEvaluationContext",
    "ArkAccessGate",
    "ArkAccountSwitchOptions",
    "ArkChallengeProperties",
    "ArkClientEvents",
    "ArkClientOptions",
    "ArkDeniedAccount",
    "ArkSignOutPage",
    "check_same_origin",
    "is_cross_site",
    "local_or_default",
    "read_field",
]
