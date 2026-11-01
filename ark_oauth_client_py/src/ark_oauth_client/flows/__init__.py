"""
The two flows that need no browser: the client credentials grant, and dynamic client registration.

Both are stateless over the discovery document, so they are safe to share, and both report the
exchange in full — request form, HTTP status and response body — so a failure can be read rather
than guessed at.
"""

from .client_credentials import ArkClientCredentials, ArkTokenResult
from .registration import ArkRegistration, ArkRegistrationResult

__all__ = [
    "ArkClientCredentials",
    "ArkTokenResult",
    "ArkRegistration",
    "ArkRegistrationResult",
]
