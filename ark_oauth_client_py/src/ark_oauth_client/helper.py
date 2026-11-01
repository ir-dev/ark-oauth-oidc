"""
Onboarding calls against the Ark server's provisioning API.

These are not part of OAuth. They are the administrative half an application reaches for when it
creates its own tenants and users — a SaaS signing up a customer, an installer seeding the first
administrator — and they need a service token (``auth_service_tkn``) rather than a user's access
token.

The shape of the answers is the .NET client's: a dict with ``error`` and ``msg``, and "already
exists in tenant" treated as success, because provisioning has to be safe to run twice.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlencode

from .auth_config import ArkAuthConfig
from .http import get_json

__all__ = ["AuthClientHelper"]


class AuthClientHelper:
    """Wraps ``{auth_server_url}/api/oauth/onboard/…``."""

    def __init__(
        self,
        config: ArkAuthConfig,
        service_token: Optional[str] = None,
        **http: Any,
    ) -> None:
        self._config = config
        self._token = service_token
        self._http = http or {"timeout": 15.0}

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def onboard_user(
        self,
        user_email: str,
        password: str,
        user_claims: str,
        full_name: str,
    ) -> Dict[str, Any]:
        """Creates a user in this tenant and maps them to this client."""
        config = self._config
        if not config or not config.auth_server_url:
            return {"error": True, "msg": "user creation failed, auth config missing."}

        query = urlencode(
            {
                "ten_id": config.tenant_id,
                "client_id": config.client_id,
                "claim_keys": user_claims,
                "user_email": user_email,
                "user_pw": password,
                "full_name": full_name,
                "user_type": "user",
            }
        )
        url = f"{config.auth_server_url.rstrip('/')}/api/oauth/onboard/user?{query}"
        try:
            return self._interpret(get_json(url, headers=self._headers(), **self._http))
        except Exception as error:
            return {
                "error": True,
                "msg": "user creation failed, pls contact admin.",
                "data": str(error),
            }

    def onboard_customer(self, rel_url: str, full_url: str) -> Dict[str, Any]:
        """
        Runs a full onboarding call the caller has already built the URL for.

        The provisioning endpoint takes a dozen parameters that differ per product, so the .NET
        client takes the assembled URL rather than trying to model them; this does the same.
        """
        config = self._config
        if not config or not config.auth_server_url:
            return {
                "error": True,
                "msg": "customer creation failed, auth config missing.",
                "rel_url": rel_url,
                "f_url": full_url,
            }
        try:
            return self._interpret(get_json(full_url, headers=self._headers(), **self._http))
        except Exception as error:
            return {
                "error": True,
                "msg": "customer creation failed, pls contact admin.",
                "data": str(error),
                "rel_url": rel_url,
                "f_url": full_url,
            }

    # ------------------------------------------------------------------

    def _interpret(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        "Already exists in tenant" is success.

        Provisioning is called from installers and sign-up flows that get retried; treating an
        existing record as a failure turns a second run into a support ticket.
        """
        errored = payload.get("error")
        if errored is None or errored:
            message = str(payload.get("msg") or "").replace(" ", "").lower()
            marker = f"alreadyexistsintenant:{self._config.tenant_id}".lower()
            if marker not in message:
                return payload
        return {"error": False, "msg": "created succesfully"}
