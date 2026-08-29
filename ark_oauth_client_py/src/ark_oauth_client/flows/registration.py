"""
Dynamic client registration (RFC 7591) and registration management (RFC 7592).

Registration is how a client stops being something a human types into an admin console: the
application posts its own metadata — redirect URIs, grant types, scopes — and the provider answers
with a client_id, optionally a client_secret, and a ``registration_access_token`` that is the only
credential able to read or delete that registration afterwards.

Two consequences are easy to miss and expensive to discover later:

* The **registration access token is shown once**. Lose it and the registration can only be cleaned
  up by an operator with database access.
* Registration is **not authentication**. A newly registered client can ask for tokens, but on Ark
  a user still has to be mapped to it before anyone can sign in.

The endpoint comes from the provider's discovery document. Its absence there is the provider saying
dynamic registration is switched off — which this class reports rather than guessing at a URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from ..diagnostics import ArkJson
from ..http import request as http_request
from ..probe import ArkSetupProbe

__all__ = ["ArkRegistration", "ArkRegistrationResult"]


@dataclass
class ArkRegistrationResult:
    """The result of a registration call, including the credentials shown only once."""

    endpoint: str = ""
    status_code: int = 0

    client_id: Optional[str] = None
    client_name: Optional[str] = None

    #: Returned once, for confidential clients. Store it now or regenerate it later.
    client_secret: Optional[str] = None

    #: Returned once. It is the only credential that can read, update or delete this registration
    #: afterwards — it is not the client's access token and cannot be re-derived.
    registration_access_token: Optional[str] = None

    registration_client_uri: Optional[str] = None

    error: Optional[str] = None
    error_description: Optional[str] = None

    request_body: Optional[str] = None
    raw_response: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return not self.error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "client_secret": self.client_secret,
            "registration_access_token": self.registration_access_token,
            "registration_client_uri": self.registration_client_uri,
            "error": self.error,
            "error_description": self.error_description,
            "request_body": self.request_body,
            "raw_response": self.raw_response,
            "succeeded": self.succeeded,
        }


class ArkRegistration:
    """Register, read and delete a client at the provider's registration endpoint."""

    def __init__(self, probe: ArkSetupProbe, **http: Any) -> None:
        self._probe = probe
        self._http = http or {"timeout": 15.0}

    def register(
        self,
        metadata: Mapping[str, Any],
        initial_access_token: Optional[str] = None,
        authority: Optional[str] = None,
    ) -> ArkRegistrationResult:
        """
        Registers a new client (RFC 7591 §3.1).

        ``metadata`` is the client metadata; ``redirect_uris`` is required for any grant that
        returns through a browser. ``initial_access_token`` authorises the registration — required
        unless the provider has been configured to accept open registration; on Ark it must carry
        the ``client.register`` scope, which is what the client_credentials grant is for.
        """
        return self._send("POST", lambda endpoint: endpoint, initial_access_token, metadata, authority)

    def read(
        self,
        client_id: str,
        registration_access_token: str,
        authority: Optional[str] = None,
    ) -> ArkRegistrationResult:
        """Reads a registration back (RFC 7592 §2.1), using its registration access token."""
        return self._send(
            "GET",
            lambda endpoint: f"{endpoint.rstrip('/')}/{client_id}",
            registration_access_token,
            None,
            authority,
        )

    def delete(
        self,
        client_id: str,
        registration_access_token: str,
        authority: Optional[str] = None,
    ) -> ArkRegistrationResult:
        """Deletes a registration (RFC 7592 §2.3). The client stops existing immediately."""
        return self._send(
            "DELETE",
            lambda endpoint: f"{endpoint.rstrip('/')}/{client_id}",
            registration_access_token,
            None,
            authority,
        )

    # ------------------------------------------------------------------

    def _send(
        self,
        method: str,
        url: Any,
        bearer_token: Optional[str],
        body: Optional[Mapping[str, Any]],
        authority: Optional[str],
    ) -> ArkRegistrationResult:
        result = ArkRegistrationResult()

        try:
            metadata = self._probe.read_metadata(authority)
            if not metadata.registration_endpoint:
                result.error = "registration_not_supported"
                result.error_description = (
                    "the provider does not advertise a registration_endpoint, which means dynamic "
                    "registration is disabled. Set ark_oauth_server:Oidc:EnableDynamicRegistration."
                )
                return result

            result.endpoint = url(metadata.registration_endpoint)
            result.request_body = None if body is None else ArkJson.prettify(json.dumps(dict(body)))

            headers: Dict[str, str] = {}
            if bearer_token:
                headers["Authorization"] = f"Bearer {bearer_token}"

            response = http_request(
                result.endpoint,
                method=method,
                json_body=dict(body) if body is not None else None,
                headers=headers,
                **self._http,
            )
            result.status_code = response.status
            result.raw_response = ArkJson.prettify(response.text)

            payload = response.body
            if not isinstance(payload, dict):
                # 204 from a delete: no body is the successful answer.
                return result

            result.client_id = _text(payload, "client_id")
            result.client_secret = _text(payload, "client_secret")
            result.registration_access_token = _text(payload, "registration_access_token")
            result.registration_client_uri = _text(payload, "registration_client_uri")
            result.client_name = _text(payload, "client_name")
        except Exception as error:
            result.status_code = getattr(error, "status", 0) or 0
            body_payload = getattr(error, "body", None)
            if body_payload is not None:
                result.raw_response = ArkJson.prettify(
                    body_payload if isinstance(body_payload, str) else json.dumps(body_payload)
                )
            result.error = getattr(error, "error", None) or "request_failed"
            result.error_description = getattr(error, "error_description", None) or str(error)

        return result


def _text(payload: Mapping[str, Any], name: str) -> Optional[str]:
    value = payload.get(name)
    return value if isinstance(value, str) else None
