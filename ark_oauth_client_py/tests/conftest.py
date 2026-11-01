from __future__ import annotations

import pytest

from .stub_idp import StubIdp


@pytest.fixture(scope="module")
def idp():
    with StubIdp() as server:
        yield server


@pytest.fixture(autouse=True)
def _reset(idp):
    """Each test starts with an empty request log and the default user."""
    idp.requests.clear()
    idp.revoked.clear()
    idp.ark_claims = ["billing.admin", "reports.read"]
    idp.access_token_lifetime = 3600
    idp.user = {
        "sub": "alice@example.com",
        "name": "Alice Example",
        "email": "alice@example.com",
        "email_verified": True,
    }
    yield
