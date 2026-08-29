"""
The client credentials grant — a service authenticating as itself, with no user involved.

    ARK_AUTHORITY=... ARK_CLIENT_ID=my-service ARK_CLIENT_SECRET=... python examples/client_credentials.py

Never use the resulting token to act on behalf of a signed-in user: it carries the service's
authority rather than theirs, and nothing downstream can tell the difference.
"""

import sys

from ark_oauth_client import ArkOAuthClient

from config import AUTHORITY, CLIENT_ID, CLIENT_SECRET, REQUIRE_HTTPS


def main():
    if not CLIENT_SECRET:
        sys.exit("set ARK_CLIENT_SECRET — a public client cannot use this grant.")

    client = ArkOAuthClient(
        authority=AUTHORITY,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        require_https=REQUIRE_HTTPS,
    )

    tokens = client.client_credentials(scopes=["reports.read"])
    print(f"access token : {tokens.access_token[:32]}...")
    print(f"expires in   : {tokens.expires_in()}s")
    print(f"scopes       : {', '.join(tokens.scopes()) or '(none granted)'}")

    # Cached until shortly before expiry: asking again costs nothing.
    again = client.client_credentials(scopes=["reports.read"])
    print(f"cached       : {again is tokens}")


if __name__ == "__main__":
    main()
