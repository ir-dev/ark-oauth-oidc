"""
The device authorization grant (RFC 8628) — signing in on something with no browser.

    ARK_AUTHORITY=... ARK_CLIENT_ID=my-device ARK_CLIENT_SECRET=... python examples/device_flow.py

The device shows a code, the user approves it on their phone, and this process polls until they do.
"""

from ark_oauth_client import ArkOAuthClient

from config import AUTHORITY, CLIENT_ID, CLIENT_SECRET, REQUIRE_HTTPS


def main():
    client = ArkOAuthClient(
        authority=AUTHORITY,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        require_https=REQUIRE_HTTPS,
    )

    authorization = client.device_authorization(scopes=["openid", "profile", "offline_access"])

    print("To sign in, visit:")
    print(f"  {authorization.get('verification_uri_complete') or authorization['verification_uri']}")
    print(f"and enter the code: {authorization['user_code']}")
    print("\nWaiting for approval...")

    tokens = client.poll_device_token(
        authorization,
        on_pending=lambda error: print(f"  ... {error.error}"),
    )

    print(f"\nSigned in as {tokens.subject}")
    print(f"Authorization claims: {', '.join(tokens.ark_claims()) or '(none)'}")


if __name__ == "__main__":
    main()
