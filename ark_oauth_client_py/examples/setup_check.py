"""
Checking the setup — run it in CI, or render it on a health page.

    ARK_AUTHORITY=... ARK_CLIENT_ID=... python examples/setup_check.py

Pairs local configuration with the provider's live metadata and reports what does not line up: a
wrong port, a stopped provider, an issuer mismatch, a scope this client is not registered for, an
authentication method the tenant does not offer. Without it, the first symptom of any of these is
`invalid_request` on a page a user is looking at.

Exits non-zero when something is wrong, so it fails a pipeline rather than a sign-in.
"""

import sys

from ark_oauth_client import ArkAuthConfig, ArkOAuthClient, ArkSetupProbe

from config import ORIGIN, REQUIRE_HTTPS, client_config


def main():
    config = ArkAuthConfig.from_mapping(client_config())

    # The renderable view: everything an operator needs to check a registration.
    model = ArkSetupProbe(config).probe(origin=ORIGIN)
    print(f"authority          : {model.authority}")
    print(f"client_id          : {model.client_id}")
    print(f"redirect_uri       : {model.redirect_uri}   <- register this exactly")
    print(f"post_logout_uri    : {model.post_logout_redirect_uri}")
    print(f"discovery          : {'ok' if model.discovery_ok else model.discovery_error}")

    if model.discovery_ok:
        print(f"issuer             : {model.issuer}")
        print(f"issuer mismatch    : {model.issuer_mismatch}")
        print(f"dynamic reg.       : {model.supports_dynamic_registration}")
        print(f"client credentials : {model.supports_client_credentials}")
        print(f"admin console      : {model.admin_console_url}")
        print(f"integration page   : {model.integration_page_url}")
        if model.unsupported_scopes:
            print(f"unpublished scopes : {', '.join(model.unsupported_scopes)}")

    # The protocol client's own report adds the problems as sentences.
    client = ArkOAuthClient(
        authority=config.resolve_authority(),
        client_id=config.client_id,
        client_secret=config.client_secret or None,
        require_https=REQUIRE_HTTPS,
    )
    report = client.check_setup(origin=ORIGIN)

    if report["problems"]:
        print("\nProblems:")
        for problem in report["problems"]:
            print(f"  - {problem}")
        sys.exit(1)

    print("\nNo problems found.")


if __name__ == "__main__":
    main()
