"""
The built-in dead end.

Self-contained HTML with inlined styles and no script: it has to render in an application that has
no template directory, no static files and a strict Content-Security-Policy, and it is the one page
a stuck user sees, so it cannot itself depend on anything.

Replace it by pointing ``access_denied_path`` at your own route and setting ``serve_default_page``
to false; ``ark_denied_account()`` gives your page the same information, and the two POST endpoints
keep working.
"""

from __future__ import annotations

from html import escape
from typing import Optional

from .endpoints import local_or_default
from .options import ArkAccountSwitchOptions

__all__ = ["ArkAccessDeniedPage"]

_STYLE = (
    ":root{--bg:#f7f7f8;--surface:#fff;--border:#e2e2e6;--fg:#17171a;--muted:#6a6a73;"
    "--accent:#4f46e5;--accent-fg:#fff}"
    "@media(prefers-color-scheme:dark){:root{--bg:#111114;--surface:#1a1a1f;--border:#313139;"
    "--fg:#ececf1;--muted:#9a9aa5;--accent:#8b85ff;--accent-fg:#16161c}}"
    "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;"
    "justify-content:center;padding:24px;background:var(--bg);color:var(--fg);"
    'font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}'
    ".card{width:100%;max-width:480px;background:var(--surface);border:1px solid var(--border);"
    "border-radius:12px;padding:28px}"
    "h1{margin:0 0 10px;font-size:19px;font-weight:640}p{margin:0 0 14px;color:var(--muted)}"
    "p.lede{color:var(--fg)}"
    "form{margin:0}.actions{display:flex;flex-direction:column;gap:10px;margin-top:20px}"
    "button{width:100%;padding:11px 14px;border-radius:8px;border:1px solid var(--accent);"
    "background:var(--accent);color:var(--accent-fg);font:inherit;font-weight:560;cursor:pointer}"
    "button.secondary{background:transparent;color:var(--fg);border-color:var(--border)}"
    ".foot{margin-top:18px;padding-top:14px;border-top:1px solid var(--border);font-size:13px;"
    "color:var(--muted)}.foot a{color:var(--accent)}"
    ".ver{margin:18px 0 0;padding-top:14px;border-top:1px solid var(--border);font-size:12px;"
    "color:var(--muted);text-align:center}"
    # One rule above the fold, not two: when the support line is drawn it already carries the
    # separator, so the version tucks under it instead of ruling the card twice.
    ".foot+.ver{margin-top:8px;padding-top:0;border-top:0}"
)


class ArkAccessDeniedPage:
    """Renders the page. Returns HTML; the caller decides the status and the headers."""

    @staticmethod
    def build(
        options: ArkAccountSwitchOptions,
        app: Optional[str],
        account: Optional[str],
        return_url: str,
    ) -> str:
        app_name = escape(app.strip() if app and app.strip() else "this application")
        target = escape(return_url)
        home = escape(local_or_default(options.home_path, "/"))

        lede = (
            f"The account you are signed in with does not have access to {app_name}."
            if account is None
            else (
                f"You are signed in as <strong>{escape(account)}</strong>, and that account does "
                f"not have access to {app_name}."
            )
        )

        parts = [
            '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>No access — {app_name}</title><style>{_STYLE}</style></head>",
            '<body><main class="card">',
            f"<h1>You do not have access to {app_name}</h1>",
            f'<p class="lede">{lede}</p>',
            "<p>If somebody else was using this browser, their sign-in is still active and it is "
            f"the one being offered to {app_name}. Choose “Sign in as a different user” "
            "to enter your own credentials.</p>",
            '<div class="actions">',
            f'<form method="post" action="{escape(options.switch_user_path)}">',
            f'<input type="hidden" name="returnUrl" value="{target}">',
            '<button type="submit">Sign in as a different user</button></form>',
        ]

        if options.allow_full_sign_out:
            parts += [
                f'<form method="post" action="{escape(options.sign_out_path)}">',
                f'<input type="hidden" name="returnUrl" value="{home}">',
                '<button class="secondary" type="submit">Sign out completely</button></form>',
            ]

        parts.append("</div>")

        if options.support_url or options.support_email:
            parts.append(f'<p class="foot">Need access to {app_name}? ')
            if options.support_url:
                parts.append(f'<a href="{escape(options.support_url)}">Request it here</a>')
            else:
                address = escape(options.support_email or "")
                parts.append(f'<a href="mailto:{address}">{address}</a>')
            parts.append("</p>")

        # Which client library drew this page. It is the one screen a stuck user is looking at
        # while somebody tries to work out why the account is wrong, and the version is otherwise
        # a `pip show` on a host they cannot reach.
        #
        # Imported here rather than at module scope because the package __init__ imports this
        # module on its way to defining __version__ — at module scope the name does not exist
        # yet. By the time anything renders a page, it does.
        from .. import __version__

        parts.append(f'<p class="ver">ark-oauth-client {escape(__version__)}</p>')

        parts.append("</main></body></html>")
        return "".join(parts)
