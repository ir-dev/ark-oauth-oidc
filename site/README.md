# site/ — the project home page

Published to <https://ir-dev.github.io/ark-oauth-oidc/> by `.github/workflows/pages.yml` on every push to
`main` that touches this folder. It is plain HTML with no build step: edit `index.html` and push.

One-time setup: **Settings → Pages → Source = GitHub Actions**.

Keep it in step with the root `README.md` when a fact on it changes (supported specs, endpoints, the
quickstart snippets). Package versions are read live from NuGet, PyPI and npm, so a release needs no edit.

## Can the identity provider itself run here, on SQLite?

No. GitHub Pages serves static files only: no .NET runtime, no server process, no writable disk. The
provider needs all three. It answers `/oauth2/token`, signs tokens with a private RSA key that must
never reach a browser, and writes to its database on every sign-in.

SQLite compiled to WebAssembly (sql.js, wa-sqlite) does run in a page, but each visitor gets their own
private copy. A provider built that way would be a different database per visitor, with its signing key
in the page source. It would not be a demo of ARK, just a demonstration of why ARK runs on a server.

What the page does instead is everything that works without a server. The **Try it** section builds a
real PKCE authorization request (`S256`, `state`, `nonce`) in the browser for any issuer.

To host a live instance, run `Ark.oAuth.Oidc.Host` (or any host using the NuGet package) on a real
server and link to it from the page. SQLite remains the default there:

* **Azure App Service (Linux container)**: the `aas-deploy` recipe. Put the database under `/home`,
  the only path that survives a restart, and run a **single instance**: SQLite does not tolerate
  several writers, and `/home` is a network share.
* **Fly.io / Railway / Render, or any VM**: mount a persistent volume and point
  `ConnectionStrings:ArkAuthConnection` at it, e.g. `Data Source=/data/ark_auth.db`.
* **More than one instance**: switch `Provider` to `postgres` or `mysql`. SQLite is the default for one box.

Whichever you choose, the administrator password comes from the environment
(`ark_oauth_server__AdminUser__Password`), never from a tracked file. This repository is public.
