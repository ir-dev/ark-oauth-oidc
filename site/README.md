# site/ — the project home page

Published to <https://ir-dev.github.io/ark-oauth-oidc/> by `.github/workflows/pages.yml` on every push to
`main` that touches this folder. It is plain HTML with no build step: edit `index.html` and push.

One-time setup: **Settings → Pages → Source = GitHub Actions**.

Keep it in step with the root `README.md` when a fact on it changes (supported specs, endpoints, the
quickstart snippets, the governance API). Package versions are read live from NuGet, PyPI and npm, so a
release needs no edit.

| File | What it is |
|---|---|
| `index.html` | The page: setup wizard, onboarding, governance, quickstart, AI agents, standards, PKCE builder, brand marks |
| `security/YYYY-MM-DD-security-review.html` | One self-contained page per security review, linked (newest first) from the **Security reviews** section of `index.html`, where each opens in a new tab. A new review is a new file plus one `<li class="card review">` entry. Advisory level only: what was wrong, its impact, the fix and what operators must do. No reproduction steps, since this site is public. Publish only once the fixes are released and deployed |
| `webhooks.html` | The webhooks developer guide, linked from the home page's nav and its **Webhooks** section: a ten-minute quick start with a RequestBin URL, an in-browser signature checker, receivers in Python, Node and .NET, the console tour, failure experiments against httpbin.org, and management-API recipes. It restates facts from `Ark.oAuth.Oidc/Ark.oAuth.Oidc/WEBHOOKS.md`, so keep the two in step. The checker's sample request is signed with a demo secret made for the page, and it must still verify after any edit (**Load a sample** → *Signature valid*). The "new in 2.4.1" pills (here and on `index.html`) can go once a later release has shipped |
| `performance/YYYY-MM-DD-scale-test.html` | One self-contained page per load test, linked from the same **Reviews and reports** list as the security reviews, newest first, with its date. A new test is a new file plus one `<li class="card review">` entry. It is the team's source of truth for sizing and for choosing a database and topology, so it states the exact hardware, operating system, software versions, network path, power state and every provider and database setting; the method; before and after from the same test; what was not tested; and never a number that was not measured |
| `performance/YYYY-MM-DD-data/` | The raw result files behind that report's tables, as the load generator (`scripts/loadtest`) wrote them, linked from the report's **Raw results** section |
| `llms.txt` | The machine-readable digest for coding agents ([llmstxt.org](https://llmstxt.org) format). Update it with the README's §4 context block |
| `assets/img/` | Web-sized copies of the brand images in `Ark.oAuth.Oidc/Ark.oAuth.Oidc.Host/wwwroot/img`. The root `README.md` uses them too |
| `assets/favicon.png`, `assets/apple-touch-icon.png` | Made from `assets/img/ark-shield-512.png` |

The originals stay in `wwwroot/img`. When one changes, re-export the web copy here at the display size
(the largest is 1600 px wide) rather than linking the original, which can be several megabytes.
Tenant logos (`tenant-*.png`) are fictional examples.

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
