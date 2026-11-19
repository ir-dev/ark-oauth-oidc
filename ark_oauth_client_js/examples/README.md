# Examples

Each one is a complete app signing in against an Ark tenant with `ark-oauth-client-js`. They all
use the Ark default callback paths, so register these on a **public** client (auth method `none`,
grants `authorization_code` + `refresh_token`), byte for byte:

- redirect URI `http://127.0.0.1:5173/signin-oidc`
- post-logout redirect URI `http://127.0.0.1:5173/signout-callback-oidc`

Add `http://127.0.0.1:5173` to the provider's `ark_oauth_server:Oidc:CorsOrigins`, and map your user
to the client.

| Folder | What | Run |
|---|---|---|
| [`vanilla/`](vanilla) | Plain ES modules, no build step, under a strict CSP. Also a `<script src>` variant using the IIFE build. | `ARK_AUTHORITY=… ARK_CLIENT_ID=… node examples/serve.mjs` (add `EXAMPLE=script-tag` for the IIFE page, after `npm run build`) |
| [`react-vite/`](react-vite) | React 19 + React Router + Vite | `npm install && npm run dev` |
| [`nextjs/`](nextjs) | Next.js App Router, `ArkNextProvider`, prerendered pages | `npm install && npm run dev` |
| [`vue/`](vue) | Vue 3 + vue-router + Vite, plugin and route guard | `npm install && npm run dev` |
| [`angular/`](angular) | Angular standalone app: `provideArk`, signals, guards, interceptor | `npm install && npm start` |

Until `ark-oauth-client-js` is on npm, install it from this repository instead:
`npm install ../..` (or `npm pack` in the package folder and install the `.tgz`).

The vanilla example is the one the end-to-end run uses (`npm run e2e`, see `e2e/real-idp.mjs`).
The Next.js, React, Vue and Angular examples were built against the packed package (Vue with
`vue-tsc` under `strict`), and the Next.js one was also signed in through end to end against a
real Ark host.
