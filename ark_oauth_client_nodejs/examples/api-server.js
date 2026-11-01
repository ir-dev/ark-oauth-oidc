/**
 * An API protected by Ark access tokens.
 *
 *   node examples/api-server.js
 *   curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/me
 *
 * Verification is local, against the provider's cached JWKS, so a request costs no round trip to
 * the identity server. What it checks: the signature against a published key (following a key
 * rotation on its own), the issuer, the `at+jwt` type header that stops an ID token being
 * presented in an access token's place, the lifetime, and then the scopes and authorization
 * claims each route requires.
 */
import { createServer } from 'node:http';
import { arkBearer } from '../src/index.js';
import { authority } from './config.js';

const port = Number(process.env.API_PORT ?? 3001);

const bearer = arkBearer({
  authority,
  clientId: process.env.ARK_API_CLIENT_ID ?? 'my-api',
  // Set when the tenant issues an audience for this API and you want it enforced.
  audience: process.env.ARK_API_AUDIENCE ?? undefined,
  // Every request through this middleware must carry these:
  scopes: [],
  claims: []
});

const routes = {
  '/me': (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify(
        {
          sub: req.ark.sub,
          client_id: req.ark.clientId,
          scopes: req.ark.scopes,
          ark_claims: req.ark.claims,
          expires: new Date(req.ark.payload.exp * 1000).toISOString()
        },
        null,
        2
      )
    );
  },

  // A route with its own requirement, on top of whatever the middleware already enforced.
  '/reports': [
    bearer.require({ claims: ['reports.read'] }),
    (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ reports: ['q1', 'q2'], for: req.ark.sub }));
    }
  ]
};

createServer((req, res) => {
  bearer(req, res, () => {
    const path = new URL(req.url, 'http://api').pathname;
    const handler = routes[path];
    if (!handler) {
      res.statusCode = 404;
      return res.end(JSON.stringify({ error: 'not_found' }));
    }
    const chain = [handler].flat();
    let i = 0;
    const step = () => {
      const fn = chain[i++];
      return fn ? fn(req, res, step) : undefined;
    };
    step();
  });
}).listen(port, () => console.log(`Ark API example on http://localhost:${port} (provider ${authority})`));
