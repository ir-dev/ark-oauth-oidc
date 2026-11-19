// A static server for the vanilla example: no dependencies, no build.
//
//   ARK_AUTHORITY=https://idp.example.com/my_idp ARK_CLIENT_ID=my-spa node examples/serve.mjs
//   open http://127.0.0.1:5173
//
// EXAMPLE=script-tag serves the <script src> variant (window.ArkOAuth, built by `npm run build`)
// instead of the ES-module one.
//
// Serves the package root (so the page imports ../../src/index.js as plain ES modules) and answers
// any other path, /signin-oidc and /signout-callback-oidc included, with the app's index.html: the
// "history fallback" every single-page app host needs for its callback routes.
//
// Register on the client, byte for byte:  http://127.0.0.1:5173/signin-oidc  (redirect URI)
//                                         http://127.0.0.1:5173/signout-callback-oidc  (post-logout)
// and add http://127.0.0.1:5173 to the provider's ark_oauth_server:Oidc:CorsOrigins.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..'));
const port = Number(process.env.PORT ?? 5173);
const host = process.env.HOST ?? '127.0.0.1';
const page = process.env.EXAMPLE === 'script-tag' ? 'examples/vanilla/script-tag.html' : 'examples/vanilla/index.html';
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.map': 'application/json' };

const config = {
  authority: process.env.ARK_AUTHORITY ?? 'https://localhost:7233/ark_idp',
  clientId: process.env.ARK_CLIENT_ID ?? 'spa-demo',
  storage: process.env.ARK_STORAGE ?? 'session',
  requiredClaims: (process.env.ARK_REQUIRED_CLAIMS ?? '').split(',').filter(Boolean)
};

// A Content-Security-Policy as strict as the library allows: no inline script, and connect-src
// limited to this origin and the provider's. The access-denied card still renders (CSSOM styling).
const csp = (authority) =>
  `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ${new URL(authority).origin}; ` +
  `img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self' ${new URL(authority).origin}`;

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${host}:${port}`);
  if (url.pathname === '/config.json') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify(config));
  }
  let file = normalize(join(root, decodeURIComponent(url.pathname)));
  if (!file.startsWith(root)) {
    res.writeHead(403);
    return res.end();
  }
  const isFile = await stat(file).then((s) => s.isFile()).catch(() => false);
  if (!isFile) file = join(root, page);
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store', 'Content-Security-Policy': csp(config.authority) });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end('not found');
  }
}).listen(port, host, () => console.log(`ark vanilla example on http://${host}:${port} (authority ${config.authority}, client ${config.clientId})`));
