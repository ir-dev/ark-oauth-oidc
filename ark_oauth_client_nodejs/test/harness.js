import { createServer } from 'node:http';

/**
 * The smallest thing that behaves like Express: a middleware chain over node:http, so the tests
 * exercise the middleware exactly as a real application mounts it — without depending on Express.
 */
export function app(...middlewares) {
  const server = createServer((req, res) => {
    let i = 0;
    const next = (error) => {
      if (error) {
        res.statusCode = 500;
        return res.end(`error: ${error.message}`);
      }
      const handler = middlewares[i++];
      if (!handler) {
        res.statusCode = 404;
        return res.end('not found');
      }
      Promise.resolve(handler(req, res, next)).catch(next);
    };
    next();
  });
  return server;
}

export function route(path, ...handlers) {
  return (req, res, next) => {
    if (new URL(req.url, 'http://x').pathname !== path) return next();
    let i = 0;
    const step = () => {
      const handler = handlers[i++];
      return handler ? handler(req, res, step) : undefined;
    };
    return step();
  };
}

/** A browser: keeps cookies, follows redirects, and reports where it ended up. */
export class Browser {
  constructor() {
    this.cookies = new Map();
  }

  cookieHeader() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  /** Submits a form the way a browser does: a same-origin POST, then redirects followed as GETs. */
  post(url, form, options = {}) {
    return this.go(url, { ...options, method: 'POST', form });
  }

  async go(url, { method = 'GET', maxRedirects = 10, headers = {}, follow = true, form = null } = {}) {
    let current = url;
    let body = form ? new URLSearchParams(form) : undefined;
    const trail = [];
    for (let i = 0; i <= maxRedirects; i += 1) {
      const response = await fetch(current, {
        method,
        body,
        redirect: 'manual',
        headers: {
          ...(body ? { 'sec-fetch-site': 'same-origin' } : {}),
          ...headers,
          ...(this.cookies.size ? { cookie: this.cookieHeader() } : {})
        }
      });
      body = undefined;

      for (const raw of response.headers.getSetCookie?.() ?? []) {
        const [pair] = raw.split(';');
        const eq = pair.indexOf('=');
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (value === '' || /max-age=0/i.test(raw)) this.cookies.delete(name);
        else this.cookies.set(name, value);
      }

      trail.push({ url: current, status: response.status });
      const location = response.headers.get('location');
      if (!follow) return { response, location, body: await response.text(), url: current, trail };
      if (response.status >= 300 && response.status < 400 && location) {
        current = new URL(location, current).toString();
        method = 'GET';
        continue;
      }
      return { response, body: await response.text(), url: current, trail };
    }
    throw new Error('too many redirects');
  }
}

export async function serve(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}
