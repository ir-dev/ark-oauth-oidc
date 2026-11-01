/**
 * Shared configuration for the examples, read from the environment.
 *
 *   export ARK_AUTHORITY="https://localhost:7107/my_idp"   # {BaseUrl}/{TenantId}
 *   export ARK_CLIENT_ID="my-app"
 *   export ARK_CLIENT_SECRET="…"        # confidential clients only
 *   export ARK_SESSION_SECRET="…"       # any 32+ random characters
 *
 * Register the client in the admin console at {BaseUrl}/{TenantId}/admin first, and remember the
 * step that is easy to miss: a user needs an access mapping to the client, or sign-in fails in a
 * way that looks exactly like a wrong password.
 */
export const authority = process.env.ARK_AUTHORITY ?? 'https://localhost:7107/my_idp';
export const clientId = process.env.ARK_CLIENT_ID ?? 'my-app';
export const clientSecret = process.env.ARK_CLIENT_SECRET ?? null;
export const sessionSecret = process.env.ARK_SESSION_SECRET ?? 'change-me-a-long-random-development-secret';
export const port = Number(process.env.PORT ?? 3000);
export const origin = process.env.ORIGIN ?? `http://localhost:${port}`;

/**
 * Set ARK_INSECURE=1 when the identity server is on plain http, or its development certificate is
 * not trusted by Node. Never in production: it turns off the checks that keep tokens off the wire
 * in the clear and stop a forged certificate being accepted.
 */
export const insecure = process.env.ARK_INSECURE === '1';
if (insecure) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
