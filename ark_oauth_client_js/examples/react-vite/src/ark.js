import { ArkBrowserClient } from 'ark-oauth-client-js';

// One client for the whole app, created once at module scope.
export const ark = new ArkBrowserClient({
  authority: import.meta.env.VITE_ARK_AUTHORITY, // {BaseUrl}/{TenantId}
  clientId: import.meta.env.VITE_ARK_CLIENT_ID, // registered as a public client
  apiOrigins: [] // add your API's origin to let ark.fetch() send it the token
});
