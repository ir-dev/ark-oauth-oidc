// Shared by server and client code: creating the client touches no browser API.
import { ArkBrowserClient } from 'ark-oauth-client-js';

export const ark = new ArkBrowserClient({
  authority: process.env.NEXT_PUBLIC_ARK_AUTHORITY ?? 'https://localhost:7233/ark_idp',
  clientId: process.env.NEXT_PUBLIC_ARK_CLIENT_ID ?? 'spa-demo'
});
