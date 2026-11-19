'use client';
/**
 * Next.js (App Router) bindings: the React bindings, plus a provider that sends the user back
 * through the Next router after signing in.
 *
 *   // app/providers.tsx
 *   'use client';
 *   import { ArkNextProvider } from 'ark-oauth-client-js/next';
 *   import { ark } from '@/lib/ark';
 *   export default function Providers({ children }) { return <ArkNextProvider client={ark}>{children}</ArkNextProvider>; }
 *
 * The client itself can be created in a module shared with server code: it does not touch `window`
 * until init(), and on the server it stays `loading`, which is also what the first browser render
 * shows, so hydration matches.
 *
 * Re-exports are named on purpose: Next refuses `export *` across a client boundary.
 */
import { createElement } from 'react';
import { useRouter } from 'next/navigation';
import { ArkProvider } from './react.js';

export { ArkProvider, ArkContext, useArk, useArkClient, useArkUser, RequireArk, ArkCallback, ArkAccessDenied } from './react.js';

/** <ArkProvider> wired to `next/navigation`: after sign-in, `router.replace(returnTo)`. */
export function ArkNextProvider(props) {
  const router = useRouter();
  return createElement(ArkProvider, { onRedirectCallback: (to) => router.replace(to), ...props });
}
