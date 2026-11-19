import { ArkBrowserClient } from 'ark-oauth-client-js';
import { ArkProvider, ArkCallback, RequireArk, useArk, useArkUser } from 'ark-oauth-client-js/react';
import { ArkNextProvider } from 'ark-oauth-client-js/next';

const ark = new ArkBrowserClient({ authority: 'https://idp.example.com/t', clientId: 'spa' });

function Profile() {
  const { isAuthenticated, user, signinRedirect, fetch, hasArkClaims } = useArk();
  const u = useArkUser();
  if (!isAuthenticated) return <button onClick={() => signinRedirect({ returnTo: '/me' })}>Sign in</button>;
  void fetch('/api/me');
  return <p>{user?.email} {u?.name as string} {String(hasArkClaims('billing.admin'))}</p>;
}

export function App({ navigate }: { navigate: (to: string) => void }) {
  return (
    <ArkProvider client={ark} onRedirectCallback={(to) => navigate(to)}>
      <ArkCallback error={(e, retry) => <button onClick={retry}>{e?.message}</button>}>Signing in…</ArkCallback>
      <RequireArk fallback={<p>Loading…</p>} claims={['billing.admin']} forbidden={<p>No</p>}>
        <Profile />
      </RequireArk>
    </ArkProvider>
  );
}

export function NextRoot({ children }: { children: React.ReactNode }) {
  return <ArkNextProvider client={ark}>{children}</ArkNextProvider>;
}
