// Compiled by `npm run typecheck`, never run: proves the declarations describe the documented usage.
import {
  ArkBrowserClient,
  ArkOAuthError,
  ArkPopupError,
  createArkClient,
  type ArkSnapshot,
  type SetupReport
} from 'ark-oauth-client-js';

const ark = new ArkBrowserClient({
  authority: 'https://idp.example.com/my_idp',
  clientId: 'my-spa',
  apiOrigins: ['https://api.example.com'],
  storage: 'local',
  accountSwitch: { requireArkClaims: true, requiredClaims: ['billing.admin'] }
});
createArkClient({ authServerUrl: 'https://idp.example.com', tenantId: 't', clientId: 'x' });

const off: () => void = ark.subscribe((s: ArkSnapshot) => {
  if (s.isAuthenticated) console.log(s.user?.email, s.arkClaims.includes('billing.admin'));
  if (s.status === 'denied') console.log(s.denial?.email);
});
off();
ark.on('sessionExpired', (e) => console.log(e.reason));
ark.on('accessDenied', (d) => console.log(d.reason));

async function flow() {
  const state = await ark.init({ onRedirectCallback: (to) => history.replaceState(null, '', to) });
  if (!state.isAuthenticated) await ark.signinRedirect({ returnTo: '/orders', prompt: 'login' });
  try {
    const r = await ark.signinPopup();
    console.log(r.denied, r.user?.sub);
  } catch (e) {
    if (e instanceof ArkPopupError && e.reason === 'blocked') await ark.signinRedirect();
    if (e instanceof ArkOAuthError) console.log(e.error, e.errorDescription);
  }
  const token: string | null = await ark.getAccessToken();
  const res: Response = await ark.fetch('/api/orders', { method: 'POST', body: '{}' });
  const report: SetupReport = await ark.checkSetup();
  console.log(token, res.status, report.problems.length, ark.hasArkClaims('a', ['b']));
  await ark.signoutRedirect({ returnTo: '/' });
  const svelteLike = ark.state.subscribe((s) => s.status);
  svelteLike();
}
void flow;
