import { Routes } from '@angular/router';
import { arkAuthGuard, arkClaimsGuard } from 'ark-oauth-client-js/angular';
import { BillingPage, CallbackPage, HomePage, ProfilePage } from './pages';

export const routes: Routes = [
  { path: '', component: HomePage },
  // The callback routes only show progress; provideArk completes the sign-in and sign-out.
  { path: 'signin-oidc', component: CallbackPage },
  { path: 'signout-callback-oidc', component: CallbackPage },
  { path: 'profile', component: ProfilePage, canActivate: [arkAuthGuard] },
  { path: 'billing', component: BillingPage, canActivate: [arkClaimsGuard('billing.admin')] }
];

// With SSR (ng new --ssr), render the guarded routes on the client, in app.routes.server.ts:
//   { path: 'profile', renderMode: RenderMode.Client }, { path: 'billing', renderMode: RenderMode.Client }
// Who is signed in is known only in the browser.
