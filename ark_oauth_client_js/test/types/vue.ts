import { createApp } from 'vue';
import { createRouter, createWebHistory, type NavigationGuard } from 'vue-router';
import { createArk, createArkGuard, useArk } from 'ark-oauth-client-js/vue';

const ark = createArk({ authority: 'https://idp.example.com/t', clientId: 'spa' });
const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/signin-oidc', component: {} },
    // the documented per-route form must fit vue-router's own guard type under strict
    { path: '/billing', component: {}, beforeEnter: createArkGuard(ark, { claims: ['billing.admin'] }), meta: { requiresAuth: true } }
  ]
});
router.beforeEach(createArkGuard(ark, { requireMeta: true, onDenied: () => ({ path: '/no-access' }) }));
const asGuard: NavigationGuard = createArkGuard(ark);
void asGuard;
createApp({}).use(router).use(ark);

export function setup() {
  const { isAuthenticated, user, signinRedirect } = useArk();
  const email: string | undefined = user.value?.email;
  if (!isAuthenticated.value) void signinRedirect();
  return { email };
}
