import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';
import { createArk, createArkGuard } from 'ark-oauth-client-js/vue';
import App from './App.vue';
import Home from './views/Home.vue';
import Callback from './views/Callback.vue';
import Billing from './views/Billing.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: Home },
    // The callback routes only show progress; the plugin completes the sign-in and sign-out.
    { path: '/signin-oidc', component: Callback },
    { path: '/signout-callback-oidc', component: Callback },
    { path: '/billing', component: Billing, meta: { requiresAuth: true, arkClaims: ['billing.admin'] } }
  ]
});

const ark = createArk({
  authority: import.meta.env.VITE_ARK_AUTHORITY ?? 'https://localhost:7233/ark_idp', // {BaseUrl}/{TenantId}
  clientId: import.meta.env.VITE_ARK_CLIENT_ID ?? 'spa-demo'
});

// Router first: the plugin finds it and returns the user through router.replace() after sign-in.
createApp(App).use(router).use(ark).mount('#app');
router.beforeEach(createArkGuard(ark, { requireMeta: true }));
