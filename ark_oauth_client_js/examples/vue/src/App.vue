<script setup lang="ts">
import { useArk } from 'ark-oauth-client-js/vue';

const { isLoading, isAuthenticated, user, arkClaims, signinRedirect, signoutRedirect } = useArk();
</script>

<template>
  <header>
    <p v-if="isLoading">Loading…</p>
    <template v-else-if="isAuthenticated">
      <p>Signed in as {{ user?.email }} · claims: {{ arkClaims.join(', ') || '(none)' }}</p>
      <button type="button" @click="signoutRedirect()">Sign out</button>
    </template>
    <button v-else type="button" @click="signinRedirect()">Sign in</button>
    <nav>
      <RouterLink to="/">Home</RouterLink> |
      <RouterLink to="/billing">Billing</RouterLink> (needs billing.admin)
    </nav>
  </header>
  <RouterView />
</template>
