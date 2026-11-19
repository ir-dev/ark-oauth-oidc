<script setup lang="ts">
import { useArk } from 'ark-oauth-client-js/vue';

const { error, signinRedirect } = useArk();
</script>

<template>
  <main v-if="error">
    <p>Sign-in did not complete: {{ error.message }}</p>
    <button type="button" @click="signinRedirect({ returnTo: '/' })">Try again</button>
  </main>
  <main v-else>One moment…</main>
</template>
