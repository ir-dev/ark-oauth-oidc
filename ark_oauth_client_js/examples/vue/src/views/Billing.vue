<script setup lang="ts">
import { useArk } from 'ark-oauth-client-js/vue';

const { user } = useArk(); // a computed ref: top-level, so the template unwraps it
</script>

<template><main>Billing for {{ user?.name }}</main></template>
