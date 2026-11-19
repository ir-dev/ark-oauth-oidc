'use client';
import { ArkCallback } from 'ark-oauth-client-js/next';

export default function SigninCallback() {
  return <ArkCallback><p id="callback">Signing you in…</p></ArkCallback>;
}
