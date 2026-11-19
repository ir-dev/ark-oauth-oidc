'use client';
import { ArkNextProvider } from 'ark-oauth-client-js/next';
import { ark } from '@/lib/ark';

export default function Providers({ children }: { children: React.ReactNode }) {
  return <ArkNextProvider client={ark}>{children}</ArkNextProvider>;
}
