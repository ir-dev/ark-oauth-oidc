import type { JSX } from 'react';
import type { ArkProviderProps } from './react.js';

export {
  ArkProvider,
  ArkContext,
  useArk,
  useArkClient,
  useArkUser,
  RequireArk,
  ArkCallback,
  ArkAccessDenied,
  ArkProviderProps,
  UseArkResult,
  RequireArkProps
} from './react.js';

/** <ArkProvider> wired to next/navigation (App Router): after sign-in, router.replace(returnTo). */
export function ArkNextProvider(props: ArkProviderProps): JSX.Element;
