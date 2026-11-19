import type { Context, ReactNode, CSSProperties, JSX } from 'react';
import type {
  ArkBrowserClient,
  ArkClientOptions,
  ArkDenial,
  ArkError,
  ArkSnapshot,
  IdTokenClaims,
  PopupSigninOptions,
  RedirectCallbackResult,
  SigninOptions,
  SigninResult,
  SignoutOptions
} from './index.js';

export const ArkContext: Context<ArkBrowserClient | null>;

export interface ArkProviderProps {
  /** Created at module scope, so every render sees the same client. */
  client?: ArkBrowserClient;
  /** Or options, from which the provider creates one. */
  options?: ArkClientOptions;
  /** Where to send the user after sign-in: pass your router's navigate. */
  onRedirectCallback?: (returnTo: string, result: RedirectCallbackResult) => unknown;
  /** Start the client on mount. Default true. */
  autoInit?: boolean;
  children?: ReactNode;
}
export function ArkProvider(props: ArkProviderProps): JSX.Element;

export interface UseArkResult extends ArkSnapshot {
  client: ArkBrowserClient;
  signinRedirect(options?: SigninOptions): Promise<void>;
  signinPopup(options?: PopupSigninOptions): Promise<SigninResult>;
  signoutRedirect(options?: SignoutOptions): Promise<void>;
  signoutLocal(options?: { revoke?: boolean }): Promise<void>;
  switchUser(options?: { returnTo?: string; loginHint?: string }): Promise<void>;
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string | null>;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  hasArkClaims(...claims: Array<string | string[]>): boolean;
  hasAnyArkClaim(...claims: Array<string | string[]>): boolean;
}

export function useArk(): UseArkResult;
export function useArkClient(): ArkBrowserClient;
export function useArkUser(): Readonly<IdTokenClaims> | null;

export interface RequireArkProps {
  children?: ReactNode;
  /** Shown while loading and while the sign-in is being started. */
  fallback?: ReactNode;
  /** Every one of these Ark claims is required. */
  claims?: string[];
  /** At least one of these. */
  anyClaims?: string[];
  /** For a signed-in user missing a claim. Default <ArkAccessDenied />. */
  forbidden?: ReactNode | ((user: Readonly<IdTokenClaims> | null) => ReactNode);
  /** For a sign-in refused by accountSwitch. Default <ArkAccessDenied />. */
  denied?: ReactNode | ((denial: ArkDenial | null) => ReactNode);
  /** For a failed sign-in. Default: a message and a retry button. */
  error?: ReactNode | ((error: ArkError | null, retry: () => Promise<void>) => ReactNode);
  signinOptions?: SigninOptions;
}
export function RequireArk(props: RequireArkProps): ReactNode;

export function ArkCallback(props: {
  children?: ReactNode;
  error?: ReactNode | ((error: ArkError | null, retry: () => Promise<void>) => ReactNode);
}): ReactNode;

export function ArkAccessDenied(props: { appName?: string; className?: string; style?: CSSProperties }): JSX.Element;
