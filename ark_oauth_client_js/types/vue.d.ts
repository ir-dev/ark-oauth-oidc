import type { App, ComputedRef, InjectionKey, ShallowRef } from 'vue';
import type {
  ArkBrowserClient,
  ArkClientOptions,
  ArkDenial,
  ArkError,
  ArkSnapshot,
  ArkStatus,
  IdTokenClaims,
  PopupSigninOptions,
  SigninOptions,
  SigninResult,
  SignoutOptions
} from './index.js';

export { ArkBrowserClient };

export interface ArkVue {
  client: ArkBrowserClient;
  /** The whole snapshot, reactive. */
  state: ShallowRef<ArkSnapshot>;
  status: ComputedRef<ArkStatus>;
  isLoading: ComputedRef<boolean>;
  isAuthenticated: ComputedRef<boolean>;
  user: ComputedRef<Readonly<IdTokenClaims> | null>;
  arkClaims: ComputedRef<readonly string[]>;
  scopes: ComputedRef<readonly string[]>;
  error: ComputedRef<ArkError | null>;
  denial: ComputedRef<ArkDenial | null>;
  signinRedirect(options?: SigninOptions): Promise<void>;
  signinPopup(options?: PopupSigninOptions): Promise<SigninResult>;
  signoutRedirect(options?: SignoutOptions): Promise<void>;
  signoutLocal(options?: { revoke?: boolean }): Promise<void>;
  switchUser(options?: { returnTo?: string; loginHint?: string }): Promise<void>;
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string | null>;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  hasArkClaims(...claims: Array<string | string[]>): boolean;
  hasAnyArkClaim(...claims: Array<string | string[]>): boolean;
  install(app: App): void;
}

export const ARK_INJECTION_KEY: InjectionKey<ArkVue>;

export function createArk(
  optionsOrClient: ArkClientOptions | ArkBrowserClient,
  settings?: { router?: { replace(to: string): unknown } | null; autoInit?: boolean }
): ArkVue;

export function useArk(): ArkVue;

/** A vue-router guard (beforeEach / beforeEnter). Route meta: `requiresAuth`, `arkClaims`. */
export function createArkGuard(
  ark: ArkVue,
  options?: {
    claims?: string[];
    anyClaims?: string[];
    requireMeta?: boolean;
    onDenied?: (to: any, state: ArkSnapshot) => unknown;
  }
  // `any`, not `unknown`: vue-router's NavigationGuard return type must accept it under strict.
): (to: { fullPath: string; meta?: Record<string, any> }) => Promise<any>;

declare module 'vue' {
  interface ComponentCustomProperties {
    $ark: ArkVue;
  }
}
