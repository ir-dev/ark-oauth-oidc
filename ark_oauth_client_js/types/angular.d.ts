import type { EnvironmentProviders, InjectionToken, Signal } from '@angular/core';
import type { CanActivateFn } from '@angular/router';
import type { HttpInterceptorFn } from '@angular/common/http';
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

export interface ArkAngular {
  client: ArkBrowserClient;
  state: Signal<ArkSnapshot>;
  status: Signal<ArkStatus>;
  isLoading: Signal<boolean>;
  isAuthenticated: Signal<boolean>;
  user: Signal<Readonly<IdTokenClaims> | null>;
  arkClaims: Signal<readonly string[]>;
  scopes: Signal<readonly string[]>;
  error: Signal<ArkError | null>;
  denial: Signal<ArkDenial | null>;
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

export const ARK_CLIENT: InjectionToken<ArkBrowserClient>;
export const ARK: InjectionToken<ArkAngular>;

export function provideArk(
  optionsOrClient: ArkClientOptions | ArkBrowserClient,
  settings?: { autoInit?: boolean; onRedirectCallback?: (returnTo: string) => unknown }
): EnvironmentProviders;

/** Call in an injection context (a field initializer, a constructor, inject()-time). */
export function injectArk(): ArkAngular;

export const arkAuthGuard: CanActivateFn;
export function arkClaimsGuard(...claims: Array<string | string[]>): CanActivateFn;
export function createArkGuard(options?: {
  claims?: string[];
  anyClaims?: string[];
  onDenied?: (...args: Parameters<CanActivateFn>) => ReturnType<CanActivateFn>;
}): CanActivateFn;

export const arkInterceptor: HttpInterceptorFn;
