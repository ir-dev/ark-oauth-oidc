import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { Routes, provideRouter, Router } from '@angular/router';
import { inject } from '@angular/core';
import { arkAuthGuard, arkClaimsGuard, arkInterceptor, createArkGuard, injectArk, provideArk } from 'ark-oauth-client-js/angular';

const routes: Routes = [
  { path: 'orders', canActivate: [arkAuthGuard], loadComponent: () => Promise.resolve(class {}) },
  { path: 'billing', canActivate: [arkClaimsGuard('billing.admin')], loadComponent: () => Promise.resolve(class {}) },
  { path: 'payroll', canActivate: [createArkGuard({ claims: ['payroll'], onDenied: () => inject(Router).parseUrl('/no-access') })], loadComponent: () => Promise.resolve(class {}) }
];

export const appConfig: ApplicationConfig = {
  providers: [
    provideArk({ authority: 'https://idp.example.com/t', clientId: 'spa', apiOrigins: ['https://api.example.com'] }),
    provideHttpClient(withInterceptors([arkInterceptor])),
    provideRouter(routes)
  ]
};

export class Header {
  ark = injectArk();
  get email() {
    return this.ark.isAuthenticated() ? this.ark.user()?.email : null;
  }
}
