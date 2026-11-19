import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { arkInterceptor, provideArk } from 'ark-oauth-client-js/angular';
import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    // Starts before the first navigation: the sign-in callback is complete by the time the router reads the URL.
    provideArk({
      authority: 'https://localhost:7233/ark_idp', // {BaseUrl}/{TenantId}
      clientId: 'spa-demo', // a public client
      apiOrigins: ['https://api.example.com'] // the only origins (besides this one) that receive the token
    }),
    provideHttpClient(withInterceptors([arkInterceptor])),
    provideRouter(routes)
  ]
};
