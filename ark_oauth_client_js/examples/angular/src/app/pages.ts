import { Component } from '@angular/core';
import { injectArk } from 'ark-oauth-client-js/angular';

@Component({ selector: 'app-home', template: '<p>Home</p>' })
export class HomePage {}

@Component({
  selector: 'app-callback',
  template: `@if (ark.error(); as error) {
      <p>Sign-in did not complete: {{ error.message }}</p>
      <button type="button" (click)="ark.signinRedirect({ returnTo: '/' })">Try again</button>
    } @else {
      <p>One moment…</p>
    }`
})
export class CallbackPage {
  protected readonly ark = injectArk();
}

@Component({ selector: 'app-profile', template: '<p>Profile of {{ ark.user()?.name }}</p>' })
export class ProfilePage {
  protected readonly ark = injectArk();
}

@Component({ selector: 'app-billing', template: '<p>Billing (you hold billing.admin)</p>' })
export class BillingPage {}
