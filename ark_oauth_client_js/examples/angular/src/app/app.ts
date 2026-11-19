import { Component, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { RouterLink, RouterOutlet } from '@angular/router';
import { injectArk } from 'ark-oauth-client-js/angular';

@Component({
  imports: [RouterOutlet, RouterLink],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  protected readonly ark = injectArk();
  private readonly http = inject(HttpClient);

  protected loadOrders(): void {
    this.http.get('https://api.example.com/orders').subscribe({ error: () => undefined });
  }
}
