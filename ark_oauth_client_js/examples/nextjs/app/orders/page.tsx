'use client';
import { RequireArk, useArk } from 'ark-oauth-client-js/next';

function Orders() {
  const { user, fetch } = useArk();
  void fetch;
  return <p id="orders">Orders for {user?.email}</p>;
}

export default function OrdersPage() {
  return (
    <RequireArk fallback={<p id="orders-loading">Loading…</p>} claims={['billing.admin']}>
      <Orders />
    </RequireArk>
  );
}
