# Webhooks

The identity server can tell your systems what happens on it — a user signed in, a sign-in failed,
an account was locked out, tokens were issued, an application or user changed — by POSTing a
signed JSON event to endpoints you configure. Delivery is database-backed: events are stored before
they are sent, retried with back-off, moved to a dead-letter queue when they cannot be delivered,
and can be replayed by hand. Each endpoint chooses where its deliveries are stored (its **shard
plan**), and an endpoint that keeps failing is switched off for its tenant automatically.

New to webhooks? The [developer guide](https://ir-dev.github.io/ark-oauth-oidc/webhooks.html) has a
first signed event arriving in a RequestBin in ten minutes, a signature checker that runs in the
browser, and experiments that show retries, dead letters and recovery.

The module is **opt-in**. A host that does not ask for it gets none of it: no tables, no background
work, no console link, and its routes answer 404.

## Turn it on

```csharp
builder.AddArkIdp();                    // or builder.Services.AddArkOidcServer(builder.Environment);
builder.Services.AddArkWebhooks();      // ← this line
```

That is the whole of the wiring. On the next start:

* the console gains a **Webhooks** page at `/{tenant}/admin/webhooks` (operator account only);
* the management API gains `/api/oauth/v1/webhooks/…` (same operator policy as the rest of it);
* two control tables, `ark_wh_endpoints` and `ark_wh_shards`, are created in the IdP's database
  beside — never inside — its own schema. The start-up schema sync, export/import and factory reset
  only ever touch the IdP's own tables, so they neither create, export nor delete webhook data.

Nothing is sent until you create an endpoint.

## What happens to an IdP request

The IdP raises an event with one call that cannot throw and never waits: it checks an in-memory
list of endpoints, and if anything subscribes, puts the event on a bounded in-memory queue. A
background writer stores queued events as delivery rows a moment later, in batches. So a sign-in or
token request pays for a dictionary walk and nothing else — no database round trip, no HTTP call.

The trade is the one the audit trail makes: an event still in that queue when the process is killed
outright is lost (a normal shutdown writes it), and if the database cannot keep up the queue fills
and new events are dropped and logged rather than the process growing. Code that must not lose an
event can call `IArkWebhookPublisher.PublishAndWaitAsync`, which stores the deliveries before it
returns.

## Events

| Type | Raised when | Tenant |
|---|---|---|
| `user.signed_in` | a user signed in with a password | the client's |
| `user.signin_failed` | wrong password, unknown user or no access | the client's |
| `user.locked_out` | the failed-attempt lockout blocked a sign-in | the client's |
| `user.signin_refused` | a verified user was refused: user or application deactivated, no access mapping | the client's |
| `user.signed_out` | a session ended through RP-initiated logout (one event per session) | the session's |
| `token.issued` | tokens issued for an authorization code or client credentials | the client's |
| `token.revoked` | a client revoked a token | the client's |
| `device.approved` | a user approved a device authorization | the client's |
| `client.updated` / `client.deleted` | an application changed in the console or management API | the client's |
| `client.registered` | dynamic client registration | the client's |
| `client.secret_reset` | a client secret was regenerated (the secret is never sent) | the client's |
| `client.activation_changed` / `client.provisioned` | activation switch, provisioning | the client's |
| `user.updated` / `user.password_changed` / `user.activation_changed` | account changes | operator tenant |
| `user.access_changed` / `user.provisioned` | access mapping added, changed or removed | the mapping's |
| `tenant.updated` | a tenant was created or changed | operator tenant |
| `webhook.test` | the console's **Send test** button | the endpoint's |

Accounts are server-wide rather than per tenant, so user and tenant changes are raised in the
operator tenant (`ark_oauth_server:TenantId`).

An endpoint subscribes with a list of types and patterns: `user.signed_in`, `user.*`, or `*` for
everything including types added later. Your host can raise events of its own — they go to every
endpoint whose patterns match:

```csharp
app.MapPost("/orders", async (IArkWebhookPublisher webhooks, Order order) =>
{
    // Returns at once; false when nothing subscribes, webhooks are off or the queue is full.
    webhooks.Publish("acme", "billing.order_placed", new { order.Id, order.Total }, subject: order.CustomerEmail);
});
```

## What an endpoint receives

```http
POST /your/endpoint HTTP/1.1
Content-Type: application/json; charset=utf-8
User-Agent: Ark-Webhooks/2.4.0
webhook-id: evt_8f3c…                    ← the event id: the same on every retry and replay
webhook-timestamp: 1795310591
webhook-signature: v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=
X-Ark-Event: user.signed_in
X-Ark-Delivery: dlv_51b2…                 ← this delivery (a replay gets a new one)
X-Ark-Attempt: 1
X-Ark-Tenant: acme
Authorization: …                          ← per the endpoint's authentication, if any

{"id":"evt_8f3c…","type":"user.signed_in","tenant_id":"acme","subject":"ana@acme.test",
 "created_at":"2026-11-22T09:14:51.120Z",
 "data":{"user":"ana@acme.test","name":"Ana","client_id":"portal","session_id":"…","ip":"203.0.113.7"}}
```

Answer any **2xx** to acknowledge. Redirects are not followed — a 3xx is a failure — and only the
first 4 KB of your response is read and kept in the delivery history.

Delivery is **at least once**: a worker that dies mid-request leaves its claim to lapse and another
sends the event again. De-duplicate on `webhook-id`. Events are **not ordered**; use `created_at`
when order matters.

### Verifying the signature

Signatures follow [Standard Webhooks](https://www.standardwebhooks.com/), so any of its libraries
verifies them. The signing secret is shown once, when the endpoint is created (and again on
**Rotate secret**). By hand: HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw body}`, keyed
with the base64-decoded part of the secret after `whsec_`, compared with the base64 value after
`v1,`. Reject timestamps more than five minutes old.

```python
import base64, hashlib, hmac, time

def verify(secret: str, headers, body: bytes) -> bool:
    msg_id, ts, sig = headers["webhook-id"], headers["webhook-timestamp"], headers["webhook-signature"]
    if abs(time.time() - int(ts)) > 300:
        return False
    key = base64.b64decode(secret.removeprefix("whsec_"))
    expected = base64.b64encode(hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    return any(hmac.compare_digest(expected, part.split(",", 1)[1]) for part in sig.split() if "," in part)
```

```csharp
static bool Verify(string secret, string id, string timestamp, string signatureHeader, string body)
{
    if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - long.Parse(timestamp)) > 300) return false;
    var key = Convert.FromBase64String(secret.StartsWith("whsec_") ? secret[6..] : secret);
    var expected = Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{id}.{timestamp}.{body}")));
    return signatureHeader.Split(' ').Any(p => p.StartsWith("v1,") &&
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(p[3..]), Encoding.ASCII.GetBytes(expected)));
}
```

```js
import crypto from "node:crypto";
export function verify(secret, headers, rawBody) {
  const id = headers["webhook-id"], ts = headers["webhook-timestamp"];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const expected = crypto.createHmac("sha256", key).update(`${id}.${ts}.${rawBody}`).digest("base64");
  return headers["webhook-signature"].split(" ").some(p => p.startsWith("v1,") &&
    p.length - 3 === expected.length && crypto.timingSafeEqual(Buffer.from(p.slice(3)), Buffer.from(expected)));
}
```

## Authentication to your endpoint

Every request is signed. On top of that, an endpoint can authenticate in one of these ways; the
secrets are stored encrypted with the IdP's data-protection key ring and never returned by the API.

| Type | Sends |
|---|---|
| `none` | the signature only |
| `basic` | `Authorization: Basic …` from a username and password |
| `bearer` | a static token — an API key or a JWT issued elsewhere — in `Authorization` (scheme configurable, blank sends the bare token) or any header you name |
| `jwt` | a JWT minted for every request, five minutes by default. **HS256** with a secret you share (32 bytes or more), or **RS256** with the tenant's own signing key, verifiable against `/{tenant}/.well-known/jwks.json`. Claims: `iss`, `aud` (default: the endpoint's origin), `sub` (the endpoint id), `iat`, `nbf`, `exp`, `jti`, `evt`, `evt_type`, `tenant_id`, `body_sha256` — a hash of the exact body, so the token cannot be lifted onto another request — plus any extra claims you give as JSON |
| `oauth2` | `Authorization: Bearer` with an access token obtained from your token endpoint, by **refresh_token** (a refresh token you paste in) or **client_credentials**, with `client_secret_post` or `client_secret_basic` |

For `oauth2`, the access token is shared by every instance and refreshed under a lease on the
endpoint's row, so with several instances one of them refreshes and the others use the result. A
refresh token your server rotates is stored and used next; reuse detection on your side never sees
the same refresh token twice. A 401 from your endpoint discards the token and the next attempt gets
a new one. An `invalid_grant` on the refresh token goes straight to the dead-letter queue with a
message to enter a new one.

Up to 20 **custom headers** can be added as well (values stored encrypted). The signature and
`X-Ark-*` headers cannot be overridden, nor `Authorization` unless the type is `none`.

## Retries, dead letters, replay

Each endpoint has a retry policy:

| Setting | Default | |
|---|---|---|
| Attempts in all | 8 | 1–50 |
| Back-off | exponential | exponential (doubling), linear or fixed |
| First retry after | 30 s | |
| Longest wait | 1 h | waits are capped here; ±20% jitter |
| Retry 4xx | off | 408 and 429 are always retried; a `Retry-After` header is honoured up to the longest wait |
| Timeout per attempt | 15 s | 1–120 |
| Parallel requests | 4 | per instance |

Timeouts, connection failures, 408, 429 and 5xx are retried. Other 4xx answers and 3xx are not:
they go to the **dead-letter queue** at once (unless "retry 4xx" is on), as does a delivery that
runs out of attempts. A dead letter keeps the exact body, the reason (`max_attempts`,
`non_retryable`, `endpoint_disabled`), the attempt count and the last answer.

**Replay** re-queues a dead letter — or any finished delivery from the history — as a new delivery
with the same event id and body, routed by the endpoint's current shard plan. The console replays
one, a selection, or every open dead letter of an endpoint; the original is kept and marked with
who replayed it and when. Waiting deliveries can be **cancelled**. Dead letters can be **purged**.

### Disabled after repeated failures

Every failed attempt adds to the endpoint's consecutive-failure count; any success resets it. When
the count reaches the endpoint's threshold (15 by default, 0 = never), the endpoint is disabled for
its tenant, exactly once even with several instances racing: new events are no longer queued for
it, and everything that was waiting is moved to the dead-letter queue instead of retrying into a
receiver known to be down. The console shows the reason and when it happened.

To recover: fix the receiver, press **Send test** (it works on a disabled endpoint, and a test never
counts towards the threshold), **Enable** (which resets the count), then **Replay all open** dead
letters.

**Pause** is the gentler switch: events keep being queued while paused and are delivered on
**Resume**.

## Shard plans: where deliveries are stored

Deliveries, their attempts and their dead letters live in shard tables, one set of three per shard:
`ark_wh_deliveries_{suffix}`, `ark_wh_attempts_{suffix}`, `ark_wh_dead_letters_{suffix}`. Which
shard a delivery goes to is decided by the endpoint's plan, chosen on the form when the webhook is
created:

| Strategy | Tables | When |
|---|---|---|
| **Shared** | `…_shared`, one set per database, shared by every endpoint on this plan | most webhooks |
| **Dedicated** | `…_d_{endpoint}`, the endpoint's own | a busy or failure-prone receiver that must not slow the others; history purged on its own |
| **Hashed** | `…_h_{endpoint}_{0..N-1}`, 2–32 shards chosen by a hash (FNV-1a) of the event's subject, type or id, spread round-robin over **one or more databases** | high volume; spreading writes and scans over tables and database servers |
| **Monthly** | `…_m_{yyyyMM}`, one set per calendar month (UTC), shared by every monthly endpoint | long retention; old months stop being scanned once drained |

The form shows the plan as you build it — every table it will create, on which database, and
whether that database answers — and saving creates the tables first, so a database that cannot be
reached is a refusal on the form, not lost deliveries later.

**Databases.** `main` is always the IdP's own database. Others are named in configuration, so
connection strings never reach the console or the endpoint rows:

```jsonc
"ark_oauth_server": {
  "Webhooks": {
    "Databases": {
      "events-eu": { "Provider": "postgres", "ConnectionString": "Host=…;Database=ark_webhooks;…" },
      "events-us": { "Provider": "postgres", "ConnectionStringName": "WebhooksUs" }   // from ConnectionStrings
    }
  }
}
```

Providers are those the IdP supports: `sqlite`, `postgres`, `mysql`, mixed freely. Only the
hashed plan spreads over more than one database.

**Changing a plan** applies to new deliveries; what is already stored stays where it is and is
still dispatched and shown in the history. A shard that nothing routes to any more (last month's,
a plan that changed, a deleted endpoint's) is **sealed** once nothing in it is waiting: it is no
longer scanned, but its history stays readable until retention removes it. Tables are never dropped
automatically; an empty sealed shard's tables can be dropped by hand.

**SQLite.** SQLite takes one writer at a time for the whole file. On a busy server, put webhook
deliveries in a database of their own (`"Provider": "sqlite", "ConnectionString": "Data
Source=./data/webhooks.db"`) so they never wait on the IdP's writes, or the reverse.

## The dispatcher

A .NET `BackgroundService` on every instance, working from the delivery tables:

* **Claiming is a compare-and-swap.** A worker reads due deliveries, then takes each one with
  `UPDATE … SET status = 'in_flight', lock_version = v + 1 … WHERE id = @id AND lock_version = v`.
  Exactly one worker can win that, on any instance and any provider, so any number of instances can
  run against the same tables. Every later change to the row is the same compare-and-swap, so a
  worker that lost its claim can never overwrite the winner.
* **Leases.** A claim lasts the endpoint's timeout plus `LeaseMarginSeconds`. A worker that dies
  holding claims just lets them lapse; another worker takes them over. On a normal shutdown it stops
  claiming, lets requests in flight finish for up to 20 seconds, and hands back whatever is left.
* **Bounded concurrency.** At most `MaxConcurrency` requests in flight per instance (16), and at
  most the endpoint's own limit to any one receiver per instance. The dispatcher claims only as
  many deliveries as it has free slots, so nothing it holds waits while its lease runs down.
* **Fair.** Paused endpoints and endpoints already at their limit are left out of the claim query,
  and the scan starts at a different shard each pass, so one busy endpoint or shard cannot take
  every slot.
* **Housekeeping** every `HousekeepingMinutes` on every instance (each step is idempotent):
  retention deletes, sealing drained shards, and re-opening a sealed shard if a delivery turns up in it.

Verified with two instances on one PostgreSQL database (400 events raised across both: each
delivered exactly once, both instances working every shard, at most 2 × 8 requests in flight to a
receiver limited to 8), and by killing an instance with ten requests in flight: the other instance
took the ten over when their leases ran out and delivered them.

## Configuration

`ark_oauth_server:Webhooks` — every value optional, shown at its default. Read on every use, so
changes apply without a restart.

| Key | Default | |
|---|---|---|
| `Enabled` | `true` | `false` stops queuing and sending; configuration and history stay |
| `MaxConcurrency` | `16` | requests in flight per instance |
| `BatchSize` | `50` | deliveries claimed per shard per poll |
| `PollIntervalMs` | `2000` | idle poll; new deliveries written on the same instance wake it at once |
| `LeaseMarginSeconds` | `60` | added to the endpoint's timeout to make the claim lease |
| `RefreshSeconds` | `10` | how soon other instances see a change made in the console |
| `RetentionDays` | `30` | delivered, cancelled and failed-test deliveries and their attempts |
| `DeadLetterRetentionDays` | `90` | dead letters and the deliveries behind them |
| `HousekeepingMinutes` | `10` | retention and shard upkeep |
| `QueueCapacity` | `10000` | events waiting to be stored, per instance |
| `MaxPayloadBytes` | `262144` | largest event body |
| `AllowInsecureHttp` | `false` | plain `http://` endpoints (and token endpoints); loopback is always allowed |
| `ControlDatabase` | `main` | where `ark_wh_endpoints` and `ark_wh_shards` live |
| `WorkerId` | machine:pid:random | the name recorded on claims and attempts |
| `Databases:{name}` | | `Provider` plus `ConnectionString` or `ConnectionStringName` |

## Management API

Base `/api/oauth/v1/webhooks`, behind the management policy (the operator's console session, or a
`client.register` token of `{TenantId}_machine`). Writes are `POST` with a JSON body; answers are
`{ error, code, msg, data }` with a real HTTP status. Secrets in a request: `null` keeps what is
stored, `""` clears it, anything else replaces it.

| Route | |
|---|---|
| `GET meta` | event catalogue, databases, strategies, defaults, limits, this instance's dispatcher status |
| `GET list?tenant_id=` · `GET get?id=` | endpoints (no secrets; `has_…` flags instead) |
| `POST upsert` | create (no `id`) or update; create returns `signing_secret`, once |
| `POST status` | `{ id, action: pause \| resume \| enable \| disable }` |
| `POST secret/rotate` · `POST delete` | `delete` takes `purge: true` to remove its history too |
| `POST test` | sends `webhook.test` now and returns the answer |
| `POST plan` | what a shard plan would create, and whether its databases answer |
| `GET deliveries?endpoint_id=&tenant_id=&status=&limit=&before=` | delivery history, newest first |
| `GET delivery?shard=&id=` | one delivery: body, attempts, dead letter |
| `POST delivery/replay` · `POST delivery/cancel` | `{ shard, id }` |
| `GET deadletters?endpoint_id=&tenant_id=&include_replayed=` | the dead-letter queue |
| `POST deadletters/replay` · `POST deadletters/purge` | `{ items: [{ shard, id }] }` or `{ endpoint_id }` |
| `GET analytics?tenant_id=&endpoint_id=&hours=` | per-endpoint counts, success rate, latency (avg, p95), backlog, open dead letters, and a time series |
| `GET shards` | the shard registry with row counts |

Every configuration change is written to the IdP's audit trail with who made it, whatever
`EnableLogTrace` says (the endpoint's host only — some receivers keep a secret in the URL path).

## Good to know

* **Backups.** Export/import does not include webhook tables; back them up with the database.
  The signing and credential secrets are encrypted with the data-protection key ring: a database
  restored elsewhere without that ring keeps its endpoints but needs their secrets entered again
  (the console says so), and the signing secret rotated.
* **Removing the module** is removing the `AddArkWebhooks()` line. The tables stay until you drop
  them (`ark_wh_*`).
* **Security.** Only the operator can configure webhooks: an endpoint sends identity events — who
  signed in, from which address — to a URL of the caller's choosing. Endpoint URLs must be https
  (or loopback) unless `AllowInsecureHttp` is set. No event carries a password, secret or token.
