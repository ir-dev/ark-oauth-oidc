# Agent-to-agent (A2A)

When one agent calls another, the second needs to know three things: which agent is calling, on
whose behalf, and that the token it was handed was meant for it and not lifted from somewhere else.
The identity server answers all three with ordinary OAuth 2.0:

* **An agent is a client.** Any confidential client can be one; there is nothing new to register.
* **A token is addressed to one agent.** Its `aud` is the client_id of the agent being called, so
  it is refused everywhere else.
* **The agent being called decides who may call it.** Its client record lists its callers. With
  nothing listed, which is how every client starts, nobody can get a token for it.
* **A user is carried, never impersonated.** An agent acting for a signed-in user exchanges that
  user's token (RFC 8693) for one addressed to the next agent. The token still names the user, and
  its `act` claim records every agent it passed through.

It is on by default and does nothing until you list a caller. Every other token the server issues,
and every client that never asks for an agent token, is exactly as before.

```
 user ──signs in──▶ web-app ──────▶ agent-a ──────▶ agent-b
                       │               │               │
 token:            aud tenant      aud agent-a     aud agent-b
                   sub alice       sub alice       sub alice
                                   act web-app     act agent-a ◀ web-app
```

New to this? The [agents guide](https://ir-dev.github.io/ark-oauth-oidc/agents.html) draws each flow
step by step, with MCP servers as well as agents, and shows the recorded reply for each request that
is refused.

## Set it up

Everything is on the **client** drawer of the admin console (`/{tenant}/admin`).

1. **Give each agent a client.** Confidential (`client_secret_basic`, `client_secret_post` or
   `private_key_jwt`), with the `client_credentials` grant. Add the
   `urn:ietf:params:oauth:grant-type:token-exchange` grant to the ones that will act for users.
   Press **Regenerate secret** and keep the value.
2. **On the agent being called, list who may call it.** Open *its* client, find
   **Agent-to-agent (A2A)**, press **Add calling client** and choose the caller. Then:
   * *claims* — what the caller holds here when it calls as itself. They arrive in the token as
     `ark_claims`, the same claim your application already authorizes users with.
   * *may act for users* — tick it to let this caller bring a user along.
3. **For calls on behalf of a user, give the user access to the agent being called**, as you would
   for any application (Users → access mapping). An agent cannot carry somebody to an application
   they have no access to, and what the user may do there is the user's own mapping.

Callers and targets must be in the same tenant.

**Mark the agents.** In the same section, tick **This client is an agent**. The client list then
shows an `agent` badge against it, with two counts — `←` how many clients may call it, `→` how many
it may call — and **agents only** above the list narrows it to them. The mark is a label for the
console and the audit trail: it grants nothing and refuses nothing, the caller list alone decides
who may call whom. A client that takes part in agent-to-agent calls without the mark is shown as
`a2a, not marked`, so nothing that acts as an agent is ever missing from the list. Through the
management API it is `"is_agent": true` on the same `client/upsert`; a save that does not carry
the field leaves it as it was.

The same list through the management API, on `POST /api/oauth/v1/client/upsert`:

```json
{
  "tenant_id": "acme", "client_id": "agent-b", "...": "...",
  "a2a_callers": [
    { "client_id": "agent-a", "claims": ["orders.read"], "delegate_users": true },
    { "client_id": "nightly-job", "claims": ["orders.read"] }
  ]
}
```

A save that does not carry `a2a_callers` leaves the list as it was; `[]` clears it.

## Calling an agent as itself

`client_credentials`, plus `audience` naming the agent to call:

```bash
curl -s https://idp.example.com/acme/oauth2/token \
  -u agent-a:$AGENT_A_SECRET \
  -d grant_type=client_credentials \
  -d audience=agent-b
```

```json
{ "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300 }
```

The access token says:

```json
{
  "iss": "https://idp.example.com/acme",
  "aud": "agent-b",
  "sub": "agent-a",
  "client_id": "agent-a",
  "ark_claims": ["orders.read"],
  "iat": 1790000000, "exp": 1790000300, "jti": "…"
}
```

With a client library the request, the cache and the renewal are one call:

```python
token = client.agent_token("agent-b").access_token                       # Python
```
```js
const { accessToken } = await client.agentToken({ audience: 'agent-b' }); // Node
```
```csharp
var result = await agentTokens.GetTokenAsync("agent-b");                 // .NET — inject ArkAgentTokens
```

`resource` (RFC 8707) is read the same way as `audience`. A token is addressed to exactly one
agent, so sending two is refused.

## Calling an agent on behalf of a user

Token exchange (RFC 8693). The caller presents the user's token and names the next agent:

```bash
curl -s https://idp.example.com/acme/oauth2/token \
  -u web-app:$WEB_APP_SECRET \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=$USER_ACCESS_TOKEN \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=agent-a
```

```json
{
  "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "scope": "profile email"
}
```

```json
{
  "aud": "agent-a",
  "sub": "alice@example.com",
  "client_id": "web-app",
  "act": { "sub": "web-app" },
  "ark_claims": ["a.use"],
  "scope": "profile email",
  "sid": "…"
}
```

`agent-a` can hand the user on in turn, presenting the token it was sent. `act` grows by one level
each time, newest first:

```json
{ "aud": "agent-b", "sub": "alice@example.com", "client_id": "agent-a",
  "act": { "sub": "agent-a", "act": { "sub": "web-app" } },
  "ark_claims": ["orders.read"] }
```

```python
# Python — in a Flask view of the signed-in app, or pass any subject_token yourself
token = current_ark.agent_token("agent-a")
token = client.agent_token("agent-b", subject_token=incoming_token).access_token
```
```js
// Node — in an Express handler of the signed-in app, or pass any subjectToken yourself
const token = await req.ark.agentToken('agent-a');
const { accessToken } = await client.agentToken({ audience: 'agent-b', subjectToken: incomingToken });
```
```csharp
// .NET — the signed-in user's token, or inside an agent the bearer token it was called with
var token = await HttpContext.GetArkAgentTokenAsync("agent-b");
```

What the server holds this to:

| Rule | Why |
|---|---|
| The presented token must be **addressed to the caller**, or have been **issued to it** at sign-in. | Every API in a tenant is handed access tokens all day. None of them can turn a caller's token into one for somewhere else. |
| The token must carry a **user**. A client's own token is refused. | Delegation carries a person. An agent with nobody to carry calls the next agent as itself. |
| The target must list the caller with **may act for users**. | Calling as itself and bringing a user along are separate permissions. |
| The **user must have access** to the target, and the token carries the user's own claims there. | An agent never widens what a person can do. |
| The user's **account is active** and their **session has not ended**. | Signing out, or being deactivated, ends what agents can do in that person's name. |
| The new token **never outlives** the one it was exchanged for. | When the user's token dies, so does everything derived from it, however far down the chain. |
| **Scope** is what the presented token held, without `openid` and `offline_access`. `scope` on the request may narrow it, never widen it. | |
| At most `A2AMaxDelegationDepth` agents in a chain (4 by default). | A loop between agents ends. |

No refresh token and no ID token are ever issued for either kind of request. When a token expires,
ask again.

## Receiving a call

An agent accepts a token only if all of these hold: the signature verifies against the issuer's
JWKS, `iss` is the issuer, the header says `typ: at+jwt`, it has not expired, and **`aud` is the
agent's own client_id**. The last check is the one that makes a token minted for one agent useless
at the next, and the client libraries fix it for you:

```python
# Python (Flask)
from ark_oauth_client.flask import add_ark_agent_api, current_ark
agent = add_ark_agent_api(app, "/a2a", authority=AUTHORITY, client_id="agent-b", client_secret=SECRET)

@app.post("/a2a/tasks")
@agent.require(claims=["orders.read"])
def tasks():
    current_ark.sub       # "agent-a", or the user it acts for
    current_ark.actors    # [] when the caller acts as itself; else newest first: ["agent-a", "web-app"]
```
```js
// Node (Express)
import { arkBearer } from 'ark-oauth-client-node';
const agent = arkBearer({ authority, clientId: 'agent-b', clientSecret, agent: true });
app.post('/a2a/tasks', agent, agent.require({ claims: ['orders.read'] }), (req, res) => {
  req.ark.sub; req.ark.actors;
});
```
```csharp
// .NET
builder.Services.AddAuthentication().AddArkAgentApi(config);   // config: Authority + ClientId (+ ClientSecret to call onward)
app.MapPost("/a2a/tasks", [Authorize] (ClaimsPrincipal user) => new { sub = user.FindFirst("sub")?.Value, actors = user.ArkActors() });
```

Without a library, `verify_agent_token` / `verifyAgentToken` do the same check on a token you hold.

Decide on `ark_claims`, as for any caller. Read `act` when it matters *which agent* is acting: the
first entry is the agent that called you. Answer a missing or bad token with 401 and a
`WWW-Authenticate: Bearer` challenge, and a valid token that may not do this with 403; the library
guards do both.

To ask the server instead of verifying locally, introspect (RFC 7662). The agent a token is
addressed to may introspect it, as may the client that obtained it; the answer carries `act` and
`ark_claims`, and is `active: false` once the session behind a delegated token has ended.

## The Agent Card

An A2A agent publishes a card at `/.well-known/agent-card.json` that says, among other things, how
to authenticate to it. For an agent secured by this server that section is the same for every agent
of the tenant, so the server writes it:

```
GET {issuer}/a2a/agent-card-security            A2A 1.0: securitySchemes + securityRequirements
GET {issuer}/a2a/agent-card-security?spec=0.3   A2A 0.3: securitySchemes + security
```

```json
{
  "securitySchemes": {
    "ark": {
      "oauth2SecurityScheme": {
        "description": "An OAuth 2.0 access token from this issuer, addressed to this agent: …",
        "flows": { "clientCredentials": { "tokenUrl": "https://idp.example.com/acme/oauth2/token", "scopes": {} } },
        "oauth2MetadataUrl": "https://idp.example.com/acme/.well-known/oauth-authorization-server"
      }
    }
  },
  "securityRequirements": [ { "schemes": { "ark": { "list": [] } } } ]
}
```

Merge it into the card you serve. It is public, names no client, and holds nothing secret.
`client.agent_card_security()`, `client.agentCardSecurity()` and
`ArkAgentTokens.GetAgentCardSecurityAsync()` fetch it. Tell callers your client_id as well: it is
the `audience` they ask for.

## When a request is refused

Errors are the standard token-endpoint shape, `{"error", "error_description"}`, HTTP 400.

| `error` | Meaning | Fix |
|---|---|---|
| `invalid_target` | The audience is not an agent this client may call: it does not exist, is deactivated, or has not listed the caller. The three are deliberately indistinguishable. | List the caller on the target client. |
| `invalid_target` — "…but not on behalf of a user" | The caller is listed, without *may act for users*. | Tick it on the target client. |
| `invalid_target` — "…has no access to…" | The user has no access mapping to the target. | Map the user to the target client. |
| `invalid_target` — "…exactly one agent" | Two audiences in one request. | One token per agent. |
| `unauthorized_client` | The caller is not registered for the grant. | Add `client_credentials` or `token-exchange` to its grants. |
| `invalid_grant` | The presented token is expired, not from this issuer, not an access token, not the caller's to exchange, carries no user, belongs to a deactivated account or an ended session, or the chain is too long. The description says which. | |
| `invalid_scope` | The request asked for a scope the presented token does not hold, or one the caller is not registered for. | |
| `invalid_request` | `subject_token`, `subject_token_type` or `audience` is missing; or `actor_token` was sent (the actor is always the authenticated client). | |
| `unsupported_grant_type` | A2A is switched off on this server. | |

## The audit trail

Every agent-to-agent event is recorded, for whoever has to answer afterwards *which agent acted,
for which person, against which agent, and was it allowed*. There are two places it goes.

**The server's own trace** (`audit_trace`, when `EnableLogTrace` is on) gets a row for each token
issued (`token`), each one refused (`a2a_refused`) and each agent token introspected
(`a2a_introspect`). A change to who may call an agent (`a2a_callers`) and to the agent mark
(`a2a_agent`) is written whatever `EnableLogTrace` says, with who made it and from where.

**An ARK-RAPID Watch audit server**, when one is configured (`ark_oauth_server:Watch`, or the
*Audit trail* step of the setup wizard — see the README). There the same events are structured,
tamper evident and searchable, under the domain `Agents`:

| `action` | When | Level, outcome |
|---|---|---|
| `agent_token.issue` | `client_credentials` + `audience`: an agent asked for a token to call another as itself | `Notice` / `Success`; refused: `Security` / `Denied` |
| `agent_token.exchange` | token exchange: an agent asked for a token to call another on behalf of a user | `Security` / `Success`; refused: `Security` / `Denied` |
| `agent_token.introspect` | an agent asked whether a token addressed to an agent is still good | `Info` / `Success` when active; `Security` / `Denied` when not |
| `agent_callers.update` | the list of who may call an agent changed | `Security` / `Success` |
| `agent.mark`, `agent.unmark` | a client was marked as an agent, or the mark was removed | `Notice` / `Success` |

The **participant** is always the agent that made the request (type `service`), because it is the
one that acted; for a change in the console it is the operator who made it. The **resource** is the
agent it wanted to reach (`agent`, its client_id), or the token asked about (`agent_token`, its
`jti`). The rest is in the attributes:

| Attribute | On | |
|---|---|---|
| `mode` | all token events | `as_itself` or `on_behalf_of` |
| `caller`, `target`, `target_name` | token events | the two agents. `target` is absent from a refusal until the caller has been found on the target's list: until then the record keeps only `requested_audience`, exactly as the caller was told nothing |
| `on_behalf_of` | delegation | the user the agent acted for |
| `actors`, `delegation_depth` | delegation | the whole `act` chain, newest first, and its length |
| `token_id` | issued | the new token's `jti`. Tokens are named, never carried |
| `subject_token_id`, `subject_token_issued_to`, `subject_token_audiences`, `subject_token_expires_at` | delegation | the token that was presented for exchange |
| `subject_token_held_as` | delegation | why this agent could exchange it: `issued_to_actor` or `addressed_to_actor` |
| `session` | delegation | the user's session (`sid`), which ends everything done in their name |
| `scopes`, `requested_scopes`, `claims` | token events | what was asked for, and the `ark_claims` the token carries at the target |
| `expires_at`, `lifetime_seconds` | issued | |
| `error`, `error_description`, `status` | refused | what the caller was sent back |
| `relation`, `active`, `reason` | introspection | why the asker was answered (`addressed_to_caller`, `issued_to_caller`, `resource_server`, or `none`), and why a token was not active |
| `added`, `removed`, `changed`, `callers`, `delegating_callers`, `delegation_granted` | `agent_callers.update` | each entry with its claims and whether it may act for users, before and after |
| `client_auth_method`, `grant_type`, `caller_is_agent`, `user_agent` | token events | how the request was made |

Every event also carries the caller's address, the tenant, a `correlation_id` and — when the
request arrived inside a W3C trace — its `trace_id` and `span_id`.

**Following one user through a chain of agents.** Each hop names the token it was exchanged from,
so the chain is a linked list: start from the user's sign-in (`user.signin`, then `token.issue`),
find the `agent_token.exchange` whose `subject_token_id` is that token's `jti`, then the one whose
`subject_token_id` is *its* `token_id`, and so on. Or filter by `session`: every delegated token of
one sign-in shares it, and the `session.end` event marks where it all stopped.

**Tying it to your own agents' records.** Send `X-Correlation-ID` (letters, digits, `-`, `_`, `.`,
`:`; up to 128) on the token request and it becomes the event's `correlation_id`; send a
`traceparent` and the event joins that trace. An agent that uses the same value in its own audit
client has one trail across both.

**What the server cannot see.** It records that a token was issued and that it was asked about.
The call from one agent to the other does not pass through it, so the *receiving* agent is the
only one that can record "I was called, by this agent, for this user, and did this". Log it there
with the token's `jti` as the resource id, and it lines up with the `token_id` above.

## Settings

Under `ark_oauth_server:Oidc`, all optional:

| Setting | Default | |
|---|---|---|
| `EnableA2A` | `true` | Off: the token endpoint ignores `audience`, token exchange is an unsupported grant, the card endpoint answers 404 and discovery does not list the grant — the server as it was before the feature. |
| `A2ATokenLifetimeSeconds` | `300` | The longest an agent token lives. The caller's own access-token lifetime applies when shorter. |
| `A2AMaxDelegationDepth` | `4` | How many agents may hand a user on, one to the next. |

Discovery lists `urn:ietf:params:oauth:grant-type:token-exchange` in `grant_types_supported` while
it is on.

## What it does not do

* **No cross-tenant calls.** A tenant's agents talk to that tenant's agents.
* **An agent's own identity is not carried down a chain.** `agent-a → agent-b → agent-c` as
  themselves is two separate calls, and `agent-c` sees `agent-b`. Only a user is carried.
* **A public client cannot be an agent.** Nothing authenticates it, so nothing could name it as the
  actor. A browser or mobile app calls its own back end, and the back end is the agent.
* **Tokens are bearer tokens.** They are short-lived and bound to one audience, not to a key
  (no DPoP or mTLS binding).
* **Dynamic client registration cannot grant any of this.** The caller list and the token-exchange
  grant are set by an operator, in the console or through the management API.

## Upgrading

Nothing to do. The first start adds two nullable columns, `clients.a2a_callers_` and
`clients.is_agent`, through the usual schema sync. One behaviour to know about: a `client_credentials` request that sends an `audience`
or `resource` naming something other than the tenant's own audience used to have the parameter
ignored, and is now answered `invalid_target` unless it names an agent the caller may call. Set
`Oidc:EnableA2A` to `false` to keep the old behaviour.
