# MCP: this server as tools for an agent

The identity server is itself an MCP (Model Context Protocol) server. An agent can set it up, run it,
administer a tenant, or look after one application, at the level its credential reaches and no further.

| Level | Address, and the `resource` of its tokens | For | Credential |
|---|---|---|---|
| Setup | `{root}/ark-idp/mcp`, while the server is unconfigured | Whoever sets it up | The setup code, as the bearer token |
| Host | `{root}/ark-idp/mcp`, once it is configured | The operator | A token of the operator tenant's machine client |
| Tenant | `{root}/{tenant_id}/mcp` | That tenant's administrator | A token of `{tenant_id}_machine` |
| Client | `{root}/{tenant_id}/mcp/{client_id}` | That application, its people, the agents it lists | A token from any flow the application is registered for |

It is on by default. Nothing answers a tool call without one of these credentials. Turn it off, or parts
of it, under [Settings](#settings).

## Discovery

Beside every endpoint, public and without a secret:

| Document | Address |
|---|---|
| Server card: what it is, which phase (`setup` or `ready`), how to authenticate, where the other levels are | `{endpoint}/server-card` |
| Configuration: the `mcpServers` block, and the token request for an unattended agent | `{endpoint}/config` |
| Protected resource metadata (RFC 9728) | `{root}/.well-known/oauth-protected-resource/{path of the endpoint}` |

The first two are there as soon as the setup wizard is: before there is a tenant, a database or an issuer.
After setup the third is named in every `401`, and the issuer's discovery document lists the tenant's
endpoint under `protected_resources`. The server card follows SEP-2127, whose format is not final; what is
specific to this server is under `_meta`.

## Setting a server up

Start the server with nothing configured. Its log prints the setup code and the address:

```
Ark IdP is not configured yet. Open /ark-idp/setup on this server in a browser …
An agent can set it up instead: connect it to the MCP server at /ark-idp/mcp with the setup code XXXX-XXXX-XXXX as its bearer token.
```

```json
{ "mcpServers": { "ark-idp-setup": {
    "type": "http", "url": "https://id.example.com/ark-idp/mcp",
    "headers": { "Authorization": "Bearer ${ARK_SETUP_CODE}" } } } }
```

The agent collects one section at a time, in any order, over as many conversations as it takes. Every
section names the department that usually has the answer and the question to ask, and every value keeps
who supplied it.

| Tool | |
|---|---|
| `setup_status` | Every section: complete, missing or wrong, whom to ask, what to do next |
| `setup_fields` | Every value: meaning, question, default, and what is stored |
| `setup_set_organization`, `_server`, `_database`, `_signing_key`, `_administrator`, `_users`, `_email`, `_protocol`, `_management`, `_audit`, `_branding` | Store values, each with a `source` (department, provided_by, reference, note) |
| `setup_clear` | Forget a section |
| `setup_test_database`, `setup_test_email`, `setup_test_audit` | Prove the settings before they are used |
| `setup_review` | The whole plan, what is assumed, who supplied what, everything that would stop it, and a `review_id` |
| `setup_complete` | Installs exactly the draft that was reviewed |

Only `company_name`, `base_url`, `tenant_id` and the administrator's `username` are required. The checks
are the wizard's own. `setup_complete` needs the `review_id` of the draft as it stands and the tenant id
repeated, so a value changed after a person agreed to the plan stops the install.

**What an agent never has to hold.** Leave the administrator's password out: the account starts on a random
one, and `setup_complete` returns a one-time link with which the administrator sets their own. The signing
key is generated inside the server. The database and SMTP passwords are held in `setup-draft.json` in the
data directory (readable only by the server's account, git-ignored, deleted when setup finishes by either
route), because they end up in `settings.json` there anyway. A password, imported key or machine secret that
is supplied anyway stays in memory and has to be given again after a restart.

`setup_complete` answers with the issuer, the machine credential (once), the administrator's link (once) and
the configuration of the tenant's own MCP server. From then on the setup code opens nothing.

The setup code is always required here, also from localhost, and a browser's `Origin` is refused: the
wizard's exemption is for a person at the machine.

## After setup: tokens

An unattended agent asks for a token addressed to the endpoint, with the machine credential:

```bash
curl -X POST https://id.example.com/acme/oauth2/token \
  -d grant_type=client_credentials -d client_id=acme_machine -d client_secret=$SECRET \
  -d resource=https://id.example.com/acme/mcp -d scope='mcp.read mcp.manage'
```

The MCP SDKs do this themselves with their client-credentials providers. The machine client is registered for
`client_secret_post`, and this server holds a client to its registered method: the Python provider takes
`token_endpoint_auth_method="client_secret_post"`; the TypeScript one only speaks `client_secret_basic`, so
override its `clientInformation()` to return `token_endpoint_auth_method: 'client_secret_post'` with the id and
secret, or use the header below. Tested with Python 2.3.0, TypeScript 1.32.2 and C# 2.4.0.

* **`resource` decides the audience (RFC 8707).** The token's `aud` is that endpoint, and no other endpoint,
  application or API of the server accepts it. A token without `resource` is an ordinary one and is refused
  here.
* **Scopes say look or change.** `mcp.read` for tools that look, `mcp.manage` for tools that change
  something. Without `mcp.manage` such a tool answers `403` with
  `WWW-Authenticate: Bearer error="insufficient_scope", scope="mcp.read mcp.manage"`, and an MCP client
  asks for the wider token and calls again. The machine client needs neither registered: they are parts of
  `client.register`, which it has. For every other client an operator adds them; `mcp.manage` can never be
  self-registered.
* **Scopes do not say what may be reached.** That is who the token is for, read from the database on each
  call, so taking a claim, a caller, a session or an account away counts at once.

Where only a fixed header can be configured, `Authorization: Basic base64(client_id:client_secret)` opens
the same endpoints (`Mcp:AllowClientSecret`).

### People

Somebody signs in through an MCP client registered in the tenant (`client_create` with kind `mcp_client`)
and needs one more thing: an administrator claim on **their access to that client**.

| Claim | Makes them |
|---|---|
| `ark.host.admin` | Operator of the server. Counts only on a mapping in the operator tenant. Only the operator grants it |
| `ark.tenant.admin` | Administrator of the tenant. Not enough in the operator tenant, whose administrator is the operator |
| `ark.client.admin` | Administrator of that application, at its own endpoint |

An application's own `admin` claim means nothing here. Without one of these, `whoami` says what is missing.

### Applications and agents

At `{root}/{tenant}/mcp/{client_id}`, through whichever flow the application is registered for:

| Who | Flow | Gets |
|---|---|---|
| A person | authorization code with PKCE, PAR, device | `my_profile`, `my_access`, `my_sessions`, `my_sign_out` |
| A person with `ark.client.admin` | the same | The application's people, access and presentation |
| The application itself | client credentials, or its secret as Basic | The same, and its own secret |
| An agent it lists as a caller ([A2A](A2A.md)) | client credentials with this `resource` | What its entry in the list grants |
| An agent acting for a person | token exchange with this `resource` | That person's own standing, with the agents in `act` |

The sign-in must be the application's own: another client is not issued a token for this endpoint unless it
is on the list. The scopes published for it are ones it is registered for, so a stock MCP client never asks
for one that is refused.

## The tools

`tools/list` shows what the caller may call. `whoami` is at every level and works for any token addressed to
the endpoint.

**Host (operator).** `host_overview`; `tenant_list`, `tenant_get`, `tenant_create`, `tenant_update`,
`tenant_machine_secret_reset`; `user_list`, `user_get`, `user_diagnose`, `user_create`, `user_update`,
`user_set_active`, `user_reset_password`, `user_unlock`, `user_sign_out`, `user_set_home`; `scope_list`,
`scope_save`, `scope_delete`; `claim_list`, `claim_save`, `claim_delete`; `audit_search`,
`audit_trail_status`, `settings_get`; and with the webhook module `webhook_list`, `webhook_save`,
`webhook_set_status`, `webhook_test`, `webhook_delete`, `webhook_deliveries`, `webhook_dead_letters`,
`webhook_replay_dead_letters`.

**Tenant (administrator).** `tenant_overview`, `tenant_update`; `client_list`, `client_get`, `client_create`,
`client_update`, `client_set_active`, `client_delete`, `client_secret_reset`, `client_integration`,
`onboard_application`; `agent_caller_list`, `agent_caller_set`, `agent_caller_remove`; `user_list`,
`user_get`, `user_diagnose`, `user_create`, `user_update`, `user_set_active`, `user_reset_password`,
`user_unlock`, `user_sign_out`; `access_list`, `access_grant`, `access_set_claims`, `access_revoke`,
`onboard_user`; `session_list`, `session_end`; `signing_key_list`, `signing_key_rotate`,
`signing_key_retire`; `scope_list`, `claim_list`; `audit_search`.

**Client.** `app_info`; for a person `my_profile`, `my_access`, `my_sessions`, `my_sign_out`; for the
application and its administrators `app_registration`, `app_integration`, `app_update_profile`,
`app_secret_rotate`, `agent_caller_list`, `user_list`, `user_get`, `user_diagnose`, `access_grant`,
`access_set_claims`, `access_revoke`, `onboard_user`, `user_tokens_revoke`, `audit_search`.

`setup_status`, `host_overview` and `tenant_overview` are where an agent starts: each ends in `next_steps`, in
order of urgency, with the tool and the arguments for every step. `user_diagnose` goes through the conditions
of a sign-in in the order the server checks them.

Not here, on purpose: export, import and factory reset, which read every private key or delete everything,
and changing the server's settings. They stay with a person in the console or the host's configuration.

### What keeps an agent in bounds

* A tool that takes something away asks for the name of what it takes away again, in `confirm`.
* New people get a one-time link rather than a password. Secrets and links are returned once, and the
  instructions tell the agent to hand them over first.
* Redirect URIs are never guessed for an application; registration is refused without one.
* A problem the agent can put right comes back as a tool result with `error`, `message` and usually the tool
  that fixes it.
* Every change, and every call refused for want of permission, is written to `audit_trace` whatever
  `EnableLogTrace` says, with the caller, the agents it acted through, the token's `jti` and what was touched.
  Arguments are never recorded. A setup leaves the line `idp_setup` with who supplied what.
  With an audit server configured it is also the event `mcp.tool_call`.

## Tenants and accounts

An account exists once per server, and a person may have access in several tenants. So each account has a
tenant that manages it, `users.home_tenant_id`: the one whose administrators created it, or none, which is
the operator and every account made before. Only that tenant may change it: reset the password, switch it
off. Another tenant may give the person access to its applications and take that away. A tenant's
administrator is told that an account outside the tenant does not exist, except that a username which is
taken cannot be created again. `user_set_home` hands an account over.

`tenant_create` makes the tenant, a signing key and `{tenant_id}_machine`, and returns that client's secret
and the tenant's MCP configuration once. An existing tenant gets one from `tenant_machine_secret_reset`.
The machine client of a tenant other than the operator's opens that tenant's MCP endpoint and nothing else:
the management API still answers only to the operator.

## Registering an agent dynamically

With `Oidc:EnableDynamicRegistration`, an agent registers itself (RFC 7591) with a token of the machine
client that carries `client.register` and has **no** `resource`. It may register for `mcp.read`. It then has
an endpoint of its own, `{root}/{tenant}/mcp/{its client_id}`, and reaches nothing else until an administrator
lists it as a caller or grants its people an administrator claim. `tenant_overview` shows the registration
endpoint. `client_create` with kind `agent` does the same from the administrator's side.

## Settings

```json
"ark_oauth_server": { "Mcp": {
    "Enabled": true,            // false: no endpoint, no metadata; resource at the token endpoint as before
    "HostLevel": true,          // /ark-idp/mcp, setup included
    "TenantLevel": true,        // /{tenant}/mcp
    "ClientLevel": true,        // /{tenant}/mcp/{client_id}
    "ReadOnly": false,          // only the tools that look; setup is not affected
    "AllowClientSecret": true,  // Basic with the machine client's or the application's secret
    "MaxRequestKilobytes": 1536
} }
```

A browser-based MCP client needs its origin in `Oidc:CorsOrigins`; any other `Origin` is refused.

## Protocol

Streamable HTTP, POST only, JSON answers, nothing kept between requests, so it works behind any load
balancer. Revision 2026-07-28, and 2025-11-25, 2025-06-18 and 2025-03-26 with the `initialize` handshake.
Tools only: no prompts, resources, subscriptions or event stream. It is written out in `Mcp/ArkMcpServer.cs`
rather than taken from the MCP SDK, because it answers before the host's routing exists, must not share the
host's own MCP server, and has to answer a missing scope with an HTTP 403.

## Upgrading

Four nullable columns are added on the first start (`auth_codes.resource`, `refresh_tokens.resource`,
`device_codes.resource`, `users.home_tenant_id`) and two scopes join the catalogue. No existing row changes.
The previous release opens the upgraded database.

`resource` used to be ignored on a sign-in. It still is, unless it names one of this server's own MCP
endpoints. On `client_credentials` such a value used to be `invalid_target`.
