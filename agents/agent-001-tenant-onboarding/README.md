# Agent 001 · Ark Pilot: tenant onboarding by conversation

An agent that sets an Ark identity server up, in place of a person stepping through the setup wizard.

It is part of the identity server: `Ark.oAuth.Oidc` references it, registers it, and carries its assembly in
the package. It runs as a background service while the server is unconfigured. It takes the server's setup code
the moment the server announces it, uses that code as the bearer token for the server's
[MCP setup tools](../../Ark.oAuth.Oidc/Ark.oAuth.Oidc/MCP.md), and gives people a chat page instead of
a form. People say what they know in any order, paste what they have, and hand the parts they do not
know to the colleague who does. The agent files, tests, chases and finally installs, when the person
running the setup has read the plan and pressed the button.

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.AddArkIdp();          // the agent included

var app = builder.Build();
app.UseArkIdp();
app.Run();
```

Open the application in a browser: the setup wizard's first page links to the agent view, `/ark-agent`, and
says in short where the conversation stands: how much is in, what is waiting for you, which colleagues have
not answered. Either route finishes the setup. They do not fill each other in: the values of the one that
installs are used.

On a server that is set up, which is nearly every start of nearly every one, nothing of the agent is built: no
HTTP client, no route, no thread that stays (`AgentGate`). `ark_onboarding_agent:Enabled=false` removes it
altogether, and so does switching off the wizard or the MCP setup tools it works with. Run one instance
until setup is finished: the conversation lives in that process.

**In an application that is not the server it sets up**, add it yourself:
`builder.Services.AddArkOnboardingAgent(builder.Configuration)`, with `McpUrl` and `SetupCode` set. It is then
the first thing in that application's pipeline.

| Folder | What it is |
|---|---|
| `Ark.Agents.TenantOnboarding` | The agent: a class library with no package dependency. It does not reference `Ark.oAuth.Oidc`; it talks to the server over MCP |
| `Ark.Agents.TenantOnboarding.Sample` | A zero-configuration identity server that opens on the agent instead of the wizard. `dotnet run`, then https://localhost:7310 |
| `Ark.Agents.TenantOnboarding.Checks` | Checks that need no server and no model: `dotnet run` |

## What a setup looks like

The wizard asks for some forty values over eleven steps. The agent needs four (the organization's name,
the public address, a tenant id, the first administrator), plus the default password for new accounts
unless new people get an activation email: the console creates every account on it and cannot add
anybody without it, so the server lists it as missing and the agent asks for it behind the lock button.
Everything else is a default it will question only when what it hears makes the default wrong.

1. **One message instead of a form.** "We're Northwind Traders, production, it will live at
   id.northwind.example, I'm the first admin, we have a React app, Priya in the DBA team has the
   database." The agent files the company, the administrator and the app's origin, holds the address
   for a confirmation, proposes a tenant id and PostgreSQL, and offers to write to Priya. That is one
   model call.
2. **Paste anything.** An email, a ticket, an `.env` file (drag it onto the box), a connection string.
   A pasted connection string is taken apart before the model sees it: host, port, database and account
   are kept, the password goes straight to the server.
3. **Hand a section to whoever knows it.** "Ask a colleague" makes a link that reaches only the sections
   chosen, and a note ready to send with the server's own questions in it. The colleague gets a short
   chat of their own. What they enter is tested (a database is connected to, a test email is sent),
   recorded under their name and team, and the lead's page updates as they type.
4. **Advice comes as a card, never as a change.** "We are regulated by the FCA, what would you change?"
   produces a list of proposals with reasons (key size, session length, lockout, consent, audit trail),
   each accepted or dismissed with a click.
5. **A plan, then a button.** The plan shows what will be installed, what is assumed, what was tested and
   who supplied what. Install is one button, only the lead has it, and it is refused if anything changed
   after the plan was read.
6. **A hand-over.** The administrator's one-time link and the machine credential are shown once, with
   copy buttons, then forgotten.

The board beside the chat is the same information as a map: every section with its state, who was
asked, who supplied each value. Any value can be set there directly, so nobody is forced to talk.

## What the harness decides, whatever the model says

The model reads and proposes. These are enforced in code (`Brain/AgentBrain.cs`), where a persuasive
sentence cannot change them:

| Rule | How |
|---|---|
| The setup code never leaves the server | It is the bearer token of the agent's own MCP calls. The page, the model and colleagues never receive it, and it is cut out of a message that contains it; cookies and links are signed with a key derived from it slowly (PBKDF2), so a link is no use for guessing it |
| Secrets do not reach the model | Passwords, keys, tokens and connection strings, in sentences, `.env` files, JSON, YAML, XML and addresses, are replaced by placeholders (`[[vault:3]]`) before the prompt is built, and put back when the tool is called. They are recognised by shape: a password that is an ordinary word in a sentence has none. The lock button skips the conversation altogether, and is the safe way |
| A placeholder is its owner's | One works only in the turn of the person whose secret it stands for, and only in a field that is itself secret. A password found in the host application works only in the lead's turn and only for the host it belongs to |
| A secret does not follow a change of address | Pointing the database, the mail server or the audit server somewhere else drops the password stored for the old one when a colleague does it over somebody else's, or when nobody clicked (the model, pasted text). A test would otherwise deliver it |
| A value is taken away only on request | A `null` or a "clear" from the model does nothing unless the person's short message asked for it |
| Nothing is invented | A text value is stored only if somebody typed it (or the environment showed it). A number or a choice the same. Anything else the model produces becomes a proposal to click |
| Yes/no settings are not changed in bulk | The model's reading of one is stored only when the person's message was a short answer. After a long message or a question it is a proposal |
| The two permanent values are confirmed by a person | The public address and the tenant id always go through a confirmation card |
| A colleague reaches only their sections | Checked on every tool call, board edit and test, against the link they came in by. Withdrawing a link, or its running out, ends their session at once. Their turns are not shown the host's environment or the lead's notes, and what they typed does not make a value the lead's |
| Who supplied a value is not the model's to say | `source` is filled in from who is signed in to the conversation, and for a colleague names the link they came by |
| The administrator's password is never collected | They set it themselves through the one-time link |
| Only the lead installs, and only what was reviewed | `setup_complete` is never the model's call; the server refuses a `review_id` that no longer matches |

**Who may talk to it** is the wizard's own rule: on a Development server a browser on the machine itself
is the setup lead; everywhere else the lead enters the setup code once. Whoever finishes setup becomes
the administrator, so this is not relaxed. Over plain http the page moves to the server's https address
when it has one, and says so when it has not.

**What the model is sent**, when there is one: what people type (secrets taken out), their names and
teams, the values on the board that the person talking may see, and on the lead's turns what the agent
found out about the host. With `LookForDatabases: true` that includes the kind, host, database and account
name of database servers in the application's `ConnectionStrings`, never a password. It is off by default,
because the agent comes with every identity server: the connection strings are then not read at all.

## The model

One setting chooses it. With none, the agent runs in **guided mode**: it asks the server's own questions
one at a time and still does the filing, testing, links and install. It also falls back to that for a
turn when the model does not answer. With **ARK-LLM**, a small model, guided mode leads and the model is
only asked to read what code cannot ([below](#ark-llm-a-small-model-on-a-very-small-server)).

```jsonc
"ark_onboarding_agent": {
  "Llm": {
    "Provider": "generic_llm",               // generic_llm | ark_llm | azure_foundry | bedrock | none

    "GenericLLM":   { "Url": "https://<host>/<flow>/api/v1/llm/invoke", "Name": "…", "Email": "…",
                      "Model": "eu.anthropic.claude-sonnet-4-6:aws-anthropic" },

    "ArkLLM":       { "Url": "https://<host>/api/v1/chat", "ApiKey": "…" },

    "AzureFoundry": { "Endpoint": "https://<resource>.services.ai.azure.com", "Deployment": "<name>", "ApiKey": "…",
                      "Api": "auto" },       // chat (OpenAI-compatible, any model) | anthropic (Claude deployments)

    "Bedrock":      { "Region": "eu-central-1", "ModelId": "eu.anthropic.claude-sonnet-4-6", "ApiKey": "…" }
  }
}
```

Keep credentials, and the name and email GenericLLM asks for, out of the repository: user secrets or the
environment (`ark_onboarding_agent__Llm__GenericLLM__Email=…`). Put a key with a `$` in it in single quotes.

```bash
cd Ark.Agents.TenantOnboarding.Sample
dotnet user-secrets set "ark_onboarding_agent:Llm:Provider"         "generic_llm"
dotnet user-secrets set "ark_onboarding_agent:Llm:GenericLLM:Url"   "https://<host>/<flow>/api/v1/llm/invoke"
dotnet user-secrets set "ark_onboarding_agent:Llm:GenericLLM:Name"  "<you>"
dotnet user-secrets set "ark_onboarding_agent:Llm:GenericLLM:Email" "<you@…>"

# or ARK-LLM
dotnet user-secrets set "ark_onboarding_agent:Llm:Provider"         "ark_llm"
dotnet user-secrets set "ark_onboarding_agent:Llm:ArkLLM:Url"       "https://<host>/api/v1/chat"
dotnet user-secrets set "ark_onboarding_agent:Llm:ArkLLM:ApiKey"    '<key>'
```

* **GenericLLM** takes one string, so instructions and the turn travel as one `query`. It allows about 1,000
  tokens for thinking and answer together and ignores a larger limit, so an answer can be cut off,
  sometimes before its first word (measured here on one long prompt: 7 of 12 answers hit the limit and
  3 of the 12 came back empty). The harness is built for that: answers are compact, a cut-off answer
  keeps every action that was complete and drops the half-written one, the rest is asked for again, and
  an empty answer is retried up to three times. The cost is latency on those turns.
* **Azure AI Foundry**: `api-key`, or set `AzureTokenProvider` to a `DefaultAzureCredential` call for
  Entra ID. `Api: auto` uses the Messages route when the deployment's name starts with `claude`.
* **Amazon Bedrock**: the Converse API, the same request for every model Bedrock hosts. A Bedrock API key
  (`ApiKey` or `AWS_BEARER_TOKEN_BEDROCK`), or SigV4 with `AccessKeyId`/`SecretAccessKey` or the standard
  `AWS_*` variables. For a profile or an instance role, set `AwsCredentialsProvider` to your AWS SDK's
  credential chain: the library carries no AWS package.
* **Your own**: register an `IArkAgentModel` and it is used instead (`instructions` and `message` in,
  text out).

Nothing uses a provider's own tool calling. The model answers with one small JSON object (`actions`,
`propose`, `ask`, `say`), which is why the same agent runs on a gateway that accepts a single string.

### ARK-LLM: a small model on a very small server

`POST {Url}` with the context in `message`, the key in `X-API-Key`, and the answer as server-sent events.
The server runs Gemma 2 2B on a CPU, one inference at a time, with a 4,096-token context and nothing
cached between calls. Two things follow.

**The agent is a considerate caller** (`Llm/ArkLlmModel.cs`):

| | Setting under `ArkLLM` | Default |
|---|---|---|
| One call at a time from this process, whoever is talking | | always |
| A pause after each, counted from when the server has finished its own bookkeeping | `PauseSeconds` | 3 |
| The longest prompt; a longer one is refused here, not sent | `MaxPromptChars` | 3600 |
| The longest answer | `MaxAnswerTokens` | 200 |
| Calls in any hour, from everybody together | `MaxCallsPerHour` | 40 |
| How long a turn waits for its place before going on without the model | `MaxWaitSeconds` | 60 |
| How long a call may take | `TimeoutSeconds` | 150 |
| Never retried. After a problem the server is left alone: 30 seconds, doubling to ten minutes, longer if it says so (`Retry-After`) | | always |
| `enableTools: false`. Otherwise the server adds its whole tool catalogue to the prompt, and pasted text could call those tools | | always |
| Streamed, and hung up on only when the answer is complete and the model goes on talking | | always |

**The model is the last thing tried** (`Brain/SmallModel.cs`). No call is made for an answer to the question
just asked, a button, small talk, a connection string, "Priya in the DBA team has the database", the kind of
organization described, or values stated outright ("it will live at …", "the admin is …", "our React app at …"):
code reads those. What is left is one short call per message: a sentence about a setting, or a question about
one, sent with only the settings it touches. Everything read from free text, by code or by the model, goes on a
card to accept; a value that is not in the message, or is not the kind the setting takes, never reaches the card.

A setup with two people, free text and questions made four calls in the test scenario; an ordinary one makes
fewer, often none. Measured on 2026-11-25: 278 prompt tokens and 6.6 seconds for a message, 135 and 3.5 for a
question (the full prompt the larger models get is about 3,600). The server keeps an audit trail of what it is
sent, names and addresses included; secrets are taken out before.

## Settings

All optional, under `ark_onboarding_agent`.

| Setting | Default | |
|---|---|---|
| `Enabled` | `true` | |
| `PathPrefix` | `/ark-agent` | Where the page and its API live |
| `AgentName` | `Ark Pilot` | |
| `GreetAtRoot` | `false` | While the server is not set up, a browser that opens `/` meets the agent instead of the wizard |
| `McpUrl` | this application, `/ark-idp/mcp` | Set it to run the agent in a different application from the identity server |
| `SetupCode` | captured | Needed with `McpUrl`; otherwise taken from the start-up log, or `setup-code.txt` in the data directory |
| `InviteLifetimeHours` | `72` | How long a colleague's link works |
| `QuietAfterHours` | `4` | When an unopened link is flagged on the board |
| `LookForDatabases` | `false` | Whether to look in the application's `ConnectionStrings` for a server identity could share |
| `RedirectToHttps` | `true` | Whether a browser on plain http is sent to the server's https address |

The agent keeps its conversations in `agent-state.json` in the identity server's data directory, beside
the server's own `setup-draft.json`, readable by the server's account only, so a restart loses nothing.
Secrets the agent recognised are never in it, and it is deleted when setup finishes by any route. The
one-time secrets of the hand-over are kept in memory until the lead confirms them, an hour at most.

## How it is built

```
Hosting/AgentRuntime.cs     the background service; the logger provider that captures the setup code; access
Hosting/AgentMiddleware.cs  the page and its API, in front of the setup gate (an unconfigured server answers everything else with its wizard)
Hosting/AgentStatus.cs      where the conversation stands, for the wizard's first page: counts and names, never a value
Mcp/McpClient.cs            JSON-RPC over HTTP to /ark-idp/mcp, bearer = the setup code
Brain/AgentBrain.cs         the harness: a turn, the rules above, guided mode, links, review, install
Brain/Prompt.cs             instructions, each turn's situation, and reading the answer (cut-off answers included)
Brain/Scrubber.cs           takes secrets out of what people type
Brain/Advisor.cs            what can be worked out without asking: the host, the company's name, the browser's address
Brain/Workspace.cs          state and its file; the vault
Brain/SmallModel.cs         what a small model is asked, what code reads instead, and checking the answer
Llm/                        GenericLLM, ARK-LLM, Azure AI Foundry, Bedrock (with SigV4)
wwwroot/                    the page: no framework, no inline script or style (strict CSP)
```

The background service is at work before anyone opens the page: it waits for the server to listen,
takes the code, connects, looks at the host (container, App Service, Kubernetes; databases the
application already uses, if `LookForDatabases` says so), and then keeps the board true to the server every 15 seconds, so values
that arrive through the wizard or another agent show up too.

## Checking it

```bash
cd Ark.Agents.TenantOnboarding.Checks && dotnet run     # 131 checks, no server or model needed
```

Those cover the connectors against the request each gateway expects, ARK-LLM's limits against a fake clock,
SigV4 against the example in the AWS documentation, reading whole and cut-off answers, what code reads for a
small model, and the scrubber.

End to end, against a scratch host with a fresh data directory (never a real identity server):

```bash
cd Ark.Agents.TenantOnboarding.Sample
ark_oauth_server__Setup__DataPath=/tmp/ark-agent-try/data dotnet run     # then open https://localhost:7310
```

Verified on 2026-11-24 and 25 against GenericLLM and a PostgreSQL 16 container: a three-party setup
(lead, a colleague by link, a pasted connection string, security advice, review, install) in seven
model calls, with the database password, the setup code and the one-time secrets confirmed absent from
everything the model was sent; in a browser, in guided mode and with the model, light and dark,
desktop and phone; over https on the development certificate; and with the agent in one application
setting up a server in another (`McpUrl` + `SetupCode`). ARK-LLM: the whole path against a local stand-in that
answers badly on purpose, and against the real server with a handful of calls. **Not tested live:** Azure AI Foundry and Amazon Bedrock (no credentials here; their
requests are checked against a stub), and outgoing email and the audit server (the agent calls the same
`setup_test_email` and `setup_test_audit` tools it uses for the database).

## What it does not do yet

* After the install it stops. The tenant's own MCP endpoint and the machine credential are in the
  hand-over, and registering the first application (`tenant_overview`, `onboard_application`) is the
  natural next agent.
* One identity server, one setup. It does not onboard further tenants on a running server.
* The colleague's link is sent by the lead (copy, or the mail client). The agent does not send mail itself.
* English only.
