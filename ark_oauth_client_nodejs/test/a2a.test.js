import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { ArkOAuthClient } from '../src/client.js';
import { arkBearer } from '../src/express.js';
import { agentActors } from '../src/tokens.js';
import { decodeJwt } from '../src/jwt.js';
import { ArkConfigError, ArkOAuthError, ArkTokenError } from '../src/errors.js';
import { StubIdp } from './stub-idp.js';
import { app, route, serve } from './harness.js';

const CALLBACK = 'http://127.0.0.1:9999/signin-oidc';
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
let idp;

before(async () => {
  idp = await new StubIdp().listen();
  idp.clients['agent-c'] = { secret: 'c-secret', method: 'client_secret_post', redirectUris: [], grants: ['client_credentials', TOKEN_EXCHANGE] };
});
after(async () => {
  await idp.close();
});
beforeEach(() => {
  idp.agents = {};
  idp.userClaimsAt = {};
  idp.grants.length = 0;
  idp.publishAudience = true;
});

/** The web application the user signs in to; any confidential client can be an agent. */
const web = () => new ArkOAuthClient({ authority: idp.issuer, clientId: 'confidential-app', clientSecret: 'top-secret', redirectUri: CALLBACK });
const agent = (clientId = 'post-app', clientSecret = 'post-secret') =>
  new ArkOAuthClient({ authority: idp.issuer, clientId, clientSecret, tokenEndpointAuthMethod: 'client_secret_post' });

async function userToken(client) {
  const tx = await client.createAuthorizationUrl();
  const authorize = await fetch(tx.url, { redirect: 'manual' });
  const params = Object.fromEntries(new URL(authorize.headers.get('location')).searchParams);
  return (await client.handleCallback(params, tx)).accessToken;
}

const rejectsWith = (error) => (thrown) => thrown instanceof ArkOAuthError && thrown.error === error;

describe('an agent calling another agent as itself', () => {
  test('the token is addressed to the target, carries what the target granted, and is cached', async () => {
    idp.agents = { 'post-app': { 'confidential-app': { claims: ['orders.read'] } } };
    const caller = web();

    const tokens = await caller.agentToken({ audience: 'post-app' });
    const { payload } = decodeJwt(tokens.accessToken);
    assert.equal(payload.aud, 'post-app');
    assert.equal(payload.sub, 'confidential-app');
    assert.deepEqual(payload.ark_claims, ['orders.read']);
    assert.deepEqual(agentActors(payload), []);
    assert.ok(tokens.expiresIn() <= 300, 'agent tokens are short-lived');
    assert.deepEqual(idp.grants, ['client_credentials']);

    assert.equal(await caller.agentToken({ audience: 'post-app' }), tokens, 'a live token is served from the cache');
    assert.notEqual(await caller.agentToken({ audience: 'post-app', force: true }), tokens);
    // The ordinary client credentials token is a different one, addressed to the tenant's APIs.
    assert.equal(decodeJwt((await caller.clientCredentials()).accessToken).payload.aud, 'test_idp_api');
  });

  test('the target verifies it; another agent refuses it', async () => {
    idp.agents = { 'post-app': { 'confidential-app': { claims: ['orders.read'] } } };
    const token = (await web().agentToken({ audience: 'post-app' })).accessToken;

    const payload = await agent().verifyAgentToken(token, { arkClaims: ['orders.read'] });
    assert.equal(payload.sub, 'confidential-app');
    await assert.rejects(() => agent('agent-c', 'c-secret').verifyAgentToken(token), /post-app/);
    await assert.rejects(() => agent().verifyAgentToken(token, { arkClaims: ['orders.write'] }), rejectsWith('insufficient_scope'));
  });

  test('a caller the target has not listed is refused', async () => {
    await assert.rejects(() => web().agentToken({ audience: 'post-app' }), rejectsWith('invalid_target'));
  });

  test('a public client cannot be an agent, and an audience is required', async () => {
    const spa = new ArkOAuthClient({ authority: idp.issuer, clientId: 'web-app', redirectUri: CALLBACK });
    await assert.rejects(() => spa.agentToken({ audience: 'post-app' }), (e) => e instanceof ArkConfigError && /confidential client/.test(e.message));
    await assert.rejects(() => web().agentToken({}), (e) => e instanceof ArkConfigError);
  });
});

describe('an agent acting on behalf of a user', () => {
  test('the user is handed from agent to agent, and act records the way', async () => {
    idp.agents = {
      'post-app': { 'confidential-app': { delegateUsers: true } },
      'agent-c': { 'post-app': { delegateUsers: true } }
    };
    idp.userClaimsAt = { 'post-app': ['orders.read'], 'agent-c': ['c.use'] };
    const first = await web().agentToken({ audience: 'post-app', subjectToken: await userToken(web()) });
    assert.equal(idp.grants.at(-1), TOKEN_EXCHANGE);
    assert.equal(first.raw.issued_token_type, 'urn:ietf:params:oauth:token-type:access_token');

    const atB = await agent().verifyAgentToken(first.accessToken, { arkClaims: ['orders.read'] });
    assert.equal(atB.sub, 'alice@example.com', 'the subject is still the user');
    assert.deepEqual(agentActors(atB), ['confidential-app']);

    const second = await agent().agentToken({ audience: 'agent-c', subjectToken: first.accessToken });
    const atC = await agent('agent-c', 'c-secret').verifyAgentToken(second.accessToken);
    assert.equal(atC.sub, 'alice@example.com');
    assert.deepEqual(atC.ark_claims, ['c.use'], "the user's own claims at the target");
    assert.deepEqual(agentActors(atC), ['post-app', 'confidential-app']);
    assert.ok(atC.exp <= atB.exp, 'never outlives the token it was exchanged for');
  });

  test('each user gets their own cached token', async () => {
    idp.agents = { 'post-app': { 'confidential-app': { delegateUsers: true } } };
    idp.userClaimsAt = { 'post-app': [] };
    const client = web();
    const alice = await userToken(client);
    const forAlice = await client.agentToken({ audience: 'post-app', subjectToken: alice });
    assert.equal(await client.agentToken({ audience: 'post-app', subjectToken: alice }), forAlice);

    const original = idp.user;
    idp.user = { ...original, sub: 'bob@example.com', email: 'bob@example.com' };
    try {
      const forBob = await client.agentToken({ audience: 'post-app', subjectToken: await userToken(client) });
      assert.equal(decodeJwt(forBob.accessToken).payload.sub, 'bob@example.com');
      assert.equal(decodeJwt(forAlice.accessToken).payload.sub, 'alice@example.com');
    } finally {
      idp.user = original;
    }
  });

  test("delegation needs the target's permission and the user's access", async () => {
    const client = web();
    const subjectToken = await userToken(client);

    idp.agents = { 'post-app': { 'confidential-app': { claims: ['x'] } } }; // itself only
    idp.userClaimsAt = { 'post-app': [] };
    await assert.rejects(() => client.agentToken({ audience: 'post-app', subjectToken }), rejectsWith('invalid_target'));

    idp.agents = { 'post-app': { 'confidential-app': { delegateUsers: true } } };
    idp.userClaimsAt = {}; // the user has no access to the target
    await assert.rejects(() => client.agentToken({ audience: 'post-app', subjectToken }), rejectsWith('invalid_target'));
  });

  test('a token meant for someone else, or carrying no user, cannot be exchanged', async () => {
    idp.agents = { 'agent-c': { 'post-app': { delegateUsers: true } } };
    idp.userClaimsAt = { 'agent-c': [] };
    const issuedToSomeoneElse = await userToken(web());
    await assert.rejects(() => agent().agentToken({ audience: 'agent-c', subjectToken: issuedToSomeoneElse }), rejectsWith('invalid_grant'));

    const own = (await agent().clientCredentials()).accessToken;
    await assert.rejects(() => agent().agentToken({ audience: 'agent-c', subjectToken: own }), rejectsWith('invalid_grant'));
  });
});

describe('the agent card and the bearer guard', () => {
  test('the security section of the agent card comes from the provider', async () => {
    const client = web();
    const card = await client.agentCardSecurity();
    assert.equal(card.securitySchemes.ark.oauth2SecurityScheme.flows.clientCredentials.tokenUrl, (await client.metadata()).token_endpoint);
    assert.deepEqual(card.securityRequirements, [{ schemes: { ark: { list: [] } } }]);

    const older = await client.agentCardSecurity({ spec: '0.3' });
    assert.equal(older.securitySchemes.ark.type, 'oauth2');
    assert.deepEqual(older.security, [{ ark: [] }]);
  });

  test('arkBearer({ agent: true }) accepts only tokens addressed to this agent', async () => {
    idp.agents = {
      'post-app': { 'confidential-app': { claims: ['orders.read'], delegateUsers: true } },
      'agent-c': { 'confidential-app': { claims: ['orders.read'] } }
    };
    idp.userClaimsAt = { 'post-app': ['orders.read'] };

    const guard = arkBearer({ client: agent(), agent: true, claims: ['orders.read'] });
    const server = app(
      guard,
      route('/a2a/tasks', (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ sub: req.ark.sub, actors: req.ark.actors }));
      })
    );
    const origin = await serve(server);
    const call = (token) => fetch(`${origin}/a2a/tasks`, { method: 'POST', headers: token ? { authorization: `Bearer ${token}` } : {} });

    try {
      const client = web();
      const asItself = await call((await client.agentToken({ audience: 'post-app' })).accessToken);
      assert.equal(asItself.status, 200);
      assert.deepEqual(await asItself.json(), { sub: 'confidential-app', actors: [] });

      const forAlice = await call((await client.agentToken({ audience: 'post-app', subjectToken: await userToken(client) })).accessToken);
      assert.deepEqual(await forAlice.json(), { sub: 'alice@example.com', actors: ['confidential-app'] });

      const elsewhere = await call((await client.agentToken({ audience: 'agent-c' })).accessToken);
      assert.equal(elsewhere.status, 401);
      assert.match(elsewhere.headers.get('www-authenticate'), /invalid_token/);

      assert.equal((await call(null)).status, 401);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

describe('an API that is not an agent', () => {
  const listed = () => {
    idp.agents = { 'post-app': { 'confidential-app': { claims: ['orders.read'], delegateUsers: true } } };
    idp.userClaimsAt = { 'post-app': ['orders.read'] };
  };

  // An API that was told no audience checks the tenant's. Without that it took a token meant for one
  // agent as readily as its own, and whoever was handed one could replay it as the user it names.
  test('refuses a token addressed to an agent', async () => {
    listed();
    const bearer = arkBearer({ authority: idp.issuer, clientId: 'payroll-api' });
    const server = app(bearer, (req, res) => res.end('payroll'));
    const origin = await serve(server);
    const call = async (token) => (await fetch(origin, { headers: { authorization: `Bearer ${token}` } })).status;
    try {
      const client = web();
      assert.equal(await call(await userToken(client)), 200, 'an ordinary token of this tenant');
      assert.equal(await call((await client.agentToken({ audience: 'post-app' })).accessToken), 401);
      assert.equal(await call((await client.agentToken({ audience: 'post-app', subjectToken: await userToken(client) })).accessToken), 401);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  test('refuses a delegated token even where an older provider publishes no audience', async () => {
    listed();
    idp.publishAudience = false;
    const client = web();
    const api = new ArkOAuthClient({ authority: idp.issuer, clientId: 'payroll-api' });

    assert.equal((await api.verifyAccessToken(await userToken(client))).sub, 'alice@example.com');
    const delegated = (await client.agentToken({ audience: 'post-app', subjectToken: await userToken(client) })).accessToken;
    await assert.rejects(() => api.verifyAccessToken(delegated), (e) => e instanceof ArkTokenError && /issued to an agent/.test(e.message));
    // Told which audience to expect, it is that check and nothing else.
    assert.deepEqual((await api.verifyAccessToken(delegated, { audience: 'post-app' })).act, { sub: 'confidential-app' });
  });

  // Both carry this client's id as their audience; the type header is all that tells them apart.
  test('an ID token is no agent token, even with the type check off', async () => {
    const client = web();
    const tx = await client.createAuthorizationUrl();
    const authorize = await fetch(tx.url, { redirect: 'manual' });
    const { idToken } = await client.handleCallback(Object.fromEntries(new URL(authorize.headers.get('location')).searchParams), tx);

    await assert.rejects(() => client.verifyAgentToken(idToken, { requireTypeHeader: false }), /at\+jwt/);
    const guard = arkBearer({ client, agent: true, requireTypeHeader: false });
    const server = app(guard, (req, res) => res.end('in'));
    const origin = await serve(server);
    try {
      assert.equal((await fetch(origin, { headers: { authorization: `Bearer ${idToken}` } })).status, 401);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
