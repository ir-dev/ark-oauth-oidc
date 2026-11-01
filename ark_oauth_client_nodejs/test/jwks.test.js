import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { JwksCache } from '../src/jwks.js';

let server;
let url;
let fetches = 0;
let keys = [];

function key(kid) {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };
}

before(async () => {
  keys = [key('key-1')];
  server = createServer((req, res) => {
    fetches += 1;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ keys }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${server.address().port}/jwks.json`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('the document is fetched once and served from cache', async () => {
  fetches = 0;
  const cache = new JwksCache(url);
  assert.equal((await cache.getSigningKey('key-1', 'RS256')).kid, 'key-1');
  await cache.getSigningKey('key-1', 'RS256');
  await cache.keys();
  assert.equal(fetches, 1);
});

test('concurrent misses collapse into one request', async () => {
  fetches = 0;
  const cache = new JwksCache(url);
  await Promise.all(Array.from({ length: 20 }, () => cache.getSigningKey('key-1', 'RS256')));
  assert.equal(fetches, 1);
});

test('an unknown kid triggers exactly one refetch, and repeats trigger none', async () => {
  fetches = 0;
  const cache = new JwksCache(url, { minRefreshIntervalMs: 0 });
  await cache.getSigningKey('key-1', 'RS256'); // warm
  assert.equal(fetches, 1);

  await assert.rejects(() => cache.getSigningKey('bogus', 'RS256'), /no key with kid 'bogus'/);
  assert.equal(fetches, 2, 'the first sight of an unknown kid is worth a refetch');

  // Repeats of a kid already known to be absent must not become traffic: otherwise a stream of
  // forged tokens turns this client into a request amplifier pointed at the identity server.
  for (let i = 0; i < 25; i += 1) {
    await assert.rejects(() => cache.getSigningKey('bogus', 'RS256'));
  }
  assert.equal(fetches, 2);
});

test('a rotation is picked up on the first token signed by the new key', async () => {
  fetches = 0;
  const cache = new JwksCache(url, { minRefreshIntervalMs: 0 });
  await cache.getSigningKey('key-1', 'RS256');

  keys = [key('key-2'), keys[0]]; // active first, previous still published
  assert.equal((await cache.getSigningKey('key-2', 'RS256')).kid, 'key-2');
  assert.equal((await cache.getSigningKey('key-1', 'RS256')).kid, 'key-1', 'tokens in flight keep validating');
});

test('the refetch is rate-limited between rotations', async () => {
  fetches = 0;
  const cache = new JwksCache(url, { minRefreshIntervalMs: 60_000 });
  await cache.getSigningKey('key-1', 'RS256');
  await assert.rejects(() => cache.getSigningKey('unseen', 'RS256'));
  assert.equal(fetches, 1, 'a fetch seconds ago is recent enough to be trusted');
});

test('a kid-less token resolves only when one key is published', async () => {
  keys = [key('key-a'), key('key-b')];
  const ambiguous = new JwksCache(url, { minRefreshIntervalMs: 0 });
  await assert.rejects(() => ambiguous.getSigningKey(undefined, 'RS256'), /ambiguous/);

  keys = [key('only')];
  const single = new JwksCache(url);
  assert.equal((await single.getSigningKey(undefined, 'RS256')).kid, 'only');
});

test('a key of the wrong type for the algorithm is not offered', async () => {
  keys = [key('rsa-key')];
  const cache = new JwksCache(url, { minRefreshIntervalMs: 0 });
  await assert.rejects(() => cache.getSigningKey('rsa-key', 'ES256'), /no key with kid/);
});
