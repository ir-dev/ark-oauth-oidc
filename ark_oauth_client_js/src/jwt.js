import { base64UrlDecode, base64UrlDecodeToString, leftHalfHash, subtle } from './crypto.js';
import { ArkTokenError } from './errors.js';

/**
 * JWT decoding, signature verification (Web Crypto) and claim validation.
 *
 * Ark signs with RS256 and publishes its keys at `jwks_uri`. The other JWS families are accepted so
 * the same client works against another provider without a second implementation. `none` is never
 * accepted: an unsigned token is one anyone can write, and every JWT library vulnerability of note
 * came from honouring the `alg` header before deciding which algorithms are acceptable.
 */

const ALGORITHMS = {
  RS256: { kty: 'RSA', hash: 'SHA-256', importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verifyParams: { name: 'RSASSA-PKCS1-v1_5' } },
  RS384: { kty: 'RSA', hash: 'SHA-384', importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, verifyParams: { name: 'RSASSA-PKCS1-v1_5' } },
  RS512: { kty: 'RSA', hash: 'SHA-512', importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, verifyParams: { name: 'RSASSA-PKCS1-v1_5' } },
  PS256: { kty: 'RSA', hash: 'SHA-256', importParams: { name: 'RSA-PSS', hash: 'SHA-256' }, verifyParams: { name: 'RSA-PSS', saltLength: 32 } },
  PS384: { kty: 'RSA', hash: 'SHA-384', importParams: { name: 'RSA-PSS', hash: 'SHA-384' }, verifyParams: { name: 'RSA-PSS', saltLength: 48 } },
  PS512: { kty: 'RSA', hash: 'SHA-512', importParams: { name: 'RSA-PSS', hash: 'SHA-512' }, verifyParams: { name: 'RSA-PSS', saltLength: 64 } },
  // JWS carries ECDSA signatures as raw r||s, which is also what Web Crypto expects.
  ES256: { kty: 'EC', hash: 'SHA-256', crv: 'P-256', importParams: { name: 'ECDSA', namedCurve: 'P-256' }, verifyParams: { name: 'ECDSA', hash: 'SHA-256' } },
  ES384: { kty: 'EC', hash: 'SHA-384', crv: 'P-384', importParams: { name: 'ECDSA', namedCurve: 'P-384' }, verifyParams: { name: 'ECDSA', hash: 'SHA-384' } },
  ES512: { kty: 'EC', hash: 'SHA-512', crv: 'P-521', importParams: { name: 'ECDSA', namedCurve: 'P-521' }, verifyParams: { name: 'ECDSA', hash: 'SHA-512' } }
};

export const SUPPORTED_ALGORITHMS = Object.freeze(Object.keys(ALGORITHMS));

/** The Web Crypto hash an algorithm's `at_hash`/`c_hash` is computed with. */
export function hashForAlgorithm(alg) {
  return ALGORITHMS[alg]?.hash ?? 'SHA-256';
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/**
 * Splits a compact JWS without verifying anything: for reading `kid` before a key is chosen, or a
 * claim for display. Nothing in this library authorises on the result of a decode alone.
 */
export function decodeJwt(token) {
  if (typeof token !== 'string') throw new ArkTokenError('the token is not a string.');
  const parts = token.split('.');
  if (parts.length !== 3) throw new ArkTokenError(`the token is not a compact JWS: expected 3 segments, found ${parts.length}.`);

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecodeToString(parts[0]));
    payload = JSON.parse(base64UrlDecodeToString(parts[1]));
  } catch (cause) {
    throw new ArkTokenError('the token header or payload is not valid JSON.', { cause });
  }
  if (!isObject(header) || !isObject(payload)) throw new ArkTokenError('the token header and payload must both be JSON objects.');

  return { header, payload, signature: base64UrlDecode(parts[2]), signingInput: `${parts[0]}.${parts[1]}` };
}

/**
 * Imports one published JWK for verification. Only the key material is passed on, so a provider's
 * extra members (`x5c`, `key_ops`, an `alg` spelled differently) cannot make the import itself fail;
 * the `alg`/`use`/`kty` checks that matter are made explicitly in verifySignature.
 */
export async function importVerifyKey(jwk, alg) {
  const spec = ALGORITHMS[alg];
  if (!spec) throw new ArkTokenError(`unsupported signing algorithm '${alg}'.`);
  const material = spec.kty === 'RSA' ? { kty: 'RSA', n: jwk.n, e: jwk.e } : { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  try {
    return await subtle().importKey('jwk', { ...material, ext: true }, spec.importParams, false, ['verify']);
  } catch (cause) {
    throw new ArkTokenError(`the published key for kid '${jwk.kid}' could not be imported: ${cause?.message ?? cause}`, { cause });
  }
}

/**
 * Verifies the signature of a decoded token against one JWK.
 *
 * @param {ReturnType<typeof decodeJwt>} decoded
 * @param {object} jwk
 * @param {{ algorithms?: string[], key?: CryptoKey }} [options] `key` is a pre-imported CryptoKey for `jwk`
 */
export async function verifySignature(decoded, jwk, { algorithms, key } = {}) {
  const alg = decoded.header.alg;
  if (!alg || alg === 'none') throw new ArkTokenError(`the token declares alg '${alg ?? 'missing'}'; unsigned tokens are never accepted.`);

  const allowed = algorithms ?? SUPPORTED_ALGORITHMS;
  if (!allowed.includes(alg)) throw new ArkTokenError(`the token is signed with ${alg}, which this client does not accept (allowed: ${allowed.join(', ')}).`);

  const spec = ALGORITHMS[alg];
  if (!spec) throw new ArkTokenError(`unsupported signing algorithm '${alg}'.`);
  if (jwk.kty !== spec.kty) throw new ArkTokenError(`the signing key is a ${jwk.kty} key but the token declares ${alg}.`);
  if (jwk.alg && jwk.alg !== alg) throw new ArkTokenError(`the key published for kid '${jwk.kid}' is registered for ${jwk.alg}, not ${alg}.`);
  if (jwk.use && jwk.use !== 'sig') throw new ArkTokenError(`the key published for kid '${jwk.kid}' is for '${jwk.use}', not signing.`);
  if (spec.crv && jwk.crv !== spec.crv) throw new ArkTokenError(`the key for kid '${jwk.kid}' is on ${jwk.crv}, but ${alg} needs ${spec.crv}.`);

  const cryptoKey = key ?? (await importVerifyKey(jwk, alg));
  const ok = await subtle().verify(spec.verifyParams, cryptoKey, decoded.signature, new TextEncoder().encode(decoded.signingInput));
  if (!ok) throw new ArkTokenError('the token signature does not verify against the published key.');
  return true;
}

/**
 * Validates the registered claims. Skipping any single one of these is how a token meant for
 * another app, another provider or another moment ends up being accepted.
 */
export function validateClaims(payload, options = {}) {
  const {
    issuer,
    audience,
    subject,
    nonce,
    maxAgeSeconds,
    clockToleranceSeconds = 60,
    requireExp = true,
    requireIat = false,
    now = Math.floor(Date.now() / 1000)
  } = options;

  const fail = (message, claim) => {
    throw new ArkTokenError(message, { claim });
  };

  if (issuer) {
    if (!payload.iss) fail('the token has no `iss` claim.', 'iss');
    if (payload.iss !== issuer) fail(`the token was issued by '${payload.iss}', not by '${issuer}'.`, 'iss');
  }

  if (audience) {
    const auds = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    if (auds.length === 0) fail('the token has no `aud` claim.', 'aud');
    if (!auds.includes(audience)) fail(`the token is addressed to ${auds.map((a) => `'${a}'`).join(', ')}, not to '${audience}'.`, 'aud');
    // OIDC Core §3.1.3.7: with several audiences, `azp` must name the party the token is for.
    if (auds.length > 1 && payload.azp && payload.azp !== audience) fail(`the token names '${payload.azp}' as its authorized party, not '${audience}'.`, 'azp');
  }

  if (subject && payload.sub !== subject) fail(`the token belongs to subject '${payload.sub}', not '${subject}'.`, 'sub');

  if (payload.exp === undefined) {
    if (requireExp) fail('the token has no `exp` claim.', 'exp');
  } else if (typeof payload.exp !== 'number' || now >= payload.exp + clockToleranceSeconds) {
    fail(`the token expired at ${new Date((Number(payload.exp) || 0) * 1000).toISOString()}.`, 'exp');
  }

  // A time claim that is not a number compares false against everything and would pass the checks
  // below unnoticed. RFC 7519 §2 makes them NumericDate; anything else is a malformed token.
  for (const claim of ['nbf', 'iat']) {
    if (payload[claim] !== undefined && (typeof payload[claim] !== 'number' || !Number.isFinite(payload[claim]))) {
      fail(`the token's \`${claim}\` is not a NumericDate.`, claim);
    }
  }
  if (payload.nbf !== undefined && now + clockToleranceSeconds < payload.nbf) {
    fail(`the token is not valid before ${new Date(payload.nbf * 1000).toISOString()}.`, 'nbf');
  }
  if (payload.iat === undefined) {
    if (requireIat) fail('the token has no `iat` claim.', 'iat');
  } else if (now + clockToleranceSeconds < payload.iat) {
    fail(`the token was issued in the future, at ${new Date(payload.iat * 1000).toISOString()}.`, 'iat');
  }

  if (nonce !== undefined && nonce !== null) {
    // A missing nonce is as bad as a wrong one: the ID token was not bound to this sign-in.
    if (!payload.nonce) fail('the ID token has no `nonce`, so it cannot be tied to this sign-in.', 'nonce');
    if (payload.nonce !== nonce) fail('the ID token `nonce` does not match the one sent with the authorization request.', 'nonce');
  }

  if (maxAgeSeconds !== undefined && maxAgeSeconds !== null) {
    if (typeof payload.auth_time !== 'number') fail('`max_age` was requested but the ID token carries no `auth_time`.', 'auth_time');
    if (now - payload.auth_time > maxAgeSeconds + clockToleranceSeconds) {
      fail(`the user authenticated ${now - payload.auth_time}s ago, beyond the requested max_age of ${maxAgeSeconds}s.`, 'auth_time');
    }
  }
  return payload;
}

/**
 * Checks `at_hash` / `c_hash` (OIDC Core §3.1.3.6): what stops an access token or a code of an
 * attacker's being presented beside a genuine ID token. Ark always issues both, so a missing one is
 * an error unless `require` is false.
 */
export async function validateTokenHashes(payload, { alg = 'RS256', accessToken, code, require: required = true } = {}) {
  const hash = hashForAlgorithm(alg);
  for (const [claim, value] of [
    ['at_hash', accessToken],
    ['c_hash', code]
  ]) {
    if (!value) continue;
    const present = payload[claim];
    if (!present) {
      if (required) {
        throw new ArkTokenError(
          `the ID token has no \`${claim}\`, so the ${claim === 'at_hash' ? 'access token' : 'authorization code'} it arrived with cannot be tied to it.`,
          { claim }
        );
      }
      continue;
    }
    if (present !== (await leftHalfHash(value, hash))) {
      throw new ArkTokenError(`the ID token \`${claim}\` does not cover the value it arrived with; it may have been substituted.`, { claim });
    }
  }
  return payload;
}

/**
 * The whole check for one token: signature against the provider's published keys, then claims,
 * then the token hashes.
 *
 * @param {string} token
 * @param {{ getSigningKey(kid: string|undefined, alg: string): Promise<{ jwk: object, key: CryptoKey }> }} jwks
 */
export async function verifyJwt(token, jwks, options = {}) {
  const decoded = decodeJwt(token);
  const { jwk, key } = await jwks.getSigningKey(decoded.header.kid, decoded.header.alg);
  await verifySignature(decoded, jwk, { algorithms: options.algorithms, key });
  validateClaims(decoded.payload, options);
  if (options.accessToken || options.code) {
    await validateTokenHashes(decoded.payload, {
      alg: decoded.header.alg,
      accessToken: options.accessToken,
      code: options.code,
      require: options.requireTokenHashes !== false
    });
  }
  return decoded.payload;
}
