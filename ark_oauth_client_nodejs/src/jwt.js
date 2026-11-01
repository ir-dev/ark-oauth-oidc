import { constants, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, leftHalfHash } from './crypto.js';
import { ArkTokenError } from './errors.js';

/**
 * JWT decoding, signature verification and claim validation.
 *
 * The Ark server signs with RS256 and publishes its keys at `jwks_uri`, so that is the path this
 * is tuned for; the other JWS families are accepted so the same client can be pointed at Entra ID,
 * Okta or Auth0 without a second implementation.
 *
 * The one algorithm deliberately not supported is `none`. An unsigned token is a token anyone can
 * write, and every historical JWT library vulnerability of note comes from honouring the `alg`
 * header without first deciding which algorithms are acceptable.
 */

const SUPPORTED_ALGORITHMS = new Map([
  ['RS256', { hash: 'sha256', kty: 'RSA' }],
  ['RS384', { hash: 'sha384', kty: 'RSA' }],
  ['RS512', { hash: 'sha512', kty: 'RSA' }],
  ['PS256', { hash: 'sha256', kty: 'RSA', pss: true }],
  ['PS384', { hash: 'sha384', kty: 'RSA', pss: true }],
  ['PS512', { hash: 'sha512', kty: 'RSA', pss: true }],
  ['ES256', { hash: 'sha256', kty: 'EC' }],
  ['ES384', { hash: 'sha384', kty: 'EC' }],
  ['ES512', { hash: 'sha512', kty: 'EC' }]
]);

/**
 * Splits a compact JWS without verifying anything.
 *
 * Useful for reading `kid` before a key is chosen, or for logging a token's `sub` while
 * diagnosing a failure — never for deciding anything. Nothing in this library authorises on the
 * result of a decode.
 */
export function decodeJwt(token) {
  if (typeof token !== 'string') throw new ArkTokenError('the token is not a string.');
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new ArkTokenError(`the token is not a compact JWS: expected 3 segments, found ${parts.length}.`);
  }

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
    payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
  } catch (cause) {
    throw new ArkTokenError('the token header or payload is not valid JSON.', { cause });
  }

  return {
    header,
    payload,
    signature: base64UrlDecode(parts[2]),
    signingInput: `${parts[0]}.${parts[1]}`
  };
}

/** Verifies the signature of an already-decoded token against one JWK. */
export function verifySignature(decoded, jwk, { algorithms } = {}) {
  const alg = decoded.header.alg;
  if (!alg || alg === 'none') {
    throw new ArkTokenError(`the token declares alg '${alg ?? 'missing'}'; unsigned tokens are never accepted.`);
  }

  const allowed = algorithms ?? [...SUPPORTED_ALGORITHMS.keys()];
  if (!allowed.includes(alg)) {
    throw new ArkTokenError(`the token is signed with ${alg}, which this client does not accept (allowed: ${allowed.join(', ')}).`);
  }

  const spec = SUPPORTED_ALGORITHMS.get(alg);
  if (!spec) throw new ArkTokenError(`unsupported signing algorithm '${alg}'.`);
  if (jwk.kty !== spec.kty) {
    throw new ArkTokenError(`the signing key is a ${jwk.kty} key but the token declares ${alg}.`);
  }
  if (jwk.alg && jwk.alg !== alg) {
    throw new ArkTokenError(`the key published for kid '${jwk.kid}' is registered for ${jwk.alg}, not ${alg}.`);
  }

  let key;
  try {
    key = createPublicKey({ key: jwk, format: 'jwk' });
  } catch (cause) {
    throw new ArkTokenError(`the published key for kid '${jwk.kid}' could not be imported: ${cause.message}`, { cause });
  }

  const keyOptions = { key };
  if (spec.pss) {
    keyOptions.padding = constants.RSA_PKCS1_PSS_PADDING;
    keyOptions.saltLength = constants.RSA_PSS_SALTLEN_DIGEST;
  }
  if (spec.kty === 'EC') {
    // JWS carries an EC signature as raw r||s, not the DER sequence Node verifies by default.
    keyOptions.dsaEncoding = 'ieee-p1363';
  }

  const ok = cryptoVerify(spec.hash, Buffer.from(decoded.signingInput, 'utf8'), keyOptions, decoded.signature);
  if (!ok) throw new ArkTokenError('the token signature does not verify against the published key.');
  return true;
}

/**
 * Validates the registered claims.
 *
 * Order matters less than completeness here: skipping any single one of these is how a token
 * meant for a different application, a different provider or a different moment ends up
 * authorising a request.
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
    if (payload.iss !== issuer) {
      fail(`the token was issued by '${payload.iss}', not by '${issuer}'.`, 'iss');
    }
  }

  if (audience) {
    const auds = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    if (auds.length === 0) fail('the token has no `aud` claim.', 'aud');
    if (!auds.includes(audience)) {
      fail(`the token is addressed to ${auds.map((a) => `'${a}'`).join(', ')}, not to '${audience}'.`, 'aud');
    }
    // OIDC Core §3.1.3.7: with several audiences, `azp` must name the party the token is for.
    if (auds.length > 1 && payload.azp && payload.azp !== audience) {
      fail(`the token names '${payload.azp}' as its authorized party, not '${audience}'.`, 'azp');
    }
  }

  if (subject && payload.sub !== subject) {
    fail(`the token belongs to subject '${payload.sub}', not '${subject}'.`, 'sub');
  }

  if (payload.exp === undefined) {
    if (requireExp) fail('the token has no `exp` claim.', 'exp');
  } else if (typeof payload.exp !== 'number' || now >= payload.exp + clockToleranceSeconds) {
    fail(`the token expired at ${new Date((payload.exp ?? 0) * 1000).toISOString()}.`, 'exp');
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
    // A missing nonce is as bad as a wrong one: it means the ID token was not bound to our
    // authorization request and could have been minted for someone else's session.
    if (!payload.nonce) fail('the ID token has no `nonce`, so it cannot be tied to this sign-in.', 'nonce');
    if (payload.nonce !== nonce) fail('the ID token `nonce` does not match the one sent with the authorization request.', 'nonce');
  }

  if (maxAgeSeconds !== undefined && maxAgeSeconds !== null) {
    if (typeof payload.auth_time !== 'number') {
      fail('`max_age` was requested but the ID token carries no `auth_time`.', 'auth_time');
    }
    if (now - payload.auth_time > maxAgeSeconds + clockToleranceSeconds) {
      fail(`the user authenticated ${now - payload.auth_time}s ago, beyond the requested max_age of ${maxAgeSeconds}s.`, 'auth_time');
    }
  }

  return payload;
}

/**
 * Checks `at_hash` / `c_hash` (OIDC Core §3.1.3.6).
 *
 * These are what stop an attacker swapping in an access token or an authorization code of their
 * own alongside a genuine ID token — the substitution attack the hashes exist for. The Ark server
 * always issues both, so a missing one is worth surfacing rather than skipping quietly.
 */
export function validateTokenHashes(payload, { accessToken, code, require: required = true } = {}) {
  const check = (claim, value) => {
    if (!value) return;
    const present = payload[claim];
    if (!present) {
      if (required) throw new ArkTokenError(`the ID token has no \`${claim}\`, so the ${claim === 'at_hash' ? 'access token' : 'authorization code'} it arrived with cannot be tied to it.`, { claim });
      return;
    }
    if (present !== leftHalfHash(value)) {
      throw new ArkTokenError(`the ID token \`${claim}\` does not cover the value it arrived with — it may have been substituted.`, { claim });
    }
  };

  check('at_hash', accessToken);
  check('c_hash', code);
  return payload;
}

/**
 * The whole check for one token: signature against the provider's published keys, then claims.
 *
 * @param {string} token
 * @param {{getSigningKey(kid: string|undefined, alg: string): Promise<object>}} jwks
 */
export async function verifyJwt(token, jwks, options = {}) {
  const decoded = decodeJwt(token);

  if (options.typ) {
    // RFC 9068 §4: an access token declares `at+jwt`, which is how a resource server refuses an
    // ID token presented in its place. Both spellings are seen in the wild.
    const typ = String(decoded.header.typ ?? '').toLowerCase();
    const expected = String(options.typ).toLowerCase();
    if (typ !== expected && typ !== `application/${expected}`) {
      throw new ArkTokenError(`expected a token of type '${options.typ}' but the header declares '${decoded.header.typ ?? 'none'}'.`);
    }
  }

  const jwk = await jwks.getSigningKey(decoded.header.kid, decoded.header.alg);
  verifySignature(decoded, jwk, { algorithms: options.algorithms });
  validateClaims(decoded.payload, options);
  if (options.accessToken || options.code) {
    validateTokenHashes(decoded.payload, {
      accessToken: options.accessToken,
      code: options.code,
      require: options.requireTokenHashes !== false
    });
  }
  return decoded.payload;
}

/**
 * Signs a compact JWS.
 *
 * Needed for exactly one thing on the client side: the `private_key_jwt` client assertion (OIDC
 * Core §9), where the client proves who it is with a signature instead of a shared secret that
 * has to be stored, rotated and kept out of logs on both ends.
 *
 * @param {object} payload
 * @param {object} options
 * @param {import('node:crypto').KeyObject|string|object} options.key PEM, JWK or KeyObject
 * @param {string} [options.alg] RS256 by default — what the Ark server accepts
 * @param {string} [options.kid] published in the header so the verifier can pick the right key
 * @param {string} [options.typ]
 */
export function signJwt(payload, { key, alg = 'RS256', kid, typ = 'JWT', header: extraHeader } = {}) {
  const spec = SUPPORTED_ALGORITHMS.get(alg);
  if (!spec) throw new ArkTokenError(`cannot sign with '${alg}'; supported: ${[...SUPPORTED_ALGORITHMS.keys()].join(', ')}.`);

  let privateKey;
  try {
    privateKey =
      typeof key === 'object' && key !== null && !Buffer.isBuffer(key) && key.asymmetricKeyType
        ? key
        : createPrivateKey(typeof key === 'object' && !Buffer.isBuffer(key) ? { key, format: 'jwk' } : key);
  } catch (cause) {
    throw new ArkTokenError(`the signing key could not be imported: ${cause.message}`, { cause });
  }

  const head = { alg, typ, ...(kid ? { kid } : {}), ...extraHeader };
  const signingInput = `${base64UrlEncode(JSON.stringify(head))}.${base64UrlEncode(JSON.stringify(payload))}`;

  const keyOptions = { key: privateKey };
  if (spec.pss) {
    keyOptions.padding = constants.RSA_PKCS1_PSS_PADDING;
    keyOptions.saltLength = constants.RSA_PSS_SALTLEN_DIGEST;
  }
  if (spec.kty === 'EC') keyOptions.dsaEncoding = 'ieee-p1363';

  const signature = cryptoSign(spec.hash, Buffer.from(signingInput, 'utf8'), keyOptions);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}
