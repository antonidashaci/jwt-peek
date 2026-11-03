/**
 * JWT decoding, claim checks and HS256 verification - in the browser, offline.
 *
 * The reason this exists as a local page: pasting a token into a website is
 * handing someone a live credential. Decoding is pure string work and needs no
 * server at all.
 *
 * Nothing here trusts the token. `alg` is read for display, never used to pick
 * a verification strategy - "alg: none" and algorithm confusion are the two
 * classic JWT breaks, and both come from believing the header.
 */

/** Base64url -> bytes. Tolerates missing padding, which JWTs always omit. */
export function base64UrlToBytes(segment) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]*$/.test(segment)) {
    throw new SyntaxError('not base64url');
  }
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - (segment.length % 4)) % 4);
  const binary = typeof atob === 'function'
    ? atob(base64)
    : Buffer.from(base64, 'base64').toString('binary');
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/** Base64url -> string, decoded as UTF-8 so non-ASCII claims survive. */
export function base64UrlToText(segment) {
  return new TextDecoder('utf-8', { fatal: false }).decode(base64UrlToBytes(segment));
}

export function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = typeof btoa === 'function'
    ? btoa(binary)
    : Buffer.from(binary, 'binary').toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * @typedef {object} DecodedToken
 * @property {object} header
 * @property {object} payload
 * @property {string} signature   base64url, '' for an unsigned token
 * @property {string} signingInput `header.payload`
 */

/**
 * Split and decode a JWT. Throws a `SyntaxError` with a useful message rather
 * than returning a half-filled object.
 *
 * @param {string} token
 * @returns {DecodedToken}
 */
export function decode(token) {
  if (typeof token !== 'string') throw new SyntaxError('A token must be a string');
  const compact = token.trim().replace(/^Bearer\s+/i, '');
  const parts = compact.split('.');

  if (parts.length !== 3) {
    throw new SyntaxError(
      parts.length < 3
        ? `A JWS has three dot-separated parts; this has ${parts.length}`
        : 'This looks like a JWE (five parts), which carries an encrypted payload',
    );
  }

  const [headerPart, payloadPart, signature] = parts;
  const header = parseJson(headerPart, 'header');
  const payload = parseJson(payloadPart, 'payload');

  return { header, payload, signature, signingInput: `${headerPart}.${payloadPart}` };
}

function parseJson(segment, label) {
  let text;
  try {
    text = base64UrlToText(segment);
  } catch {
    throw new SyntaxError(`The ${label} is not valid base64url`);
  }
  try {
    const value = JSON.parse(text);
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('not an object');
    }
    return value;
  } catch {
    throw new SyntaxError(`The ${label} is not a JSON object`);
  }
}

/** Claims whose value is a NumericDate (seconds since the epoch). */
export const TIME_CLAIMS = ['exp', 'iat', 'nbf', 'auth_time', 'updated_at'];

/**
 * Turn a NumericDate claim into a Date, rejecting the common mistake of
 * putting milliseconds there.
 *
 * @param {unknown} value
 * @returns {{ date: Date, suspectMilliseconds: boolean }|null}
 */
export function claimToDate(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return null;
  // Seconds-since-epoch passed 1e10 in the year 2286; anything bigger is ms.
  const suspectMilliseconds = value > 1e11;
  return {
    date: new Date(suspectMilliseconds ? value : value * 1000),
    suspectMilliseconds,
  };
}

/**
 * Human "in 3 minutes" / "14 hours ago".
 * @param {Date} date
 * @param {Date} [now]
 */
export function relativeTime(date, now = new Date()) {
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const units = [
    ['year', 31536000], ['month', 2592000], ['day', 86400],
    ['hour', 3600], ['minute', 60], ['second', 1],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size || unit === 'second') {
      return formatter.format(Math.round(seconds / size), unit);
    }
  }
  return '';
}

/**
 * @typedef {object} Finding
 * @property {'error'|'warn'|'ok'} level
 * @property {string} claim
 * @property {string} message
 */

/**
 * Check the claims that decide whether a token would actually be accepted.
 *
 * @param {DecodedToken} decoded
 * @param {{ now?: Date, leewaySeconds?: number, audience?: string, issuer?: string }} [options]
 * @returns {Finding[]}
 */
export function inspect(decoded, options = {}) {
  const { now = new Date(), leewaySeconds = 0, audience, issuer } = options;
  const { header, payload, signature } = decoded;
  const findings = [];
  const seconds = now.getTime() / 1000;

  const alg = String(header.alg ?? '');
  if (!alg) {
    findings.push({ level: 'error', claim: 'alg', message: 'No algorithm in the header' });
  } else if (alg.toLowerCase() === 'none') {
    findings.push({
      level: 'error',
      claim: 'alg',
      message: 'alg is "none": this token is unsigned and anyone can forge it',
    });
  } else if (!signature) {
    findings.push({
      level: 'error',
      claim: 'alg',
      message: `Header says ${alg} but the signature is empty`,
    });
  }

  if (payload.exp === undefined) {
    findings.push({ level: 'warn', claim: 'exp', message: 'No expiry: this token never dies' });
  } else {
    const exp = claimToDate(payload.exp);
    if (!exp) {
      findings.push({ level: 'error', claim: 'exp', message: 'exp is not a NumericDate' });
    } else if (exp.suspectMilliseconds) {
      findings.push({
        level: 'error',
        claim: 'exp',
        message: 'exp looks like milliseconds; NumericDate is in seconds',
      });
    } else if (payload.exp + leewaySeconds < seconds) {
      findings.push({
        level: 'error',
        claim: 'exp',
        message: `Expired ${relativeTime(exp.date, now)}`,
      });
    } else {
      findings.push({
        level: 'ok',
        claim: 'exp',
        message: `Expires ${relativeTime(exp.date, now)}`,
      });
    }
  }

  if (payload.nbf !== undefined) {
    const nbf = claimToDate(payload.nbf);
    if (nbf && payload.nbf - leewaySeconds > seconds) {
      findings.push({
        level: 'error',
        claim: 'nbf',
        message: `Not valid until ${relativeTime(nbf.date, now)}`,
      });
    }
  }

  if (payload.iat !== undefined) {
    const iat = claimToDate(payload.iat);
    if (iat && payload.iat - leewaySeconds > seconds) {
      findings.push({
        level: 'warn',
        claim: 'iat',
        message: 'Issued in the future: check the clock on the issuing server',
      });
    }
  }

  if (audience !== undefined) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud].filter((v) => v !== undefined);
    findings.push(aud.includes(audience)
      ? { level: 'ok', claim: 'aud', message: `Audience includes ${audience}` }
      : { level: 'error', claim: 'aud', message: `Audience does not include ${audience}` });
  }

  if (issuer !== undefined) {
    findings.push(payload.iss === issuer
      ? { level: 'ok', claim: 'iss', message: `Issuer is ${issuer}` }
      : { level: 'error', claim: 'iss', message: `Issuer is ${JSON.stringify(payload.iss)}, expected ${issuer}` });
  }

  return findings;
}

/**
 * Verify an HS256/384/512 signature with the given secret.
 *
 * The algorithm is a *parameter*, taken from what you expect, not from the
 * token's own header. Reading `alg` from the token and verifying with it is
 * algorithm confusion - it lets an attacker downgrade an RS256 token to an
 * HS256 one signed with the public key.
 *
 * @param {string} token
 * @param {string} secret
 * @param {'HS256'|'HS384'|'HS512'} [expectedAlg]
 * @param {Crypto} [cryptoImpl]
 * @returns {Promise<{ valid: boolean, reason?: string }>}
 */
export async function verifyHmac(token, secret, expectedAlg = 'HS256', cryptoImpl = globalThis.crypto) {
  const hashes = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
  const hash = hashes[expectedAlg];
  if (!hash) return { valid: false, reason: `${expectedAlg} is not an HMAC algorithm` };
  if (!secret) return { valid: false, reason: 'No secret given' };

  const decoded = decode(token);
  if (!decoded.signature) return { valid: false, reason: 'The token has no signature' };
  if (String(decoded.header.alg) !== expectedAlg) {
    return {
      valid: false,
      reason: `Header says ${decoded.header.alg}, you asked to verify as ${expectedAlg}`,
    };
  }

  const encoder = new TextEncoder();
  const key = await cryptoImpl.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash }, false, ['sign'],
  );
  const mac = await cryptoImpl.subtle.sign('HMAC', key, encoder.encode(decoded.signingInput));
  const expected = bytesToBase64Url(new Uint8Array(mac));

  return expected === decoded.signature
    ? { valid: true }
    : { valid: false, reason: 'Signature does not match this secret' };
}
