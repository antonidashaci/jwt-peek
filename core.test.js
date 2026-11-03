import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';

import {
  base64UrlToText, bytesToBase64Url, claimToDate, decode, inspect, relativeTime, verifyHmac,
} from './core.js';

const b64 = (object) => bytesToBase64Url(new TextEncoder().encode(JSON.stringify(object)));
const unsigned = (header, payload) => `${b64(header)}.${b64(payload)}.`;

async function sign(header, payload, secret, hash = 'SHA-256') {
  const input = `${b64(header)}.${b64(payload)}`;
  const key = await webcrypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash }, false, ['sign'],
  );
  const mac = await webcrypto.subtle.sign('HMAC', key, new TextEncoder().encode(input));
  return `${input}.${bytesToBase64Url(new Uint8Array(mac))}`;
}

const NOW = new Date('2026-11-03T12:00:00Z');
const seconds = (date) => Math.floor(date.getTime() / 1000);

test('decodes header and payload', () => {
  const token = unsigned({ alg: 'HS256', typ: 'JWT' }, { sub: '42', name: 'Ada' });
  const decoded = decode(token);
  assert.deepEqual(decoded.header, { alg: 'HS256', typ: 'JWT' });
  assert.equal(decoded.payload.name, 'Ada');
});

test('tolerates a Bearer prefix and surrounding whitespace', () => {
  const token = unsigned({ alg: 'HS256' }, { sub: '1' });
  assert.equal(decode(`  Bearer ${token} `).payload.sub, '1');
});

test('non-ASCII claims survive', () => {
  const token = unsigned({ alg: 'HS256' }, { name: 'Şişli Çiçek' });
  assert.equal(decode(token).payload.name, 'Şişli Çiçek');
});

test('base64url decodes without padding', () => {
  assert.equal(base64UrlToText('eyJhIjoxfQ'), '{"a":1}');
});

test('useful errors instead of a half-filled object', () => {
  assert.throws(() => decode('abc'), /three dot-separated parts/);
  assert.throws(() => decode('a.b.c.d.e'), /JWE/);
  assert.throws(() => decode('!!!.e30.'), /header is not valid base64url/);
  assert.throws(() => decode('eyJub3QifQ.e30.'), /header is not a JSON object/);
  assert.throws(() => decode(`${b64([1, 2])}.e30.`), /header is not a JSON object/);
  assert.throws(() => decode(null), /must be a string/);
});

test('claimToDate rejects milliseconds in a NumericDate', () => {
  assert.equal(claimToDate(1762171200).date.toISOString(), '2025-11-03T12:00:00.000Z');
  assert.equal(claimToDate(1762171200).suspectMilliseconds, false);
  assert.equal(claimToDate(1762171200000).suspectMilliseconds, true);
  assert.equal(claimToDate('soon'), null);
  assert.equal(claimToDate(0), null);
});

test('relativeTime reads like a sentence', () => {
  assert.match(relativeTime(new Date('2026-11-03T12:05:00Z'), NOW), /5 minutes/);
  assert.match(relativeTime(new Date('2026-11-01T12:00:00Z'), NOW), /2 days ago/);
});

test('flags an unsigned token', () => {
  const findings = inspect(decode(unsigned({ alg: 'none' }, { sub: '1' })), { now: NOW });
  const alg = findings.find((f) => f.claim === 'alg');
  assert.equal(alg.level, 'error');
  assert.match(alg.message, /unsigned/);
});

test('flags a signed-looking token with no signature', () => {
  const findings = inspect(decode(unsigned({ alg: 'HS256' }, { sub: '1' })), { now: NOW });
  assert.match(findings.find((f) => f.claim === 'alg').message, /signature is empty/);
});

test('expiry', () => {
  const expired = inspect(
    decode(unsigned({ alg: 'HS256' }, { exp: seconds(NOW) - 60 })), { now: NOW },
  ).find((f) => f.claim === 'exp');
  assert.equal(expired.level, 'error');
  assert.match(expired.message, /Expired/);

  const live = inspect(
    decode(unsigned({ alg: 'HS256' }, { exp: seconds(NOW) + 3600 })), { now: NOW },
  ).find((f) => f.claim === 'exp');
  assert.equal(live.level, 'ok');
});

test('leeway covers a small clock skew', () => {
  const token = decode(unsigned({ alg: 'HS256' }, { exp: seconds(NOW) - 20 }));
  assert.equal(inspect(token, { now: NOW, leewaySeconds: 60 })
    .find((f) => f.claim === 'exp').level, 'ok');
});

test('a token with no expiry is called out', () => {
  const finding = inspect(decode(unsigned({ alg: 'HS256' }, { sub: '1' })), { now: NOW })
    .find((f) => f.claim === 'exp');
  assert.equal(finding.level, 'warn');
  assert.match(finding.message, /never dies/);
});

test('exp in milliseconds is an error, not a date in the year 57000', () => {
  const finding = inspect(
    decode(unsigned({ alg: 'HS256' }, { exp: NOW.getTime() })), { now: NOW },
  ).find((f) => f.claim === 'exp');
  assert.equal(finding.level, 'error');
  assert.match(finding.message, /milliseconds/);
});

test('nbf and a future iat', () => {
  const nbf = inspect(
    decode(unsigned({ alg: 'HS256' }, { nbf: seconds(NOW) + 600 })), { now: NOW },
  ).find((f) => f.claim === 'nbf');
  assert.equal(nbf.level, 'error');

  const iat = inspect(
    decode(unsigned({ alg: 'HS256' }, { iat: seconds(NOW) + 600 })), { now: NOW },
  ).find((f) => f.claim === 'iat');
  assert.equal(iat.level, 'warn');
  assert.match(iat.message, /clock/);
});

test('audience, as a string or an array', () => {
  const one = decode(unsigned({ alg: 'HS256' }, { aud: 'api' }));
  assert.equal(inspect(one, { now: NOW, audience: 'api' }).find((f) => f.claim === 'aud').level, 'ok');
  assert.equal(inspect(one, { now: NOW, audience: 'web' }).find((f) => f.claim === 'aud').level, 'error');

  const many = decode(unsigned({ alg: 'HS256' }, { aud: ['web', 'api'] }));
  assert.equal(inspect(many, { now: NOW, audience: 'api' }).find((f) => f.claim === 'aud').level, 'ok');
});

test('issuer', () => {
  const token = decode(unsigned({ alg: 'HS256' }, { iss: 'https://auth.example.com' }));
  assert.equal(
    inspect(token, { now: NOW, issuer: 'https://auth.example.com' }).find((f) => f.claim === 'iss').level,
    'ok',
  );
  assert.equal(inspect(token, { now: NOW, issuer: 'other' }).find((f) => f.claim === 'iss').level, 'error');
});

test('verifies a real HS256 signature', async () => {
  const token = await sign({ alg: 'HS256', typ: 'JWT' }, { sub: '42' }, 'topsecret');
  assert.deepEqual(await verifyHmac(token, 'topsecret', 'HS256', webcrypto), { valid: true });
});

test('rejects the wrong secret', async () => {
  const token = await sign({ alg: 'HS256' }, { sub: '42' }, 'topsecret');
  const result = await verifyHmac(token, 'guess', 'HS256', webcrypto);
  assert.equal(result.valid, false);
  assert.match(result.reason, /does not match/);
});

test('HS384 and HS512', async () => {
  const t384 = await sign({ alg: 'HS384' }, { sub: '1' }, 's', 'SHA-384');
  assert.equal((await verifyHmac(t384, 's', 'HS384', webcrypto)).valid, true);
  const t512 = await sign({ alg: 'HS512' }, { sub: '1' }, 's', 'SHA-512');
  assert.equal((await verifyHmac(t512, 's', 'HS512', webcrypto)).valid, true);
});

test('will not let the token choose the algorithm', async () => {
  // Algorithm confusion: the header claims HS256, we were asked for HS512.
  const token = await sign({ alg: 'HS256' }, { sub: '1' }, 's');
  const result = await verifyHmac(token, 's', 'HS512', webcrypto);
  assert.equal(result.valid, false);
  assert.match(result.reason, /Header says HS256/);
});

test('refuses to "verify" an unsigned token', async () => {
  const result = await verifyHmac(unsigned({ alg: 'none' }, { sub: '1' }), 's', 'HS256', webcrypto);
  assert.equal(result.valid, false);
  assert.match(result.reason, /no signature/);
});

test('rejects a non-HMAC algorithm and an empty secret', async () => {
  assert.match((await verifyHmac('a.b.c', 's', 'RS256', webcrypto)).reason, /not an HMAC/);
  assert.match((await verifyHmac('a.b.c', '', 'HS256', webcrypto)).reason, /No secret/);
});
