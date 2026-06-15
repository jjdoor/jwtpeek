'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  stripToken, decodeJwt, normalizeEpochMs, evaluateExpiry, formatDuration,
} = require('../src/core.js');

// The classic jwt.io HS256 sample (no exp claim).
const SAMPLE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const mkToken = (header, payload, sig = 'sig') => `${enc(header)}.${enc(payload)}.${sig}`;

test('decodeJwt decodes the classic sample', () => {
  const d = decodeJwt(SAMPLE);
  assert.deepEqual(d.header, { alg: 'HS256', typ: 'JWT' });
  assert.equal(d.payload.sub, '1234567890');
  assert.equal(d.payload.name, 'John Doe');
  assert.equal(d.payload.iat, 1516239022);
  assert.equal(d.signature, 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
});

test('decodeJwt handles base64url needing padding & non-ASCII', () => {
  const d = decodeJwt(mkToken({ alg: 'none' }, { name: 'Ünicøde ✓', n: 1 }, ''));
  assert.equal(d.payload.name, 'Ünicøde ✓');
  assert.equal(d.signature, '');
});

test('decodeJwt accepts a 2-part unsecured token', () => {
  const t = `${enc({ alg: 'none' })}.${enc({ sub: 'x' })}`;
  const d = decodeJwt(t);
  assert.equal(d.payload.sub, 'x');
  assert.equal(d.signature, '');
});

test('decodeJwt rejects malformed input', () => {
  assert.throws(() => decodeJwt('not-a-jwt'));          // no dots
  assert.throws(() => decodeJwt('a.b.c.d'));            // too many parts
  assert.throws(() => decodeJwt(''));                   // empty
  assert.throws(() => decodeJwt('!!!.@@@'));            // bad base64url
  assert.throws(() => decodeJwt(`${enc({ a: 1 })}.bm90anNvbg`)); // payload decodes to "notjson"
});

test('stripToken removes Bearer/Authorization prefixes, quotes, whitespace', () => {
  assert.equal(stripToken('  Bearer abc.def.ghi '), 'abc.def.ghi');
  assert.equal(stripToken('"abc.def.ghi"'), 'abc.def.ghi');
  assert.equal(stripToken('Authorization: Bearer abc.def.ghi'), 'abc.def.ghi');
  assert.equal(stripToken('abc.\n def.\n ghi'), 'abc.def.ghi');
});

test('normalizeEpochMs treats seconds as default, tolerates ms', () => {
  assert.equal(normalizeEpochMs(1516239022), 1516239022000);
  assert.equal(normalizeEpochMs(1516239022000), 1516239022000);
  assert.equal(normalizeEpochMs('nope'), null);
  assert.equal(normalizeEpochMs(undefined), null);
});

test('evaluateExpiry flags expired / active / absent', () => {
  const now = 1_600_000_000_000;
  assert.equal(evaluateExpiry({ exp: 1500000000 }, now).expired, true);   // 2017 < now
  assert.equal(evaluateExpiry({ exp: 1700000000 }, now).expired, false);  // 2023 > now
  assert.equal(evaluateExpiry({}, now).expired, null);
  assert.equal(evaluateExpiry({ nbf: 1700000000 }, now).notYetValid, true);
  assert.equal(evaluateExpiry({ nbf: 1500000000 }, now).notYetValid, false);
});

test('formatDuration is compact, two-unit max, with years', () => {
  assert.equal(formatDuration(0), '0s');
  assert.equal(formatDuration(45000), '45s');
  assert.equal(formatDuration(90000), '1m 30s');
  assert.equal(formatDuration(86400000 + 3 * 3600000), '1d 3h');
  assert.equal(formatDuration(2 * 31536000000 + 5 * 86400000), '2y 5d');
  assert.equal(formatDuration(-5000), '5s');
});
