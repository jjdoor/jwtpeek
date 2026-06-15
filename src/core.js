'use strict';

/**
 * jwtpeek core — pure JWT decoding + claim classification.
 *
 * No fs, no clock, no network: every function takes its inputs explicitly so
 * this and the Python port behave identically and stay unit-testable.
 *
 * IMPORTANT: jwtpeek DECODES, it does not VERIFY. A JWT's signature is what
 * proves the payload wasn't tampered with; we never check it. Treat decoded
 * contents as untrusted unless you've verified the signature with the issuer's
 * key.
 */

const UNITS = { y: 31536000000, d: 86400000, h: 3600000, m: 60000, s: 1000 };

// Registered date claims (RFC 7519 + common OIDC) mapped to a display label.
// This is also the print order; `exp` is last so the validity verdict lands
// as the kicker.
const TIME_CLAIMS = [
  ['iat', 'issued'],
  ['nbf', 'not before'],
  ['auth_time', 'auth time'],
  ['updated_at', 'updated'],
  ['exp', 'expires'],
];

/**
 * Strip the noise that creeps in when a token is copy-pasted: surrounding
 * quotes, an "Authorization:"/"Bearer " prefix, and any wrapping whitespace
 * (including the line breaks a wrapped terminal paste introduces).
 *
 * @param {*} input
 * @returns {string}
 */
function stripToken(input) {
  let s = String(input == null ? '' : input).trim();
  s = s.replace(/^['"]+|['"]+$/g, '');
  s = s.replace(/^Authorization:\s*/i, '');
  s = s.replace(/^Bearer\s+/i, '');
  s = s.replace(/\s+/g, '');
  return s;
}

/**
 * Decode one base64url segment to a UTF-8 string. Throws on non-base64url so
 * callers can report a precise error instead of silently mangling bytes.
 *
 * @param {string} seg
 * @returns {string}
 */
function b64urlToString(seg) {
  if (!/^[A-Za-z0-9_-]+$/.test(seg)) throw new Error('not base64url');
  let b64 = seg.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Buffer.from(b64, 'base64').toString('utf8');
}

function parseSegment(seg, which) {
  if (!seg) throw new Error(`${which} segment is empty`);
  let json;
  try { json = b64urlToString(seg); }
  catch { throw new Error(`${which} is not valid base64url`); }
  let obj;
  try { obj = JSON.parse(json); }
  catch { throw new Error(`${which} is not valid JSON`); }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error(`${which} is not a JSON object`);
  }
  return obj;
}

/**
 * Decode a JWT into { header, payload, signature }. Accepts a 2-part unsecured
 * token (alg: none) as well as the usual 3-part form. Throws an Error with a
 * human message on anything that isn't a structurally valid JWT.
 *
 * Does NOT verify the signature — see the module note.
 *
 * @param {string} token
 * @returns {{ header: object, payload: object, signature: string }}
 */
function decodeJwt(token) {
  const t = String(token == null ? '' : token).trim();
  if (!t) throw new Error('empty token');
  const parts = t.split('.');
  if (parts.length < 2 || parts.length > 3) {
    throw new Error(`not a JWT: expected 2 or 3 dot-separated parts, got ${parts.length}`);
  }
  return {
    header: parseSegment(parts[0], 'header'),
    payload: parseSegment(parts[1], 'payload'),
    signature: parts.length === 3 ? parts[2] : '',
  };
}

/**
 * Normalize a JWT NumericDate to epoch milliseconds. Per RFC 7519 these are
 * *seconds*, but some issuers wrongly emit milliseconds — detect that (a real
 * seconds value won't reach 1e12 until the year 5138) and pass it through.
 * Returns null for anything that isn't a finite number.
 *
 * @param {*} value
 * @returns {number|null}
 */
function normalizeEpochMs(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return value >= 1e12 ? Math.round(value) : Math.round(value * 1000);
}

/**
 * Evaluate validity windows against a supplied `nowMs` (no clock in here).
 * `expired`/`notYetValid` are null when the corresponding claim is absent.
 *
 * @param {object} payload
 * @param {number} nowMs
 * @returns {{ expMs:number|null, nbfMs:number|null, expired:boolean|null, notYetValid:boolean|null }}
 */
function evaluateExpiry(payload, nowMs) {
  const expMs = normalizeEpochMs(payload && payload.exp);
  const nbfMs = normalizeEpochMs(payload && payload.nbf);
  return {
    expMs,
    nbfMs,
    expired: expMs == null ? null : nowMs >= expMs,
    notYetValid: nbfMs == null ? null : nowMs < nbfMs,
  };
}

/**
 * Compact, two-unit-max human span, e.g. "1d 3h", "7y 2d", "45s". Sign is
 * ignored (callers phrase "ago"/"in" themselves).
 *
 * @param {number} ms
 * @returns {string}
 */
function formatDuration(ms) {
  ms = Math.abs(Math.round(Number(ms) || 0));
  if (ms < 1000) return '0s';
  const order = [['y', UNITS.y], ['d', UNITS.d], ['h', UNITS.h], ['m', UNITS.m], ['s', UNITS.s]];
  const parts = [];
  let rem = ms;
  for (const [label, size] of order) {
    if (rem >= size) {
      const n = Math.floor(rem / size);
      rem -= n * size;
      parts.push(`${n}${label}`);
      if (parts.length === 2) break;
    } else if (parts.length) {
      break;
    }
  }
  return parts.length ? parts.join(' ') : '0s';
}

module.exports = {
  UNITS, TIME_CLAIMS, stripToken, b64urlToString, decodeJwt,
  normalizeEpochMs, evaluateExpiry, formatDuration,
};
