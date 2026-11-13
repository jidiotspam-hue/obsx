'use strict';

/**
 * OBSX Security — Cryptographic Primitives & Shared Helpers (Zone 1)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the MIT License — See LICENSE file.
 */

const crypto = require('crypto');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (str) => Buffer.from(str, 'base64url');

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('base64url');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

const randomId = (bytes = 16) => crypto.randomBytes(bytes).toString('base64url');

let cachedSecret = null;
async function secret(customKv) {
  if (process.env.OBSX_SECRET && process.env.OBSX_SECRET.length >= 16) {
    return process.env.OBSX_SECRET;
  }
  if (process.env.VERITAS_SECRET && process.env.VERITAS_SECRET.length >= 16) {
    return process.env.VERITAS_SECRET;
  }
  if (process.env.TRACER_SECRET && process.env.TRACER_SECRET.length >= 16) {
    return process.env.TRACER_SECRET;
  }
  if (cachedSecret) return cachedSecret;
  if (customKv) {
    const existing = await customKv.get('tracer:secret');
    if (existing) {
      cachedSecret = existing;
      return cachedSecret;
    }
    const fresh = randomId(32);
    await customKv.set('tracer:secret', fresh);
    cachedSecret = fresh;
    return cachedSecret;
  }
  cachedSecret = randomId(32);
  return cachedSecret;
}

async function signToken(payload, kv) {
  const sec = await secret(kv);
  const body = b64u(JSON.stringify(payload));
  const mac = hmac(sec, 'tracer.v1.' + body);
  return `${body}.${mac}`;
}

async function verifyToken(token, kv) {
  if (typeof token !== 'string' || token.length > 4096) {
    console.log('[VERIFY_TOKEN FAIL] Invalid token type or size:', typeof token, token ? token.length : 0);
    return null;
  }
  const dot = token.indexOf('.');
  if (dot < 1) {
    console.log('[VERIFY_TOKEN FAIL] No delimiter dot found:', token);
    return null;
  }
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const sec = await secret(kv);
  const expected = hmac(sec, 'tracer.v1.' + body);
  if (!safeEqual(mac, expected)) {
    console.log('[VERIFY_TOKEN FAIL] HMAC signature mismatch. Sec prefix:', sec ? sec.slice(0, 10) : 'none');
    return null;
  }
  try {
    return JSON.parse(unb64u(body).toString('utf8'));
  } catch (err) {
    console.log('[VERIFY_TOKEN FAIL] JSON decode error:', err.message);
    return null;
  }
}

async function fingerprint(kind, value, kv) {
  const sec = await secret(kv);
  return crypto.createHmac('sha256', sec).update(`${kind}:${value}`).digest('base64url').slice(0, 16);
}

/**
 * Proof of Work (PoW) Challenge Generation & Verification
 * Used to ensure headless automated callers cannot spam requests for free.
 */
function createPoWChallenge(sessionId, difficulty = 3) {
  const salt = randomId(8);
  const timestamp = Date.now();
  const challenge = `${sessionId}:${timestamp}:${salt}`;
  return { challenge, difficulty, timestamp };
}

function verifyPoW(challenge, nonce, difficulty = 3) {
  if (typeof challenge !== 'string' || typeof nonce !== 'string') return false;
  const diff = Number(difficulty);
  if (!Number.isInteger(diff) || diff < 1 || diff > 64) return false;
  if (nonce.length === 0 || nonce.length > 64) return false;
  const target = '0'.repeat(diff);
  const hash = sha256(`${challenge}:${nonce}`);
  return hash.startsWith(target);
}

const CANON_MAX_DEPTH = 32;

/**
 * Deterministic JSON Canonicalization for Cryptographic Action Sealing
 * Hardened with recursion depth ceiling and circular reference protection.
 */
function canon(v, depth = 0, seen = new WeakSet()) {
  if (depth > CANON_MAX_DEPTH) {
    const err = new Error('Payload depth exceeds maximum allowed limit');
    err.code = 'CANON_TOO_DEEP';
    throw err;
  }
  if (Array.isArray(v)) {
    return (
      '[' +
      v
        .map((x) =>
          x === undefined || typeof x === 'function' || typeof x === 'symbol'
            ? 'null'
            : canon(x, depth + 1, seen)
        )
        .join(',') +
      ']'
    );
  }
  if (v !== null && typeof v === 'object') {
    if (seen.has(v)) {
      const err = new Error('Circular reference detected in payload');
      err.code = 'CANON_CIRCULAR';
      throw err;
    }
    seen.add(v);
    const keys = Object.keys(v)
      .sort()
      .filter(
        (k) =>
          v[k] !== undefined &&
          typeof v[k] !== 'function' &&
          typeof v[k] !== 'symbol' &&
          k !== 'obsx' &&
          k !== 'advisory' &&
          k !== 'seal'
      );
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canon(v[k], depth + 1, seen)).join(',') + '}';
  }
  const j = JSON.stringify(v);
  return j === undefined ? 'null' : j;
}

const SEAL_FAIL_CLOSED_CODES = new Set([
  'CANON_TOO_DEEP',
  'CANON_CIRCULAR',
  'INVALID_SEAL_SESSION',
  'INVALID_SEAL_NONCE',
  'INVALID_SEAL_TIMESTAMP',
]);

function assertNoNewlines(val, code, label) {
  if (typeof val === 'string' && /[\r\n]/.test(val)) {
    const err = new Error(`${label} must not contain newline delimiters`);
    err.code = code;
    throw err;
  }
}

/**
 * Computes an HMAC-SHA256 signature for an application action payload.
 * Enforces delimiter sanitization to prevent boundary collision attacks.
 */
function signActionSeal(rk, session, ts, nonce, payload) {
  if (typeof session !== 'string') {
    const err = new Error('Session identifier must not contain newline delimiters');
    err.code = 'INVALID_SEAL_SESSION';
    throw err;
  }
  assertNoNewlines(session, 'INVALID_SEAL_SESSION', 'Session identifier');
  assertNoNewlines(nonce, 'INVALID_SEAL_NONCE', 'Nonce');
  assertNoNewlines(ts, 'INVALID_SEAL_TIMESTAMP', 'Timestamp');

  const msg = 'obsx.seal.v1\n' + session + '\n' + ts + '\n' + (nonce || '') + '\n' + canon(payload);
  const keyBuf = Buffer.isBuffer(rk) ? rk : unb64u(rk);
  return crypto.createHmac('sha256', keyBuf).update(msg).digest('base64url');
}

/**
 * Validates cryptographic action payload signature.
 * Fails closed on canonicalization violations or delimiter boundary injection.
 */
function verifyActionSeal(rk, session, ts, nonce, payload, sig) {
  if (!rk || !session || !sig) return false;
  try {
    const expected = signActionSeal(rk, session, ts, nonce, payload);
    return safeEqual(sig, expected);
  } catch (err) {
    if (SEAL_FAIL_CLOSED_CODES.has(err.code)) {
      return false;
    }
    throw err;
  }
}

function isTestRuntime() {
  if (process.env.NODE_ENV === 'production') return false;
  return (
    process.env.NODE_ENV === 'test' ||
    process.env.OBSX_TEST_MODE === '1' ||
    Boolean(process.env.TEST_MODE) ||
    (Array.isArray(process.execArgv) && process.execArgv.includes('--test')) ||
    (Array.isArray(process.argv) &&
      process.argv.slice(1).some((a) => /(?:^|[\\/])[^\\/]*\.test\.m?js$/.test(String(a)) || String(a) === '--test'))
  );
}

const HTML_ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch]);
}

module.exports = {
  b64u,
  unb64u,
  sha256,
  hmac,
  safeEqual,
  randomId,
  randomInt: crypto.randomInt,
  secret,
  signToken,
  verifyToken,
  fingerprint,
  createPoWChallenge,
  verifyPoW,
  canon,
  signActionSeal,
  verifyActionSeal,
  isTestRuntime,
  escapeHtml,
};
