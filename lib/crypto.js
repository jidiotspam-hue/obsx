'use strict';

/**
 * OBSX Security — Cryptographic Primitives & Shared Helpers (Zone 1)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the MIT License — See LICENSE file.
 */

const crypto = require('crypto');
const net = require('net');

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
let secretInitPromise = null;

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
  if (secretInitPromise) return secretInitPromise;
  secretInitPromise = (async () => {
    if (customKv) {
      const existing = await customKv.get('tracer:secret');
      if (existing) {
        cachedSecret = existing;
        return cachedSecret;
      }
      const fresh = randomId(32);
      const acquired = await customKv.set('tracer:secret', fresh, 'NX');
      cachedSecret = acquired ? fresh : (await customKv.get('tracer:secret')) || fresh;
      return cachedSecret;
    }
    cachedSecret = randomId(32);
    return cachedSecret;
  })();
  try {
    return await secretInitPromise;
  } finally {
    secretInitPromise = null;
  }
}

async function signToken(payload, kv) {
  const sec = await secret(kv);
  const body = b64u(JSON.stringify(payload));
  const mac = hmac(sec, 'tracer.v1.' + body);
  return `${body}.${mac}`;
}

async function verifyToken(token, kv) {
  if (typeof token !== 'string' || token.length > 4096) {
    return null;
  }
  const dot = token.indexOf('.');
  if (dot < 1) {
    return null;
  }
  const body = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const sec = await secret(kv);
  const expected = hmac(sec, 'tracer.v1.' + body);
  if (!safeEqual(mac, expected)) {
    return null;
  }
  try {
    return JSON.parse(unb64u(body).toString('utf8'));
  } catch {
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
          !(depth === 0 && (k === 'obsx' || k === 'advisory' || k === 'seal'))
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

const SEAL_REPLAY_CACHE = new Map();
const SEAL_REPLAY_MAX = 10000;

function recordSealUse(cacheKey, ttlMs) {
  const now = Date.now();
  if (SEAL_REPLAY_CACHE.size >= SEAL_REPLAY_MAX) {
    for (const [k, exp] of SEAL_REPLAY_CACHE) {
      if (exp <= now) SEAL_REPLAY_CACHE.delete(k);
    }
    while (SEAL_REPLAY_CACHE.size >= SEAL_REPLAY_MAX) {
      const oldest = SEAL_REPLAY_CACHE.keys().next().value;
      if (oldest === undefined) break;
      SEAL_REPLAY_CACHE.delete(oldest);
    }
  }
  const existingExp = SEAL_REPLAY_CACHE.get(cacheKey);
  if (existingExp && existingExp > now) return false;
  SEAL_REPLAY_CACHE.set(cacheKey, now + ttlMs);
  return true;
}

/**
 * Validates cryptographic action payload signature.
 * Enforces timestamp freshness, replay protection, and fail-closed boundary checks.
 */
function verifyActionSeal(rk, session, ts, nonce, payload, sig, options = {}) {
  if (!rk || !session || !sig) return false;
  const opts = options && typeof options === 'object' ? options : {};
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || tsNum <= 0) return false;
  const maxAgeMs = opts.maxAgeMs !== undefined ? Number(opts.maxAgeMs) : 300000;
  const futureSkewMs = opts.futureSkewMs !== undefined ? Number(opts.futureSkewMs) : 60000;
  if (Number.isFinite(maxAgeMs) && maxAgeMs > 0) {
    const now = Date.now();
    if (now - tsNum > maxAgeMs) return false;
    if (tsNum - now > futureSkewMs) return false;
  }
  try {
    const expected = signActionSeal(rk, session, ts, nonce, payload);
    if (!safeEqual(sig, expected)) return false;
    if (opts.allowReplay !== true) {
      const replayWindow = Number.isFinite(maxAgeMs) && maxAgeMs > 0 ? maxAgeMs : 300000;
      const digest = sha256(`${session}\n${tsNum}\n${String(nonce ?? '')}\n${sig}`);
      if (!recordSealUse(digest, replayWindow)) return false;
    }
    return true;
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
    process.env.TEST_MODE === '1' ||
    process.env.TEST_MODE === 'true' ||
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

function parseCanonicalIp(rawIp) {
  if (typeof rawIp !== 'string') return null;
  let s = rawIp.trim();
  if (!s || s.length > 64) return null;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zoneIdx = s.indexOf('%');
  if (zoneIdx > 0) s = s.slice(0, zoneIdx);
  const family = net.isIP(s);
  if (family === 4) {
    const octets = s.split('.').map(Number);
    return { family: 4, ip: s, octets, isLoopback: octets[0] === 127 };
  }
  if (family !== 6) return null;
  const lower = s.toLowerCase();
  const halves = lower.split('::');
  if (halves.length > 2) return null;

  const parseSide = (part) => {
    if (!part) return [];
    const tokens = part.split(':');
    const out = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (tok.includes('.')) {
        if (i !== tokens.length - 1 || net.isIP(tok) !== 4) return null;
        const v4 = tok.split('.').map(Number);
        out.push(((v4[0] << 8) | v4[1]) & 0xffff, ((v4[2] << 8) | v4[3]) & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(tok)) return null;
        out.push(parseInt(tok, 16));
      }
    }
    return out;
  };

  const left = parseSide(halves[0]);
  const right = halves.length === 2 ? parseSide(halves[1]) : [];
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 0)) return null;
  const groups = [...left, ...Array(missing).fill(0), ...right];
  if (groups.length !== 8) return null;

  // Map IPv4-mapped IPv6 (::ffff:a.b.c.d / 0:0:0:0:0:ffff:xxxx:yyyy) to canonical IPv4
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const octets = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
    return { family: 4, ip: octets.join('.'), octets, isLoopback: octets[0] === 127 };
  }

  const isLoopback =
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0 &&
    groups[6] === 0 &&
    groups[7] === 1;
  return {
    family: 6,
    ip: groups.map((g) => g.toString(16)).join(':'),
    groups,
    isLoopback,
  };
}

function normalizeIp(rawIp) {
  const parsed = parseCanonicalIp(rawIp);
  return parsed ? parsed.ip : '';
}

function getSubnetKey(rawIp) {
  const parsed = parseCanonicalIp(rawIp);
  if (!parsed) return 'subnet:unknown';
  if (parsed.isLoopback) return 'subnet:loopback';
  if (parsed.family === 4) {
    return `subnet:v4:${parsed.octets[0]}.${parsed.octets[1]}.${parsed.octets[2]}.0/24`;
  }
  const prefix = parsed.groups
    .slice(0, 3)
    .map((g) => g.toString(16).padStart(4, '0'))
    .join(':');
  return `subnet:v6:${prefix}/48`;
}

function formatCidrSubnet(rawIp) {
  const parsed = parseCanonicalIp(rawIp);
  if (!parsed) return 'unknown';
  if (parsed.family === 4) {
    return `${parsed.octets[0]}.${parsed.octets[1]}.${parsed.octets[2]}.0/24`;
  }
  return `${parsed.groups.slice(0, 4).map((g) => g.toString(16)).join(':')}::/64`;
}

function randomInt(...args) {
  return crypto.randomInt(...args);
}

module.exports = {
  b64u,
  unb64u,
  sha256,
  hmac,
  safeEqual,
  randomId,
  randomInt,
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
  parseCanonicalIp,
  normalizeIp,
  getSubnetKey,
  formatCidrSubnet,
};
