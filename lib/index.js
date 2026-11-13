'use strict';

/**
 * OBSX Security — Official Node.js Verification SDK & Middleware (Zone 1)
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the MIT License — See LICENSE file.
 *
 * Zero-dependency client entry point for `require('obsx-security')` / `import { verifyToken, middleware } from 'obsx-security'`.
 */

const http = require('http');
const https = require('https');

const DEFAULT_ENDPOINT = 'https://obsx.tech/api/v1';
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 65536;
const MAX_CLIENT_UA_LEN = 512;
const MAX_HEADER_LEN = 256;

let cachedCore = null;
let cachedCrypto = null;
let cachedTelemetry = null;
let cachedKv = null;

function getCoreModule() {
  if (!cachedCore) cachedCore = require('./core');
  return cachedCore;
}

function getCryptoModule() {
  if (!cachedCrypto) cachedCrypto = require('./crypto');
  return cachedCrypto;
}

function getTelemetryModule() {
  if (!cachedTelemetry) cachedTelemetry = require('./telemetry');
  return cachedTelemetry;
}

function getKvModule() {
  if (!cachedKv) cachedKv = require('./kv');
  return cachedKv;
}

function buildRejectVerdict(code, text, detail) {
  return {
    ok: false,
    verdict: 'reject',
    allowed: false,
    mode: 'enforce',
    risk: 100,
    sealed: 'none',
    reasons: [
      {
        code,
        weight: 100,
        detail: detail || text,
        text,
      },
    ],
  };
}

function sanitizeHeaderValue(value, maxLen = MAX_HEADER_LEN) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\r\n\0]+/g, ' ').trim().slice(0, maxLen);
}

function getHeaderCaseInsensitive(headers, targetKey) {
  if (!headers || typeof headers !== 'object') return undefined;
  const lower = targetKey.toLowerCase();
  if (headers[lower] !== undefined) return headers[lower];
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return headers[key];
  }
  return undefined;
}

function isHttpRequestObject(val) {
  return Boolean(
    val &&
      typeof val === 'object' &&
      val.headers &&
      typeof val.headers === 'object' &&
      (typeof val.method === 'string' || typeof val.url === 'string')
  );
}

function resolveSecretKey(options = {}) {
  const key =
    options.secretKey ||
    options.secret ||
    process.env.OBSX_SECRET_KEY ||
    process.env.OBSX_SECRET ||
    '';
  return typeof key === 'string' ? sanitizeHeaderValue(key, 512) : '';
}

function resolveEndpointUrl(options = {}) {
  const raw = options.endpoint || process.env.OBSX_ENDPOINT || DEFAULT_ENDPOINT;
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('Invalid OBSX endpoint URL');
  }
  const normalized = raw.trim().replace(/\/+$/, '').replace(/\/verify$/i, '');
  const targetStr = `${normalized}/verify`;
  const parsed = new URL(targetStr);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Unsupported OBSX endpoint protocol');
  }
  parsed.username = '';
  parsed.password = '';
  parsed.hash = '';
  return parsed;
}

function extractVerifyRequest(tokenOrPayload, options = {}) {
  let reqObj = null;
  let source = tokenOrPayload;

  if (isHttpRequestObject(tokenOrPayload)) {
    reqObj = tokenOrPayload;
    source = tokenOrPayload.body;
  }

  const headers = (reqObj && reqObj.headers) || options.headers || null;
  const headerToken = sanitizeHeaderValue(getHeaderCaseInsensitive(headers, 'x-obsx-token'), 4096);
  const headerNonce = sanitizeHeaderValue(getHeaderCaseInsensitive(headers, 'x-obsx-nonce'), 256);

  const clientUa = sanitizeHeaderValue(
    options.clientUa || getHeaderCaseInsensitive(headers, 'user-agent') || '',
    MAX_CLIENT_UA_LEN
  );

  const clientIp =
    sanitizeHeaderValue(
      options.clientIp ||
        (reqObj && reqObj.ip) ||
        (reqObj && reqObj.socket && reqObj.socket.remoteAddress) ||
        '',
      128
    ) || undefined;

  // String token fast-path (no unnecessary data forwarded)
  if (typeof source === 'string') {
    const trimmed = source.trim();
    const nonce = options.nonce !== undefined ? String(options.nonce) : headerNonce || undefined;
    if (!trimmed) {
      return { hasToken: false, body: {}, clientUa, clientIp };
    }
    return {
      hasToken: true,
      body: nonce !== undefined ? { token: trimmed, nonce } : { token: trimmed },
      clientUa,
      clientIp,
    };
  }

  // Sealed payload path: preserve exact payload shape for HMAC action-seal verification
  if (source && typeof source === 'object' && (source.obsx || source.seal || source.advisory)) {
    const container = source.obsx || source.seal || source.advisory;
    const tok =
      (container && typeof container.token === 'string' && container.token.trim()) ||
      (typeof source.token === 'string' && source.token.trim()) ||
      headerToken;
    return {
      hasToken: Boolean(tok),
      body: { ...source },
      clientUa,
      clientIp,
    };
  }

  // Unsealed object/form submission: extract strictly token + nonce so PII (passwords, emails) stays local
  const obj = source && typeof source === 'object' ? source : {};
  const rawToken =
    obj.token ??
    obj['obsx-token'] ??
    obj.obsxToken ??
    headerToken ??
    '';
  const token = typeof rawToken === 'string' ? rawToken.trim() : '';
  const rawNonce =
    obj.nonce ??
    obj['obsx-nonce'] ??
    obj.obsxNonce ??
    options.nonce ??
    (headerNonce || undefined);

  if (!token) {
    return { hasToken: false, body: {}, clientUa, clientIp };
  }

  const body = { token };
  if (typeof rawNonce === 'string' || typeof rawNonce === 'number') {
    const nonceStr = String(rawNonce);
    if (nonceStr !== '') body.nonce = nonceStr;
  }

  return {
    hasToken: true,
    body,
    clientUa,
    clientIp,
  };
}

function postJson(urlObj, payload, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(payload);
    const transport = urlObj.protocol === 'https:' ? https : http;
    const req = transport.request(
      {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: `${urlObj.pathname}${urlObj.search}`,
        method: 'POST',
        agent: false,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          Accept: 'application/json',
          Connection: 'close',
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        let size = 0;
        let overflowed = false;

        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            overflowed = true;
            req.destroy(new Error('OBSX verification response exceeded size limit'));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          if (overflowed) return;
          const raw = Buffer.concat(chunks).toString('utf8');
          try {
            const parsed = JSON.parse(raw);
            resolve({ statusCode: res.statusCode || 500, data: parsed });
          } catch {
            reject(new Error('Invalid JSON response from OBSX verify endpoint'));
          }
        });
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('OBSX verification request timed out'));
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function verifyLocal(extracted, options) {
  const core = getCoreModule();
  const secretKey = resolveSecretKey(options);

  let project = options.project || null;
  if (!project && secretKey) {
    project = await core.projectBySecretKey(secretKey);
    if (!project) {
      return buildRejectVerdict('unauthorized', 'Invalid OBSX secret key for local verification');
    }
  }
  if (!project && options.projectId) {
    project = await core.loadProject(String(options.projectId));
  }
  if (!project) {
    return buildRejectVerdict(
      'missing_secret_key',
      'Local verification requires project, projectId, or valid secretKey'
    );
  }

  return core.verify(project, extracted.body, {
    ip: extracted.clientIp,
    ua: extracted.clientUa,
    proxyHeaders: Array.isArray(options.proxyHeaders) ? options.proxyHeaders : [],
    headers: options.headers || {},
    serverToServer: true,
  });
}

/**
 * Verify an OBSX attestation token, form payload, request object, or sealed JSON body.
 * Always fails closed (returns `{ ok: false, allowed: false, verdict: 'reject', risk: 100 }`)
 * when credentials are missing, token is absent, or upstream verification fails.
 */
async function verifyToken(tokenOrPayload, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const extracted = extractVerifyRequest(tokenOrPayload, opts);

  if (!extracted.hasToken) {
    return buildRejectVerdict('missing_token', 'Missing OBSX attestation token');
  }

  if (opts.local === true || opts.project) {
    return verifyLocal(extracted, opts);
  }

  const secretKey = resolveSecretKey(opts);
  if (!secretKey) {
    return buildRejectVerdict(
      'missing_secret_key',
      'Missing OBSX secret key (pass { secretKey } or set OBSX_SECRET_KEY)'
    );
  }

  let endpointUrl;
  try {
    endpointUrl = resolveEndpointUrl(opts);
  } catch (err) {
    return buildRejectVerdict('invalid_endpoint', err.message || 'Invalid OBSX endpoint');
  }

  const timeoutRaw = Number(opts.timeoutMs);
  const timeoutMs = Number.isFinite(timeoutRaw)
    ? Math.max(250, Math.min(30000, timeoutRaw))
    : DEFAULT_TIMEOUT_MS;

  const requestHeaders = {
    Authorization: `Bearer ${secretKey}`,
    'User-Agent': 'obsx-security-node/2.2',
  };
  if (extracted.clientUa) {
    requestHeaders['X-OBSX-Client-UA'] = extracted.clientUa;
  }

  try {
    const { statusCode, data } = await postJson(endpointUrl, extracted.body, requestHeaders, timeoutMs);
    if (!data || typeof data !== 'object' || statusCode < 200 || statusCode >= 300 || data.ok === false) {
      const code = (data && data.error) || (statusCode === 401 ? 'unauthorized' : 'verification_error');
      const text = (data && data.message) || `OBSX verification failed (HTTP ${statusCode})`;
      return buildRejectVerdict(code, text);
    }

    const allowed =
      typeof data.allowed === 'boolean'
        ? data.allowed
        : data.verdict === 'accept' || data.verdict === 'observe';

    return {
      ...data,
      ok: true,
      allowed,
    };
  } catch (err) {
    return buildRejectVerdict('verification_unreachable', err.message || 'OBSX verification request failed');
  }
}

function sendJsonResponse(res, statusCode, payload) {
  if (typeof res.status === 'function' && typeof res.json === 'function') {
    return res.status(statusCode).json(payload);
  }
  if (!res.headersSent) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  }
  res.end(JSON.stringify(payload));
  return undefined;
}

/**
 * One-line Express / Connect / Node HTTP middleware protecting any route handler.
 * Populates `req.obsx` with the verified OBSX verdict object.
 */
function middleware(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const allowReview = opts.blockReview === true ? false : opts.allowReview !== false;
  const rejectStatus = Number.isInteger(opts.statusCode) && opts.statusCode >= 400 && opts.statusCode < 600
    ? opts.statusCode
    : 403;

  return async function obsxMiddleware(req, res, next) {
    try {
      const result = await verifyToken(req, opts);
      req.obsx = result;

      const blockedByReview = !allowReview && result.verdict === 'review';
      if (!result || result.allowed !== true || blockedByReview) {
        if (typeof opts.onReject === 'function') {
          return await opts.onReject(result, req, res, next);
        }
        return sendJsonResponse(res, rejectStatus, {
          ok: false,
          error: 'obsx_rejected',
          verdict: (result && result.verdict) || 'reject',
          risk: (result && typeof result.risk === 'number') ? result.risk : 100,
          reasons: (result && result.reasons) || [],
        });
      }

      if (typeof next === 'function') {
        return next();
      }
      return result;
    } catch (err) {
      if (typeof opts.onReject === 'function') {
        return opts.onReject(buildRejectVerdict('verification_error', err.message || 'Verification failed'), req, res, next);
      }
      return sendJsonResponse(res, rejectStatus, {
        ok: false,
        error: 'obsx_verification_failed',
        verdict: 'reject',
        risk: 100,
        reasons: [],
      });
    }
  };
}

function verifyActionSeal(...args) {
  return getCryptoModule().verifyActionSeal(...args);
}

const api = {
  verifyToken,
  verify: verifyToken,
  middleware,
  protect: middleware,
  verifyActionSeal,
};

Object.defineProperties(api, {
  core: {
    enumerable: true,
    get: getCoreModule,
  },
  crypto: {
    enumerable: true,
    get: getCryptoModule,
  },
  telemetry: {
    enumerable: true,
    get: getTelemetryModule,
  },
  kv: {
    enumerable: true,
    get: getKvModule,
  },
  getKv: {
    enumerable: true,
    get: () => getKvModule().getKv,
  },
  MemoryStore: {
    enumerable: true,
    get: () => getKvModule().MemoryStore,
  },
});

module.exports = api;
