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
const stream = require('stream');
const net = require('net');

const DEFAULT_ENDPOINT = 'https://obsx.tech/api/v1';
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 65536;
const MAX_CLIENT_UA_LEN = 512;
const MAX_HEADER_LEN = 256;
const INTERNAL_HTTP_REQUEST = Symbol('obsx.internalHttpRequest');

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
  if (typeof headers.get === 'function') {
    const val = headers.get(targetKey) ?? headers.get(targetKey.toLowerCase());
    return val === null ? undefined : val;
  }
  const lower = targetKey.toLowerCase();
  if (headers[lower] !== undefined) return headers[lower];
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return headers[key];
  }
  return undefined;
}

function parseCompatToken(raw) {
  if (typeof raw !== 'string') return { token: '', nonce: undefined };
  const trimmed = raw.trim();
  if (!trimmed) return { token: '', nonce: undefined };
  const sep = trimmed.indexOf('::');
  if (sep > 0) {
    const token = trimmed.slice(0, sep).trim();
    const nonce = trimmed.slice(sep + 2).trim();
    return { token, nonce: nonce || undefined };
  }
  return { token: trimmed, nonce: undefined };
}

function isWebRequest(val) {
  return Boolean(
    val &&
    typeof val === 'object' &&
    typeof val.clone === 'function' &&
    val.headers &&
    typeof val.headers.get === 'function' &&
    (typeof val.json === 'function' || typeof val.text === 'function')
  );
}

function isPlainObject(val) {
  return Boolean(val && typeof val === 'object' && !Array.isArray(val));
}

function hasActionSealFields(val) {
  return (
    isPlainObject(val) &&
    typeof val.sig === 'string' &&
    val.sig.length > 0 &&
    val.ts !== undefined &&
    val.ts !== null
  );
}

function isHttpRequestObject(val, allowDuckTyped = false) {
  if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
  if (!val.headers || typeof val.headers !== 'object') return false;
  if (val instanceof http.IncomingMessage || val instanceof stream.Readable) return true;
  if (typeof val.method === 'string' || typeof val.url === 'string') {
    if (allowDuckTyped) return true;
    // Require non-JSON-serializable runtime traits so parsed req.body objects cannot impersonate req
    return (
      typeof val.on === 'function' ||
      typeof val.pipe === 'function' ||
      typeof val.get === 'function' ||
      typeof val.header === 'function' ||
      val.socket instanceof net.Socket ||
      Boolean(val.raw && val.raw instanceof stream.Readable)
    );
  }
  return false;
}

function resolveSecretKey(options = {}) {
  const key =
    options.secretKey ||
    options.secret ||
    process.env.OBSX_SECRET_KEY ||
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
  const allowDuckTyped = Boolean(options && options[INTERNAL_HTTP_REQUEST]);

  if (isHttpRequestObject(tokenOrPayload, allowDuckTyped)) {
    reqObj = tokenOrPayload;
    source = tokenOrPayload.body;
  }

  const headers = (reqObj && reqObj.headers) || options.headers || {};
  const headerToken = sanitizeHeaderValue(getHeaderCaseInsensitive(headers, 'x-obsx-token'), 4096);
  const headerNonce = sanitizeHeaderValue(getHeaderCaseInsensitive(headers, 'x-obsx-nonce'), 256);

  const hasClientUa = Boolean(
    reqObj ||
      options.clientUa !== undefined ||
      (options.headers && typeof options.headers === 'object' && 'user-agent' in options.headers) ||
      (options.headers && typeof options.headers === 'object' && 'User-Agent' in options.headers)
  );

  const clientUa = sanitizeHeaderValue(
    options.clientUa !== undefined
      ? options.clientUa
      : getHeaderCaseInsensitive(headers, 'user-agent') || '',
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

  // String token fast-path (supports compact compat "token::nonce" format)
  if (typeof source === 'string') {
    const parsed = parseCompatToken(source);
    const nonce =
      typeof options.nonce === 'string' || typeof options.nonce === 'number'
        ? String(options.nonce)
        : parsed.nonce !== undefined
        ? parsed.nonce
        : headerNonce || undefined;
    if (!parsed.token) {
      return { hasToken: false, body: {}, clientUa, hasClientUa, clientIp, headers };
    }
    return {
      hasToken: true,
      body: nonce !== undefined && nonce !== '' ? { token: parsed.token, nonce } : { token: parsed.token },
      clientUa,
      hasClientUa,
      clientIp,
      headers,
    };
  }

  // Sealed payload path: preserve exact payload shape only when real HMAC action-seal fields exist
  const sealedContainer =
    (isPlainObject(source) && hasActionSealFields(source.obsx) && source.obsx) ||
    (isPlainObject(source) && hasActionSealFields(source.seal) && source.seal) ||
    (isPlainObject(source) && hasActionSealFields(source.advisory) && source.advisory) ||
    null;
  const isFlatSeal = isPlainObject(source) && hasActionSealFields(source);

  if (sealedContainer || isFlatSeal) {
    const tok =
      (sealedContainer && typeof sealedContainer.token === 'string' && sealedContainer.token.trim()) ||
      (typeof source.token === 'string' && source.token.trim()) ||
      (typeof source['obsx-token'] === 'string' && source['obsx-token'].trim()) ||
      headerToken;
    const body = { ...source };
    if (!body.token && !body['obsx-token'] && !(sealedContainer && sealedContainer.token) && headerToken) {
      body.token = headerToken;
    }
    if (
      body.nonce === undefined &&
      body['obsx-nonce'] === undefined &&
      !(sealedContainer && sealedContainer.nonce !== undefined)
    ) {
      const fallbackNonce =
        typeof options.nonce === 'string' || typeof options.nonce === 'number'
          ? String(options.nonce)
          : headerNonce;
      if (fallbackNonce !== undefined && fallbackNonce !== '') {
        body.nonce = fallbackNonce;
      }
    }
    return {
      hasToken: Boolean(tok),
      body,
      clientUa,
      hasClientUa,
      clientIp,
      headers,
    };
  }

  // Unsealed object/form submission: extract strictly token + nonce so PII (passwords, emails) stays local
  const obj = isPlainObject(source) ? source : {};
  const nestedContainer =
    (isPlainObject(obj.obsx) && obj.obsx) ||
    (isPlainObject(obj.seal) && obj.seal) ||
    (isPlainObject(obj.advisory) && obj.advisory) ||
    null;
  const compatResponseRaw =
    obj['g-recaptcha-response'] ??
    obj['cf-turnstile-response'] ??
    obj['h-captcha-response'] ??
    '';
  const compatParsed = parseCompatToken(typeof compatResponseRaw === 'string' ? compatResponseRaw : '');
  const rawToken =
    (nestedContainer && nestedContainer.token) ||
    obj.token ||
    obj['obsx-token'] ||
    obj.obsxToken ||
    headerToken ||
    compatParsed.token ||
    '';
  const token = typeof rawToken === 'string' ? rawToken.trim() : '';
  const rawNonce =
    (nestedContainer && nestedContainer.nonce) ??
    (obj.nonce !== '' ? obj.nonce : undefined) ??
    (obj['obsx-nonce'] !== '' ? obj['obsx-nonce'] : undefined) ??
    (obj.obsxNonce !== '' ? obj.obsxNonce : undefined) ??
    options.nonce ??
    compatParsed.nonce ??
    (headerNonce || undefined);

  if (!token) {
    return { hasToken: false, body: {}, clientUa, hasClientUa, clientIp, headers };
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
    hasClientUa,
    clientIp,
    headers,
  };
}

function postJson(urlObj, payload, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const succeed = (val) => {
      if (!settled) {
        settled = true;
        resolve(val);
      }
    };
    const fail = (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const bodyStr = JSON.stringify(payload);
    const transport = urlObj.protocol === 'https:' ? https : http;
    const req = transport.request(
      {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: `${urlObj.pathname}${urlObj.search}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          Accept: 'application/json',
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        let size = 0;

        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            const err = new Error('OBSX verification response exceeded size limit');
            fail(err);
            req.destroy(err);
            return;
          }
          chunks.push(chunk);
        });

        res.on('error', fail);
        res.on('close', () => {
          if (!settled && !res.complete) {
            fail(new Error('OBSX verification response truncated'));
          }
        });

        res.on('end', () => {
          if (settled) return;
          const raw = Buffer.concat(chunks).toString('utf8');
          try {
            const parsed = JSON.parse(raw);
            succeed({ statusCode: res.statusCode || 500, data: parsed });
          } catch {
            fail(new Error('Invalid JSON response from OBSX verify endpoint'));
          }
        });
      }
    );

    req.setTimeout(timeoutMs, () => {
      const err = new Error('OBSX verification request timed out');
      fail(err);
      req.destroy(err);
    });
    req.on('error', fail);
    req.write(bodyStr);
    req.end();
  });
}

async function verifyLocal(extracted, options) {
  try {
    const core = getCoreModule();
    const explicitKey = sanitizeHeaderValue(options.secretKey || options.secret || '', 512);
    const resolvedKey = resolveSecretKey(options);

    let project = options.project || null;
    if (!project && explicitKey) {
      project = await core.projectBySecretKey(explicitKey);
      if (!project) {
        return buildRejectVerdict('unauthorized', 'Invalid OBSX secret key for local verification');
      }
    }
    if (!project && options.projectId) {
      project = await core.loadProject(String(options.projectId));
    }
    if (!project && !explicitKey && resolvedKey) {
      project = await core.projectBySecretKey(resolvedKey);
      if (!project) {
        return buildRejectVerdict('unauthorized', 'Invalid OBSX secret key for local verification');
      }
    }
    if (!project) {
      return buildRejectVerdict(
        'missing_secret_key',
        'Local verification requires project, projectId, or valid secretKey'
      );
    }

    return await core.verify(project, extracted.body, {
      ip: extracted.clientIp,
      ua: extracted.clientUa,
      hasClientUa: Boolean(extracted.hasClientUa),
      proxyHeaders: Array.isArray(options.proxyHeaders) ? options.proxyHeaders : [],
      headers: extracted.headers || options.headers || {},
      serverToServer: true,
    });
  } catch (err) {
    return buildRejectVerdict('verification_error', err.message || 'Local verification failed');
  }
}

async function verifyExtracted(extracted, opts = {}) {
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
    'User-Agent': 'obsx-security-node/2.3',
  };
  if (extracted.hasClientUa || extracted.clientUa) {
    requestHeaders['X-OBSX-Client-UA'] = extracted.clientUa || '';
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

/**
 * Verify an OBSX attestation token, form payload, request object, or sealed JSON body.
 * Always fails closed (returns `{ ok: false, allowed: false, verdict: 'reject', risk: 100 }`)
 * when credentials are missing, token is absent, or upstream verification fails.
 */
async function verifyToken(tokenOrPayload, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  if (isWebRequest(tokenOrPayload)) {
    const reqHeaders = tokenOrPayload.headers;
    let bodyPayload = {};
    try {
      const cloned = tokenOrPayload.clone();
      const ct = String(reqHeaders.get('content-type') || '').toLowerCase();
      if (ct.includes('application/json')) {
        bodyPayload = await cloned.json();
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        const params = new URLSearchParams(await cloned.text());
        bodyPayload = Object.create(null);
        for (const [k, v] of params.entries()) {
          bodyPayload[k] = v;
        }
      } else if (ct.includes('multipart/form-data') && typeof cloned.formData === 'function') {
        const fd = await cloned.formData();
        bodyPayload = Object.create(null);
        for (const [k, v] of fd.entries()) {
          if (typeof v === 'string') bodyPayload[k] = v;
        }
      } else if (typeof cloned.text === 'function') {
        const rawText = await cloned.text();
        if (rawText && rawText.trim().startsWith('{')) {
          bodyPayload = JSON.parse(rawText);
        }
      }
    } catch {
      bodyPayload = {};
    }
    const mergedOpts = { ...opts, headers: opts.headers || reqHeaders };
    const extracted = extractVerifyRequest(bodyPayload, mergedOpts);
    return verifyExtracted(extracted, mergedOpts);
  }
  const extracted = extractVerifyRequest(tokenOrPayload, opts);
  return verifyExtracted(extracted, opts);
}

function sendJsonResponse(res, statusCode, payload) {
  if (!res || res.headersSent) return undefined;
  if (typeof res.status === 'function' && typeof res.json === 'function') {
    return res.status(statusCode).json(payload);
  }
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
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
    let result;
    try {
      const extracted = extractVerifyRequest(req, { ...opts, [INTERNAL_HTTP_REQUEST]: true });
      result = await verifyExtracted(extracted, opts);
    } catch (err) {
      const failVerdict = buildRejectVerdict('verification_error', err.message || 'Verification failed');
      if (req && typeof req === 'object') req.obsx = failVerdict;
      if (typeof opts.onReject === 'function') {
        return opts.onReject(failVerdict, req, res, next);
      }
      return sendJsonResponse(res, rejectStatus, {
        ok: false,
        error: 'obsx_verification_failed',
        verdict: 'reject',
        risk: 100,
        reasons: failVerdict.reasons,
      });
    }

    if (req && typeof req === 'object') req.obsx = result;

    const blockedByReview = !allowReview && result && result.verdict === 'review';
    if (!result || result.allowed !== true || blockedByReview) {
      if (typeof opts.onReject === 'function') {
        return opts.onReject(result, req, res, next);
      }
      return sendJsonResponse(res, rejectStatus, {
        ok: false,
        error: 'obsx_rejected',
        verdict: (result && result.verdict) || 'reject',
        risk: (result && typeof result.risk === 'number') ? result.risk : 100,
        reasons: (result && result.reasons) || [],
      });
    }

    // Invoke downstream middleware/handler outside verification error catch
    if (typeof next === 'function') {
      return next();
    }
    return result;
  };
}

function verifyActionSeal(...args) {
  return getCryptoModule().verifyActionSeal(...args);
}

// Keep top-level export names statically analyzable for Node ESM named imports (cjs-module-lexer)
exports.verifyToken = verifyToken;
exports.verify = verifyToken;
exports.verifyRequest = verifyToken;
exports.middleware = middleware;
exports.protect = middleware;
exports.verifyActionSeal = verifyActionSeal;

Object.defineProperties(exports, {
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
