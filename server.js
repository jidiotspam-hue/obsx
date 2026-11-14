'use strict';

/**
 * OBSX Security — HTTP Operator Server Harness & Telemetry Broadcaster
 * Copyright (c) 2026 Alexis Grimmace.
 * Licensed under the Elastic License 2.0 + OBSX Zone 2 Terms — See LICENSE file.
 */

// Load local environment configuration if present (.env)
require('./lib/config');

const http = require('http');
const net = require('net');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const core = require('./lib/core');
const accounts = require('./lib/accounts');
const crypto = require('./lib/crypto');
const mailer = require('./lib/mailer');
const updater = require('./lib/updater');
const { getKv } = require('./lib/kv');
const botshield = require('./lib/botshield');

const PKG_VERSION = (() => {
  try {
    return String(JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')).version || '2.3.0');
  } catch {
    return '2.3.0';
  }
})();
const ALLOWED_SDK_FILES = new Set(['obsx.min.js', 'obsx.js']);

const BIND = process.env.OBSX_BIND || "0.0.0.0";
const PORT = parseInt(process.env.PORT || '3000', 10);
const PUBLIC_DIR = path.resolve(__dirname, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.txt': 'text/plain; charset=utf-8',
};

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-OBSX-Site',
  'Access-Control-Max-Age': '86400',
};

function readBody(req, maxBytes = 512 * 1024, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const rawCt = String((req.headers && req.headers['content-type']) || '').trim().toLowerCase();
    if (rawCt && !rawCt.includes('application/json')) {
      req.resume();
      return reject(new Error('Unsupported Content-Type'));
    }

    const chunks = [];
    let received = 0;
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy(new Error('Body read timeout'));
      reject(new Error('Body read timeout'));
    }, timeoutMs);

    req.on('data', (chunk) => {
      if (settled) return;
      received += chunk.length;
      if (received > maxBytes) {
        settled = true;
        clearTimeout(timer);
        req.pause();
        return reject(new Error('Payload too large'));
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (chunks.length === 0) return resolve({});
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        if (!text.trim()) return resolve({});
        const parsed = JSON.parse(text);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return reject(new Error('Invalid JSON'));
        }
        resolve(parsed);
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

function sendJson(res, statusCode, data, headers = {}) {
  const body = JSON.stringify(data);
  const finalHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  };
  res.writeHead(statusCode, finalHeaders);
  res.end(body);
}

function sendMethodNotAllowed(res, allowedMethods) {
  sendJson(res, 405, { ok: false, error: 'method_not_allowed' }, {
    Allow: allowedMethods.join(', '),
  });
}

function ipv4ToUint32(octets) {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function ipMatchesCidr(parsedIp, cidrText) {
  if (!parsedIp || !cidrText) return false;
  const slashIdx = cidrText.indexOf('/');
  const baseStr = slashIdx >= 0 ? cidrText.slice(0, slashIdx).trim() : cidrText.trim();
  const base = crypto.parseCanonicalIp(baseStr);
  if (!base || base.family !== parsedIp.family) return false;
  if (slashIdx < 0) return base.ip === parsedIp.ip;
  const prefixLen = Number(cidrText.slice(slashIdx + 1).trim());
  const maxBits = parsedIp.family === 4 ? 32 : 128;
  if (!Number.isInteger(prefixLen) || prefixLen < 0 || prefixLen > maxBits) return false;
  if (parsedIp.family === 4) {
    const mask = prefixLen === 0 ? 0 : (0xffffffff << (32 - prefixLen)) >>> 0;
    return (ipv4ToUint32(parsedIp.octets) & mask) === (ipv4ToUint32(base.octets) & mask);
  }
  let bits = prefixLen;
  for (let i = 0; i < 8 && bits > 0; i++) {
    const take = Math.min(16, bits);
    const mask = (0xffff << (16 - take)) & 0xffff;
    if ((parsedIp.groups[i] & mask) !== (base.groups[i] & mask)) return false;
    bits -= take;
  }
  return true;
}

function isTrustedProxyPeer(rawSocketIp) {
  const parsed = crypto.parseCanonicalIp(rawSocketIp);
  if (!parsed) return false;
  if (parsed.isLoopback) return true;
  const rawList = String(process.env.TRUSTED_PROXY_CIDRS || '').trim();
  if (!rawList) return false;
  for (const cidr of rawList.split(',')) {
    const entry = cidr.trim();
    if (entry && ipMatchesCidr(parsed, entry)) return true;
  }
  return false;
}

// Trusted-hop IP resolution: proxy headers are honored ONLY when TRUST_PROXY=true
// AND the direct TCP socket peer is loopback or in TRUSTED_PROXY_CIDRS.
// Walks X-Forwarded-For right-to-left skipping trusted proxies to avoid spoofing.
function getClientIp(req) {
  const rawSocketIp = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '127.0.0.1';
  const socketIp = crypto.normalizeIp(rawSocketIp) || '127.0.0.1';
  if (process.env.TRUST_PROXY === 'true' && isTrustedProxyPeer(rawSocketIp)) {
    const cf = String(req.headers['cf-connecting-ip'] || '').trim();
    if (cf && cf.length <= 45 && net.isIP(cf) !== 0) {
      return crypto.normalizeIp(cf) || cf;
    }
    const xffRaw = String(req.headers['x-forwarded-for'] || '');
    if (xffRaw) {
      const hops = xffRaw.split(',').map((s) => s.trim()).filter(Boolean);
      for (let i = hops.length - 1; i >= 0; i--) {
        const hop = hops[i];
        if (hop.length <= 45 && net.isIP(hop) !== 0) {
          if (!isTrustedProxyPeer(hop) || i === 0) {
            return crypto.normalizeIp(hop) || hop;
          }
        }
      }
    }
  }
  return socketIp;
}

function isRequestHttps(req) {
  if (req.socket && req.socket.encrypted) return true;
  const rawSocketIp = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '127.0.0.1';
  if (process.env.TRUST_PROXY === 'true' && isTrustedProxyPeer(rawSocketIp)) {
    const xfp = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    if (xfp === 'https') return true;
    if (xfp === 'http') return false;
    if (req.headers['cf-visitor']) {
      try {
        return JSON.parse(req.headers['cf-visitor']).scheme === 'https';
      } catch {
        // ignore
      }
    }
  }
  return false;
}

function detectProxyHeaders(req) {
  const headers = req.headers || {};
  const suspicious = [];
  if (headers['x-bare-host'] || headers['x-bare-headers']) suspicious.push('bare_mux_protocol');
  if (headers['x-wisp-version']) suspicious.push('wisp_tunnel');
  if (headers['x-uv-original-url'] || headers['x-uv-origin']) suspicious.push('ultraviolet_proxy');
  if (headers['x-rammerhead-proxy'] || headers['x-proxy-user-agent']) suspicious.push('rammerhead_proxy');
  if (headers['x-sovereign-proxy'] || headers['x-sovereign-gateway'] || headers['x-ss-internal-proxy']) suspicious.push('sovereign_gateway');
  if (headers['x-canary-token']) suspicious.push('canary_probe');
  if (typeof headers['via'] === 'string' && /squid|varnish|haproxy|tinyproxy|anon|proxy/i.test(headers['via'])) {
    suspicious.push(`via_header:${headers['via'].slice(0, 30)}`);
  }
  return suspicious;
}

// Global active connections map for graceful termination
const activeSockets = new Set();

function hasValidOperatorKey(req) {
  const dedicatedOpKey = String(process.env.OBSX_OPERATOR_KEY || '');
  const headerVal = String(req.headers['x-obsx-operator-key'] || req.headers['x-obsx-key'] || '');
  if (dedicatedOpKey.length >= 16) {
    return crypto.safeEqual(headerVal, dedicatedOpKey);
  }
  const operatorSecret = String(process.env.OBSX_SECRET || '');
  if (operatorSecret.length < 16) return false;
  return crypto.safeEqual(headerVal, operatorSecret);
}

function hasValidCloudRingKey(req) {
  const cloudKey = String(process.env.OBSX_CLOUD_KEY || '').trim();
  if (cloudKey.length < 16) return false;
  const headerKey = String(req.headers['x-obsx-cloud-key'] || '');
  return crypto.safeEqual(headerKey, cloudKey);
}

function getOperatorAllowlist() {
  const configured = [
    process.env.OPERATOR_EMAILS,
    process.env.OBSX_OPERATOR_EMAILS,
    process.env.OPERATOR_EMAIL,
  ]
    .filter(Boolean)
    .flatMap((v) => String(v).split(','))
    .map((e) => accounts.cleanEmail(e))
    .filter(Boolean);
  return new Set(configured);
}

function isOperatorAuthorized(req, user) {
  if (hasValidOperatorKey(req)) return true;
  if (!user || !user.email) return false;
  const normalized = accounts.cleanEmail(user.email);
  return Boolean(normalized && getOperatorAllowlist().has(normalized));
}

function isTrustedSameOriginMutation(req, isHttps = false) {
  const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    return false;
  }
  const reqHost = String(req.headers.host || '').toLowerCase();
  const expectedProto = isHttps ? 'https:' : 'http:';
  const origin = req.headers.origin;
  const referer = req.headers.referer;
  if (typeof origin === 'string' && origin.trim()) {
    try {
      const parsed = new URL(origin);
      if (!reqHost || parsed.host.toLowerCase() !== reqHost || parsed.protocol !== expectedProto) {
        return false;
      }
    } catch {
      return false;
    }
  } else if (typeof referer === 'string' && referer.trim()) {
    try {
      const parsedRef = new URL(referer);
      if (!reqHost || parsedRef.host.toLowerCase() !== reqHost || parsedRef.protocol !== expectedProto) {
        return false;
      }
    } catch {
      return false;
    }
  }
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (contentType && !contentType.includes('application/json') && !req.headers['x-requested-with']) {
    return false;
  }
  if (origin || referer || secFetchSite) {
    const method = String(req.method || 'GET').toUpperCase();
    const hasDeclaredBody = Number(req.headers['content-length'] || 0) > 0 || Boolean(req.headers['transfer-encoding']);
    if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && hasDeclaredBody && !contentType.includes('application/json') && !req.headers['x-requested-with']) {
      return false;
    }
  }
  return true;
}

async function requireOperatorAccess(req, res, isHttps = false) {
  if (hasValidOperatorKey(req)) return { via: 'key', email: null };
  const user = await accounts.getSessionUser(req);
  if (!user) {
    sendJson(res, 401, { ok: false, error: 'unauthorized' });
    return null;
  }
  if (!isOperatorAuthorized(req, user)) {
    sendJson(res, 403, { ok: false, error: 'operator_required' });
    return null;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD' && !isTrustedSameOriginMutation(req, isHttps)) {
    sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
    return null;
  }
  return { via: 'session', email: accounts.cleanEmail(user.email) };
}

function parseRequestUrl(req) {
  const rawUrl = typeof req.url === 'string' ? req.url : '/';
  const normalized = rawUrl.startsWith('//') ? '/' + rawUrl.replace(/^\/+/, '') : rawUrl;
  try {
    const rawHost = typeof req.headers.host === 'string' ? req.headers.host : 'localhost';
    const safeHost = /^[a-zA-Z0-9._:\[\]-]+$/.test(rawHost) ? rawHost : 'localhost';
    return new URL(normalized, `http://${safeHost}`);
  } catch {
    return null;
  }
}

function isValidResourceId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id);
}

function isStrictGateActive() {
  const isTestRunner =
    process.env.NODE_ENV === 'test' ||
    process.env.OBSX_TEST_MODE === '1';
  return (
    process.env.STRICT_GATE === 'true' ||
    process.env.NODE_ENV === 'production' ||
    (!isTestRunner && process.env.STRICT_GATE !== 'false')
  );
}

// Authenticated operator actions: soft kinematic risk is tolerated, hard bot
// indicators (no token, invalid PoW, headless UA, proxy headers, missing telemetry,
// circuit breaker) still block.
const OPERATOR_GATE = { selfAuth: true, allowReview: true, settingsOverride: { reviewAt: 50, rejectAt: 90 } };

async function gateSelfRequest(req, body, actionName, opts = {}) {
  const token = (body && body.token) || req.headers['x-obsx-token'];
  const nonce = (body && body.nonce) || req.headers['x-obsx-nonce'];
  const isStrict = isStrictGateActive();
  // allowReview: soft (kinematic) risk is tolerated; hard bot indicators still block.
  const allowReview = opts.allowReview === true;

  if (!token) {
    if (isStrict) {
      return {
        allowed: false,
        statusCode: 403,
        error: 'security_gate_rejected',
        reasons: [{ code: 'missing_token' }],
      };
    }
    return { allowed: true };
  }

  const project = await core.loadProject(core.DEMO.pid);
  const verdict = await core.verify(project, { ...body, token, nonce }, {
    ip: getClientIp(req),
    proxyHeaders: detectProxyHeaders(req),
    headers: req.headers,
    ua: req.headers['user-agent'],
    action: actionName,
    requireBiometrics: isStrict,
    selfAuth: opts.selfAuth === true,
    settingsOverride: opts.settingsOverride || null,
  });

  if (verdict.allowed === false || (isStrict && !allowReview && verdict.verdict !== 'accept')) {
    return {
      allowed: false,
      statusCode: 403,
      error: 'security_gate_rejected',
    // Never ship the scoring model to the caller: codes only, no weights,
    // no risk total, no internal details. Full detail stays in the logs.
    reasons: (verdict.reasons || []).map((r) => ({ code: r.code })),
    verdict: { allowed: false, verdict: verdict.verdict, mode: verdict.mode, sealed: verdict.sealed },
  };
  }

  return { allowed: true, verdict };
}

// --- Load shedding: survive sustained connection floods. ---
const startedAt = Date.now();
// Thresholds sized for a 1 GB, 4-core origin. The old defaults (900 req/s,
// 900 in-flight, 8000 connections) are server-class numbers: the guard only
// fired once the box was already saturated, so every request in between was
// served slowly and timed out at the edge.
// Capacity and volume rules live in lib/botshield.js: one place to tune, and
// testable without a running server. The server's job is measurement only —
// open sockets, in-flight requests, request rate.
const pageCache = new Map();

function staticEntry(targetPath) {
  const now = Date.now();
  const hit = pageCache.get(targetPath);
  if (hit && now - hit.at < 30000) return hit;
  const body = fs.readFileSync(targetPath);
  const ext = path.extname(targetPath).toLowerCase();
  const entry = {
    at: now,
    body,
    size: body.length,
    etag: 'W/"' + body.length.toString(16) + '-' + crypto.sha256(body).slice(0, 10) + '"',
    contentType: MIME_TYPES[ext] || 'application/octet-stream',
    // Cacheable on purpose: an edge cache absorbs repeat hits so the origin
    // only sees one fetch per TTL instead of one per request.
    cacheControl: ext === '.html'
      ? 'public, max-age=60, stale-while-revalidate=300'
      : ext === '.js'
        ? 'public, max-age=3600, stale-while-revalidate=86400'
        : 'public, max-age=86400',
  };
  pageCache.set(targetPath, entry);
  return entry;
}
let activeConnections = 0;
let inFlight = 0;
let shedCount = 0;
let reqWindowStart = Date.now();
let reqWindowCount = 0;
let reqRate = 0;

function tickRate() {
  const now = Date.now();
  if (now - reqWindowStart >= 1000) {
    reqRate = Math.round(reqWindowCount * 1000 / (now - reqWindowStart));
    reqWindowStart = now;
    reqWindowCount = 0;
  }
  reqWindowCount++;
  return reqRate;
}

// --- Origin-side evidence. ---
// Cloudflare hides client IPs from the tunnel logs, so the origin keeps its own
// picture of which paths are being hammered. Volume control itself lives in
// lib/botshield.js.
const pathHits = new Map();          // path -> hits in the current reporting window
let lastSentinelLog = Date.now();

function recordPathHit(pathname) {
  pathHits.set(pathname, (pathHits.get(pathname) || 0) + 1);
  if (pathHits.size > 400) pathHits.clear();
  const now = Date.now();
  if (now - lastSentinelLog < 60000) return;
  lastSentinelLog = now;
  if (reqRate > 20) {
    const topPaths = [...pathHits.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([p, c]) => `${p}=${c}`)
    console.log(
      `[OBSX Sentinel] ${new Date().toISOString()} reqRate=${reqRate} conns=${activeConnections} inFlight=${inFlight} latency=${botshield.stats(false).health.workLatencyMs}ms topPaths: ${topPaths}`
    );
  }
  pathHits.clear();
}

// Public responses may report *that* a rule fired, never how it is scored.
function trimVerdict(v) {
  if (!v || typeof v !== 'object') return v;
  return {
    ok: v.ok !== false,
    allowed: Boolean(v.allowed),
    verdict: v.verdict,
    risk: v.risk,
    mode: v.mode,
    sealed: v.sealed,
    reasons: (v.reasons || []).map((r) => ({ code: r.code })),
  };
}

// Session issuance and note posting budgets cap per-IP burst abuse.
const sessionIssueBudget = new Map();
const notePostBudget = new Map();
function withinRateBudget(budgetMap, ip, limit, windowMs = 60000, maxEntries = 20000) {
  const now = Date.now();
  const entry = budgetMap.get(ip);
  if (!entry || now >= entry.reset) {
    if (budgetMap.size > maxEntries) {
      for (const [k, v] of budgetMap) if (now >= v.reset) budgetMap.delete(k);
    }
    budgetMap.set(ip, { count: 1, reset: now + windowMs });
    return true;
  }
  entry.count++;
  return entry.count <= limit;
}

function withinSessionBudget(ip) {
  return withinRateBudget(sessionIssueBudget, ip, Number(process.env.OBSX_SESSION_BUDGET || 40));
}

function withinNotePostBudget(ip) {
  return withinRateBudget(notePostBudget, ip, Number(process.env.OBSX_NOTE_POST_BUDGET || 20));
}

const shedOffenders = new Map();   // ip -> {count, reason, first}
function noteShed(ip, reason) {
  const e = shedOffenders.get(ip) || { count: 0, reason, first: Date.now() };
  e.count++;
  shedOffenders.set(ip, e);
  if (shedOffenders.size > 5000) {
    for (const [k, v] of shedOffenders) if (Date.now() - v.first > 120000) shedOffenders.delete(k);
  }
  if (shedCount % 50 === 0) {
    // Bounded top-6 scan: sorting a 5000-entry table every 50 sheds is itself a
    // cost the origin pays while it is being flooded.
    const top = [];
    for (const [ip, e] of shedOffenders) {
      if (top.length < 6) {
        top.push([ip, e]);
        if (top.length === 6) top.sort((a, b) => b[1].count - a[1].count);
      } else if (e.count > top[5][1].count) {
        top[5] = [ip, e];
        for (let k = 4; k >= 0 && top[k][1].count < top[k + 1][1].count; k--) {
          const t = top[k]; top[k] = top[k + 1]; top[k + 1] = t;
        }
      }
    }
    const line = top.map(([ip, e]) => `${ip}=${e.count}(${e.reason})`).join(' ');
    console.log(`[OBSX Shed] ${new Date().toISOString()} shedding ${shedCount} total; top offenders: ${line}`);
  }
}


const server = http.createServer(async (req, res) => {
  const clientIp = getClientIp(req);
  const isHttps = isRequestHttps(req);
  const proxyHeaders = detectProxyHeaders(req);
  const url = parseRequestUrl(req);
  if (!url) {
    return sendJson(res, 400, { ok: false, error: 'invalid_request' });
  }
  const pathname = url.pathname;
  const method = req.method;

  const reqRateNow = tickRate();
  inFlight++;
  const arrivedAt = Date.now();

  // Bot Protection is the first thing any request meets. It owns capacity,
  // budgets, challenges and quarantine, and it measures its own health (RSS,
  // event-loop lag, served rate) so the decision to refuse happens before any
  // application work starts.
  const shield = botshield.evaluate(req, res, clientIp, pathname, reqRateNow, url, {
    activeConnections,
    inFlight,
  });
  res.on('close', () => {
    inFlight--;
    if (!shield.handled) botshield.noteWorkLatency(Date.now() - arrivedAt, clientIp);
  });

  if (shield.handled) return;

  if (pathname === '/api/v1/health') {
    const bs = botshield.stats();
    return sendJson(res, 200, {
      ok: true, uptime: Math.round((Date.now() - startedAt) / 1000),
      activeConnections, inFlight, shed: shedCount, reqRate,
      workLatencyMs: bs.health.workLatencyMs,
      rssMb: bs.health.rssMb,
      eventLagMs: bs.health.eventLagMs,
      botShield: {
        enabled: bs.enabled, mode: bs.mode, engaged: bs.engaged,
        difficultyBits: bs.difficultyBits,
        challenged: bs.counters.challenged, solved: bs.counters.solved,
        blocked: bs.counters.blocked, quarantined: bs.counters.quarantined,
        shed: bs.counters.shed,
        byTier: bs.counters.byTier,
      },
    });
  }

  // The volume gate covers every path, not just /api/: the flood that took
  // this origin down hit "/" exclusively, and "/" was never rate-limited.
  recordPathHit(pathname);

  // Global Hardened Security Headers
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (isHttps) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self';"
  );

  try {
    // --- 0. Global OpenAI / ChatGPT Scraper Gate, Google SEO Sitemap & robots.txt Policy ---
    const reqUa = req.headers['user-agent'] || '';
    const globalBlockOpenAi = process.env.BLOCK_OPENAI_SCRAPERS !== 'false';
    if (pathname === '/robots.txt' && (method === 'GET' || method === 'HEAD')) {
      const robotsTxt = globalBlockOpenAi
        ? '# get your own ram\nUser-agent: GPTBot\nDisallow: /\n\nUser-agent: ChatGPT-User\nDisallow: /\n\nUser-agent: OAI-SearchBot\nDisallow: /\n\nUser-agent: Googlebot\nAllow: /\n\nUser-agent: Googlebot-Image\nAllow: /\n\nUser-agent: Google-InspectionTool\nAllow: /\n\nUser-agent: *\nAllow: /\n\nSitemap: https://obsx.tech/sitemap.xml\n'
        : 'User-agent: Googlebot\nAllow: /\n\nUser-agent: *\nAllow: /\n\nSitemap: https://obsx.tech/sitemap.xml\n';
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(method === 'HEAD' ? undefined : robotsTxt);
    }

    if (pathname === '/sitemap.xml' && (method === 'GET' || method === 'HEAD')) {
      const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://obsx.tech/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://obsx.tech/docs.html</loc>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://obsx.tech/dashboard.html</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://obsx.tech/notes.html</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>`;
      res.writeHead(200, { 'Content-Type': 'application/xml; charset=utf-8' });
      return res.end(method === 'HEAD' ? undefined : sitemapXml);
    }

    const isTenantVerifyOrSession =
      pathname === '/api/v1/verify' ||
      pathname === '/api/v1/session' ||
      pathname === '/api/v1/signal' ||
      pathname === '/dram-dark.jpg' ||
      pathname === '/dram-light.jpg' ||
      pathname === '/dram-stick.svg';
    const reqReferer = req.headers.referer || req.headers.referrer || '';
    if (globalBlockOpenAi && !isTenantVerifyOrSession && core.isOpenAiScraperUa(reqUa, reqReferer, url.search)) {
      res.setHeader('X-OBSX-Policy', 'get your own ram');
      const acceptHeader = req.headers.accept || '';
      if (acceptHeader.includes('text/html') && !pathname.startsWith('/api/')) {
        res.writeHead(403, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-OBSX-Policy': 'get your own ram',
        });
        return res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>403 Forbidden — get your own ram</title>
  <style>
    body { background: #090d16; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 24px; box-sizing: border-box; overflow: hidden; position: relative; }
    .dram-sky { position: fixed; inset: 0; pointer-events: none; z-index: 1; overflow: hidden; }
    .dram-balloon { position: absolute; bottom: -140px; display: flex; flex-direction: column; align-items: center; animation: floatUp linear infinite; opacity: 0.9; filter: drop-shadow(0 8px 16px rgba(0,0,0,0.6)); }
    .dram-balloon img { width: 110px; height: auto; image-rendering: pixelated; border-radius: 6px; }
    .dram-string { width: 1.5px; height: 55px; background: linear-gradient(to bottom, rgba(250,204,21,0.85), rgba(255,255,255,0.05)); margin-top: -4px; }
    .dram-tag { font-size: 10px; font-weight: 700; color: #facc15; background: rgba(17,24,39,0.9); border: 1px solid rgba(250,204,21,0.4); padding: 2px 6px; border-radius: 4px; margin-top: 2px; white-space: nowrap; }
    @keyframes floatUp {
      0% { transform: translateY(0) rotate(-3deg); opacity: 0; }
      10% { opacity: 0.92; }
      50% { transform: translateY(-55vh) rotate(4deg); }
      90% { opacity: 0.92; }
      100% { transform: translateY(-120vh) rotate(-3deg); opacity: 0; }
    }
    .card { position: relative; z-index: 10; max-width: 660px; width: 100%; background: rgba(17, 24, 39, 0.94); backdrop-filter: blur(10px); border: 1px solid #ef4444; border-radius: 14px; padding: 32px; box-shadow: 0 24px 60px rgba(0,0,0,0.75); text-align: center; }
    .dram-hero-imgs { display: flex; justify-content: center; align-items: center; gap: 18px; margin-bottom: 18px; }
    .dram-hero-imgs img { height: 74px; width: auto; image-rendering: pixelated; border-radius: 8px; border: 1px solid rgba(255,255,255,0.12); background: #000; padding: 4px; }
    .badge { display: inline-block; padding: 4px 10px; background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.4); border-radius: 6px; font-size: 12px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
    h1 { font-size: 40px; margin: 14px 0 10px; color: #ffffff; letter-spacing: -0.02em; }
    blockquote { text-align: left; margin: 20px 0; padding: 14px 18px; border-left: 3px solid #ef4444; background: rgba(255,255,255,0.03); color: #94a3b8; font-size: 13.5px; line-height: 1.6; border-radius: 0 8px 8px 0; }
    .footer { margin-top: 24px; font-size: 12px; color: #64748b; border-top: 1px solid #1f2937; padding-top: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
    .btn-back { color: #38bdf8; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <div class="dram-sky">
    <div class="dram-balloon" style="left: 6%; animation-duration: 9s; animation-delay: 0s;">
      <img src="/dram-stick.svg" alt="DRAM" /><div class="dram-string"></div><span class="dram-tag">5% Utilized DRAM</span>
    </div>
    <div class="dram-balloon" style="left: 20%; animation-duration: 11s; animation-delay: 2s;">
      <img src="/dram-dark.jpg" alt="DRAM" /><div class="dram-string"></div><span class="dram-tag">get your own ram</span>
    </div>
    <div class="dram-balloon" style="left: 36%; animation-duration: 8.5s; animation-delay: 4s;">
      <img src="/dram-light.jpg" alt="DRAM" /><div class="dram-string"></div><span class="dram-tag">Personal Raspberry Pi RAM</span>
    </div>
    <div class="dram-balloon" style="left: 64%; animation-duration: 10.5s; animation-delay: 1s;">
      <img src="/dram-stick.svg" alt="DRAM" /><div class="dram-string"></div><span class="dram-tag">Not for Cloud Scrapers</span>
    </div>
    <div class="dram-balloon" style="left: 78%; animation-duration: 9.5s; animation-delay: 3s;">
      <img src="/dram-dark.jpg" alt="DRAM" /><div class="dram-string"></div><span class="dram-tag">get your own ram</span>
    </div>
    <div class="dram-balloon" style="left: 90%; animation-duration: 12s; animation-delay: 0.5s;">
      <img src="/dram-light.jpg" alt="DRAM" /><div class="dram-string"></div><span class="dram-tag">100% Sovereign DRAM</span>
    </div>
  </div>
  <div class="card">
    <div class="dram-hero-imgs">
      <img src="/dram-dark.jpg" alt="Pixel DRAM Module Dark" />
      <img src="/dram-stick.svg" alt="Pixel DRAM Stick" style="background:transparent; border:none; height:64px;" />
      <img src="/dram-light.jpg" alt="Pixel DRAM Module Light" style="background:#fff;" />
    </div>
    <span class="badge">HTTP 403 · OPENAI / CHATGPT SCRAPER BLOCKED</span>
    <h1>get your own ram</h1>
    <p style="color:#cbd5e1; line-height:1.6; margin: 0 auto; max-width: 540px;">
      This security node runs on dedicated personal hardware DRAM. OpenAI crawlers, ChatGPT agents, and ChatGPT referrals are explicitly denied access.
    </p>
    <blockquote>
      "From a global allocation perspective, actually, it's quite terrible to have everybody have a bunch of the world's limited supply of DRAM sitting in their own computer and being used five percent of the time."
      <br/>— <strong>Sam Altman</strong> (Cheeky Pint Podcast, Oct 29)
    </blockquote>
    <div class="footer">
      <span>Enforced by OBSX Security Gate · Policy: <code>blockOpenAiScrapers=true</code></span>
      <a href="/" class="btn-back">Return to Human Site &rarr;</a>
    </div>
  </div>
</body>
</html>`);
      }
      return sendJson(
        res,
        403,
        { ok: false, error: 'openai_scraper_blocked', message: 'get your own ram' },
        CORS_HEADERS
      );
    }

    // --- 1. CORS Preflight Handling ---
    if (method === 'OPTIONS' && pathname.startsWith('/api/v1/')) {
      res.writeHead(204, CORS_HEADERS);
      return res.end();
    }

    // --- 2. API Routes ---
    if (pathname.startsWith('/api/v1/')) {
      // 1. Session Start (Public SDK Entry)
      if (pathname === '/api/v1/session') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        if (!withinSessionBudget(clientIp)) {
          return sendJson(res, 429, { ok: false, error: 'session_rate_limited', retry_after: 10 }, CORS_HEADERS);
        }
        const body = await readBody(req);
        const project = await core.projectByPublicKey(body.site);
        if (!project) return sendJson(res, 404, { ok: false, error: 'unknown_site' }, CORS_HEADERS);

        const session = await core.startSession(project, {
          ip: clientIp,
          ua: req.headers['user-agent'],
          origin: req.headers.origin || '',
          proxyHeaders,
          fromHttp: true,
          mode: body.mode || undefined,
        });
        return sendJson(res, 200, { ok: true, ...session }, CORS_HEADERS);
      }

      // 2. Signal Recording (Public SDK Entry)
      if (pathname === '/api/v1/signal') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const body = await readBody(req);
        const result = await core.recordSignals(body, {
          ip: clientIp,
          proxyHeaders,
          ua: req.headers['user-agent'],
          origin: req.headers.origin || '',
          fromHttp: true,
        });
        return sendJson(res, result.ok ? 200 : 400, result, CORS_HEADERS);
      }

      // 3. Action Verification (Backend-to-Backend API)
      if (pathname === '/api/v1/verify') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const auth = req.headers.authorization || '';
        const sk = auth.replace(/^Bearer\s+/i, '').trim();
        const project = await core.projectBySecretKey(sk);
        if (!project) {
          return sendJson(
            res,
            401,
            { ok: false, error: 'unauthorized', message: 'Missing or invalid secret key' },
            CORS_HEADERS
          );
        }

        const body = await readBody(req);
        const hasClientUa = 'x-obsx-client-ua' in req.headers;
        const forwardedClientUa =
          typeof req.headers['x-obsx-client-ua'] === 'string'
            ? req.headers['x-obsx-client-ua'].replace(/[\r\n\0]+/g, ' ').trim().slice(0, 512)
            : '';
        const verdict = await core.verify(project, body, {
          ip: clientIp,
          proxyHeaders,
          headers: req.headers,
          ua: forwardedClientUa,
          hasClientUa,
          serverToServer: true,
        });
        res.setHeader('X-OBSX-Mode', verdict.mode || 'enforce');
        if (verdict.shadowVerdict) res.setHeader('X-OBSX-Shadow-Verdict', verdict.shadowVerdict);
        return sendJson(res, 200, verdict, CORS_HEADERS);
      }

      // 4. Sandbox / Interactive Demo Verification
      if (pathname === '/api/v1/demo') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const body = await readBody(req);
        const project = await core.loadProject(core.DEMO.pid);
        const verdict = await core.verify(project, body, {
          ip: clientIp,
          proxyHeaders,
          headers: req.headers,
          ua: req.headers['user-agent'],
          fromHttp: true,
          hasClientUa: true,
          requireBiometrics: isStrictGateActive(),
        });
        res.setHeader('X-OBSX-Mode', verdict.mode || 'enforce');
        if (verdict.shadowVerdict) res.setHeader('X-OBSX-Shadow-Verdict', verdict.shadowVerdict);
        // Public demo: show the outcome, not the scoring model. Weights, thresholds
        // and internal details stay server-side.
        return sendJson(res, 200, {
          ok: true,
          allowed: verdict.allowed,
          verdict: verdict.verdict,
          risk: verdict.risk,
          mode: verdict.mode,
          sealed: verdict.sealed,
          reasons: (verdict.reasons || []).map((r) => ({ code: r.code })),
          timestamp: verdict.timestamp || Date.now(),
        }, CORS_HEADERS);
      }

      // 5. User Auth - Email OTP (Passwordless Login / Registration)
      // Guarded by OBSX Client Attestation & Cryptographic PoW
      if (pathname === '/api/v1/auth/email') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const body = await readBody(req);

        // Guard authentication with OBSX Attestation Gate
        const action = body.action === 'verify' ? 'Operator Sign-In Verification' : 'Operator OTP Request';
        const gate = await gateSelfRequest(req, body, action, {
          selfAuth: true,
          allowReview: true,
          settingsOverride: { reviewAt: 50, rejectAt: 90 },
        });
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          });
        }

        if (body.action === 'verify') {
          try {
            const authResult = await accounts.verifyEmailAuth(body.email, body.code, isHttps);
            return sendJson(
              res,
              200,
              { ok: true, uid: authResult.uid, email: authResult.email },
              { 'Set-Cookie': authResult.sessionCookie }
            );
          } catch (err) {
            return sendJson(res, 400, { ok: false, error: err.message });
          }
        } else {
          try {
            const resData = await accounts.startEmailAuth(body.email, clientIp);
            return sendJson(res, 200, resData);
          } catch (err) {
            return sendJson(res, err.status || 400, { ok: false, error: err.message });
          }
        }
      }

      // 6. User Auth - Logout
      if (pathname === '/api/v1/auth/logout') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        if (!isTrustedSameOriginMutation(req, isHttps)) {
          return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
        }
        const result = await accounts.deleteUserSession(req);
        return sendJson(
          res,
          200,
          { ok: true },
          { 'Set-Cookie': result.sessionCookie }
        );
      }

      // 7. Get Current User Profile & Projects
      if (pathname === '/api/v1/me') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        const user = await accounts.getSessionUser(req);
        return sendJson(res, 200, { ok: true, user });
      }

      // 8. List User Projects
      if (pathname === '/api/v1/projects') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        const user = await accounts.getSessionUser(req);
        if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
        return sendJson(res, 200, { ok: true, projects: user.projects || [] });
      }

      // 9. Project Management (Create New Project)
      if (pathname === '/api/v1/project') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const user = await accounts.getSessionUser(req);
        if (!user) {
          return sendJson(res, 401, { ok: false, error: 'unauthorized', message: 'Authentication required to create projects.' });
        }
        if (!isTrustedSameOriginMutation(req, isHttps)) {
          return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
        }
        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Operator Create Project', OPERATOR_GATE);
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          });
        }
        const project = await core.createProject(body, user.uid);
        return sendJson(res, 201, { ok: true, project });
      }

      // 10. Security Alert Dispatcher Test & Incident Stream
      if (pathname === '/api/v1/alert/test') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const op = await requireOperatorAccess(req, res, isHttps);
        if (!op) return;

        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Security Alert Dispatch Probe', OPERATOR_GATE);
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          });
        }

        // Strictly constrain alert dispatches to an allowlisted operator address (Prevents Open Mail Relay)
        const targetEmail = op.email || getOperatorAllowlist().values().next().value || '';
        if (!targetEmail) {
          return sendJson(res, 400, { ok: false, error: 'operator_email_required' });
        }

        const alertRes = await mailer.notifyCriticalIncident({
          code: 'operator_test_probe',
          title: 'Manual Security Dispatch Pipeline Test',
          detail: 'Operator requested outbound verification from official@obsx.tech.',
          clientIp,
          action: 'Dashboard Manual Trigger',
          severity: 'INFO',
          recipient: targetEmail,
        });
        return sendJson(res, 200, { ok: true, ...alertRes });
      }

      if (pathname === '/api/v1/alerts') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        if (!(await requireOperatorAccess(req, res, isHttps))) return;

        const alerts = mailer.getRecentAlerts();
        const mailConfig = mailer.getConfig();
        return sendJson(res, 200, {
          ok: true,
          alerts,
          mailer: {
            configured: mailConfig.isConfigured,
            from: mailConfig.from,
            host: mailConfig.host ? `${mailConfig.host}:${mailConfig.port}` : 'dev_console',
          },
        });
      }

      // 11. Real-time Telemetry & Observability Metrics API
      if (pathname === '/api/v1/metrics') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        const metrics = await core.getLiveMetrics();
        return sendJson(res, 200, { ok: true, metrics }, CORS_HEADERS);
      }

      // 11b. Public Live Attestation Telemetry Stream & Proof of Trust
      if (pathname === '/api/v1/telemetry/live') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        const telemetry = await core.getLiveTelemetry();
        // Detailed recent events and reason breakdowns stay operator-facing; anonymous visitors get totals only.
        const teleUser = await accounts.getSessionUser(req);
        if (!isOperatorAuthorized(req, teleUser) && telemetry && typeof telemetry === 'object') {
          delete telemetry.recentEvents;
          if (telemetry.stats && typeof telemetry.stats === 'object') {
            delete telemetry.stats.topReasons;
          }
        }
        return sendJson(res, 200, telemetry, CORS_HEADERS);
      }

      // 11b-2. Runtime Version, Build Attestation & Upstream Auto-Updater Status
      if (pathname === '/api/v1/system/version') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET', 'OPTIONS']);
        const info = updater.getSystemVersionInfo();
        const opUser = await accounts.getSessionUser(req);
        const isOp = isOperatorAuthorized(req, opUser);
        res.setHeader(
          'X-OBSX-Build',
          isOp ? `${info.version}-${info.shortCommit}-${info.edition}` : String(info.version || PKG_VERSION)
        );
        if (!isOp) {
          return sendJson(res, 200, {
            ok: info.ok,
            product: info.product,
            version: info.version,
            edition: info.edition,
            safeMode: info.safeMode,
            safeModeReason: info.safeModeReason,
            licenseFingerprint: info.licenseFingerprint,
            licensePolicy: info.licensePolicy,
            autoUpdate: {
              enabled: Boolean(info.autoUpdate && info.autoUpdate.enabled),
              httpSyncEnabled: Boolean(info.autoUpdate && info.autoUpdate.httpSyncEnabled),
              autoRestartEnabled: Boolean(info.autoUpdate && info.autoUpdate.autoRestartEnabled),
            },
            timestamp: info.timestamp,
          }, CORS_HEADERS);
        }
        return sendJson(res, 200, info, CORS_HEADERS);
      }

      if (pathname === '/api/v1/system/update') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        // Operator identity required: either configured operator key or operator allowlist email.
        if (!(await requireOperatorAccess(req, res, isHttps))) return;
        const updateRes = await updater.checkAndApplyUpstreamUpdate({ force: true });
        return sendJson(res, 200, { ok: true, ...updateRes, versionInfo: updater.getSystemVersionInfo() });
      }

      if (pathname === '/api/v1/system/diff') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        if (!(await requireOperatorAccess(req, res, isHttps))) return;
        return sendJson(res, 200, updater.getUpstreamCodeDiff());
      }

      if (pathname === '/api/v1/system/adapt') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        if (!(await requireOperatorAccess(req, res, isHttps))) return;
        const adaptRes = updater.autoAdaptDirtyNode();
        return sendJson(res, adaptRes.ok ? 200 : 409, adaptRes);
      }

      if (pathname === '/api/v1/system/license') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        if (!(await requireOperatorAccess(req, res, isHttps))) return;
        return sendJson(res, 200, updater.getLicenseStatus());
      }

      if (pathname === '/api/v1/system/license/accept') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const op = await requireOperatorAccess(req, res, isHttps);
        if (!op) return;
        const result = updater.acceptLicenseTerms({ acceptedBy: op.email || 'operator-key' });
        const status = result.ok ? 200 : (result.statusCode || 409);
        return sendJson(res, status, result);
      }

      if (pathname === '/api/v1/bot-protection') {
        if (method !== 'GET' && method !== 'HEAD') return sendMethodNotAllowed(res, ['GET', 'HEAD']);
        // Full addresses only to whoever holds a configured non-empty operator key.
        const body = JSON.stringify(botshield.stats(hasValidOperatorKey(req)));
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          ...CORS_HEADERS,
        });
        return res.end(method === 'HEAD' ? undefined : body);
      }

      if (pathname === '/api/v1/bot-protection/mode') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        if (!hasValidOperatorKey(req)) {
          return sendJson(res, 401, { ok: false, error: 'invalid_key' });
        }
        const body = await readBody(req);
        if (!botshield.setMode(body && body.mode)) {
          return sendJson(res, 400, { ok: false, error: 'invalid_mode' });
        }
        return sendJson(res, 200, botshield.stats(true));
      }

      if (pathname === '/api/v1/sentinel/ring') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        if (!hasValidCloudRingKey(req) && !(await requireOperatorAccess(req, res, isHttps))) return;
        const ring = await core.getGlobalThreatRing();
        const syncSecret = String(process.env.OBSX_CLOUD_SYNC_SECRET || '').trim();
        if (syncSecret && ring && Array.isArray(ring.activeSubnets)) {
          const ts = Date.now();
          ring.ts = ts;
          ring.sig = crypto.hmac(crypto.canon({ ts, activeSubnets: ring.activeSubnets }), syncSecret);
        }
        return sendJson(res, 200, ring);
      }

      // 11c. High-Stakes Vault Payment & Scratch Exploit Arena
      if (pathname === '/api/v1/vault/drain') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const body = await readBody(req);
        // Vault evaluation enforces full OBSX cryptographic verification regardless of caller hints.
        const result = await core.processVaultDrain({
          mode: 'obsx',
          token: body.token,
          nonce: body.nonce,
          signals: body.signals,
          attackVector: body.attackVector,
          amount: body.amount || 500,
          clientIp,
          proxyHeaders,
          ua: req.headers['user-agent'] || '',
          requireBiometrics: isStrictGateActive(),
        });
        if (result && result.verdict && Array.isArray(result.verdict.reasons)) {
          result.verdict.reasons = result.verdict.reasons.map((r) => ({ code: r.code }));
        }
        return sendJson(res, 200, result, CORS_HEADERS);
      }

      if (pathname === '/api/v1/vault/reset') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        if (!(await requireOperatorAccess(req, res, isHttps))) return;
        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Reset Security Vault Pool', OPERATOR_GATE);
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          });
        }
        const result = await core.resetVault();
        return sendJson(res, 200, result);
      }

      // 12. Project Settings Management & Secret Key Rotation
      if (pathname.startsWith('/api/v1/project/')) {
        const sub = pathname.slice('/api/v1/project/'.length);
        const actionSuffix = [
          '/rotate-key',
          '/settings',
          '/circuit-breaker/reset',
          '/circuit-breaker',
          '/telemetry',
        ].find((s) => sub.endsWith(s)) || '';
        const pid = actionSuffix ? sub.slice(0, -actionSuffix.length) : sub;
        if (!isValidResourceId(pid)) {
          return sendJson(res, 400, { ok: false, error: 'invalid_id' });
        }

        // Rotate key: POST /api/v1/project/:pid/rotate-key
        if (actionSuffix === '/rotate-key') {
          if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          if (!isTrustedSameOriginMutation(req, isHttps)) return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });

          const body = await readBody(req);
          const gate = await gateSelfRequest(req, body, 'Operator Rotate Secret Key', OPERATOR_GATE);
          if (!gate.allowed) {
            return sendJson(res, gate.statusCode || 403, {
              ok: false,
              error: gate.error || 'security_gate_rejected',
              reasons: gate.reasons,
              verdict: gate.verdict,
            });
          }

          const rotated = await core.rotateProjectSecretKey(pid);
          return sendJson(res, 200, { ok: true, ...rotated });
        }

        // Update settings: PATCH /api/v1/project/:pid/settings
        if (actionSuffix === '/settings') {
          if (method !== 'PATCH' && method !== 'POST') return sendMethodNotAllowed(res, ['PATCH', 'POST']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          if (!isTrustedSameOriginMutation(req, isHttps)) return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          const body = await readBody(req);

          const gate = await gateSelfRequest(req, body, 'Operator Update Project Settings', OPERATOR_GATE);
          if (!gate.allowed) {
            return sendJson(res, gate.statusCode || 403, {
              ok: false,
              error: gate.error || 'security_gate_rejected',
              reasons: gate.reasons,
              verdict: gate.verdict,
            });
          }

          const updated = await core.updateProjectSettings(pid, body);
          return sendJson(res, 200, { ok: true, ...updated });
        }

        // Circuit Breaker Status: GET /api/v1/project/:pid/circuit-breaker
        if (actionSuffix === '/circuit-breaker') {
          if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          return sendJson(res, 200, {
            ok: true,
            hasSentinel: false,
            message: 'Managed cloud feature on obsx.tech',
          });
        }

        // Circuit Breaker Reset: POST /api/v1/project/:pid/circuit-breaker/reset
        if (actionSuffix === '/circuit-breaker/reset') {
          if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          if (!isTrustedSameOriginMutation(req, isHttps)) return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });

          const body = await readBody(req);
          const gate = await gateSelfRequest(req, body, 'Operator Reset Circuit Breaker', OPERATOR_GATE);
          if (!gate.allowed) {
            return sendJson(res, gate.statusCode || 403, {
              ok: false,
              error: gate.error || 'security_gate_rejected',
              reasons: gate.reasons,
              verdict: gate.verdict,
            });
          }

          return sendJson(res, 200, { ok: true, reset: false, message: 'Managed cloud feature' });
        }

        // Tenant Project Telemetry: GET /api/v1/project/:pid/telemetry
        if (actionSuffix === '/telemetry') {
          if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized', message: 'Operator session required' });
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found', message: 'Project not found or unauthorized' });

          const token = req.headers['x-obsx-token'];
          if (token) {
            const gate = await gateSelfRequest(req, null, 'Operator Project Telemetry Query', OPERATOR_GATE);
            if (!gate.allowed) {
              return sendJson(res, gate.statusCode || 403, {
                ok: false,
                error: gate.error || 'security_gate_rejected',
                reasons: gate.reasons,
                verdict: gate.verdict,
              });
            }
          }

          const telemetry = await core.getProjectTelemetry(pid);
          return sendJson(res, 200, {
            ok: true,
            project: {
              pid: project.pid,
              name: project.name,
              publicKey: project.publicKey,
              settings: project.settings,
            },
            upstreamAdvisory: isOperatorAuthorized(req, user) ? updater.getOperatorDriftAdvisory() : null,
            ...telemetry,
          });
        }

        // Get project details: GET /api/v1/project/:pid
        if (method === 'GET') {
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          return sendJson(res, 200, { ok: true, project });
        }

        // Delete project: DELETE /api/v1/project/:pid
        if (method === 'DELETE') {
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          if (!isTrustedSameOriginMutation(req, isHttps)) {
            return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
          }

          const body = await readBody(req);
          const gate = await gateSelfRequest(req, body, 'Operator Delete Project', OPERATOR_GATE);
          if (!gate.allowed) {
            return sendJson(res, gate.statusCode || 403, {
              ok: false,
              error: gate.error || 'security_gate_rejected',
              reasons: gate.reasons,
              verdict: gate.verdict,
            });
          }

          const ok = await core.deleteProject(pid, user.uid);
          if (!ok) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          return sendJson(res, 200, { ok: true, deleted: pid });
        }
      }

      // 11. Notes Application API (Benchmark Arena)
      function extractCookieValue(cookieHeader, targetName) {
        if (!cookieHeader || typeof cookieHeader !== 'string') return '';
        for (const part of cookieHeader.split(';')) {
          const eqIdx = part.indexOf('=');
          if (eqIdx <= 0) continue;
          const name = part.slice(0, eqIdx).trim();
          if (name === targetName) {
            return part.slice(eqIdx + 1).trim();
          }
        }
        return '';
      }

      function getCallerUid(user, req, clientIp) {
        if (user) return user.uid;
        const cookies = (req && req.headers ? req.headers.cookie : '') || '';
        const candidate = extractCookieValue(cookies, 'obsx_guest');
        // x-guest-id is attacker-controlled: anyone could name another guest's
        // mailbox. Only exact obsx_guest cookie values matching expected token format count.
        const guestSecret = /^[A-Za-z0-9_-]{8,128}$/.test(candidate) ? candidate : '';
        if (guestSecret) {
          return `guest_${crypto.sha256(`${clientIp}:${guestSecret}`).slice(0, 14)}`;
        }
        return `guest_${crypto.sha256(clientIp).slice(0, 12)}`;
      }

      // List Notes
      if (pathname === '/api/v1/notes') {
        if (method === 'GET') {
          const user = await accounts.getSessionUser(req);
          const uid = getCallerUid(user, req, clientIp);
          const notes = await core.getUserNotes(uid);
          return sendJson(res, 200, { ok: true, notes, isGuest: !user });
        }

        if (method === 'POST') {
          const user = await accounts.getSessionUser(req);
          if (!isTrustedSameOriginMutation(req, isHttps)) {
            return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
          }
          if (!withinNotePostBudget(clientIp)) {
            return sendJson(res, 429, { ok: false, error: 'rate_limited', retry_after: 60 });
          }
          const uid = getCallerUid(user, req, clientIp);
          const body = await readBody(req);
          const mode = body.protectionMode === 'advisory' ? 'advisory' : 'obsx';

          console.log('[NOTES DEBUG] POST /api/v1/notes', {
            mode,
            hasToken: !!body.token,
            tokenLen: body.token ? body.token.length : 0,
            hasNonce: !!body.nonce,
            clientIp,
          });

          let verificationVerdict = null;
          if (mode === 'obsx') {
            const project = await core.loadProject(core.DEMO.pid);
            verificationVerdict = await core.verify(project, body, {
              ip: clientIp,
              proxyHeaders,
              headers: req.headers,
              ua: req.headers['user-agent'],
              fromHttp: true,
              hasClientUa: true,
              action: 'Save Protected Note',
              requireBiometrics: isStrictGateActive(),
            });
            if (verificationVerdict.allowed === false || verificationVerdict.verdict !== 'accept') {
              console.log('[NOTES REJECTED BY OBSX]', verificationVerdict);
              return sendJson(res, 403, {
                ok: false,
                error: 'security_violation',
                protection: 'obsx',
                verdict: trimVerdict(verificationVerdict),
              });
            }
          } else {
            // Traditional Advisory Simulation (Unattested client model)
            const telemetry = body.telemetry || {};
            let risk = 0;
            const reasons = [];
            if (telemetry.webdriver) {
              risk = 80;
              reasons.push('webdriver_detected');
            }
            verificationVerdict = {
              verdict: risk >= 65 ? 'reject' : 'accept',
              risk,
              reasons,
              note: 'Evaluated under Traditional Advisory model without cryptographic proof-of-work or proxy interception.',
            };
            if (verificationVerdict.verdict === 'reject') {
              return sendJson(res, 403, {
                ok: false,
                error: 'advisory_rejected',
                protection: 'advisory',
                verdict: trimVerdict(verificationVerdict),
              });
            }
          }

          const note = await core.createUserNote(uid, {
            title: String(body.title || 'Untitled Note').slice(0, 120),
            content: String(body.content || '').slice(0, 2000),
            category: String(body.category || 'General').slice(0, 40),
            protection: mode,
          });

          return sendJson(res, 201, {
            ok: true,
            note,
            verdict: trimVerdict(verificationVerdict),
          });
        }

        return sendMethodNotAllowed(res, ['GET', 'POST']);
      }

      // Delete Note
      if (pathname.startsWith('/api/v1/notes/')) {
        if (method !== 'DELETE') return sendMethodNotAllowed(res, ['DELETE']);
        const user = await accounts.getSessionUser(req);
        if (!isTrustedSameOriginMutation(req, isHttps)) {
          return sendJson(res, 403, { ok: false, error: 'cross_origin_forbidden' });
        }
        const uid = getCallerUid(user, req, clientIp);
        const noteId = pathname.slice('/api/v1/notes/'.length);
        if (!isValidResourceId(noteId)) {
          return sendJson(res, 400, { ok: false, error: 'invalid_id' });
        }

        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Delete Protected Note', OPERATOR_GATE);
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          });
        }

        const success = await core.deleteUserNote(uid, noteId);
        return sendJson(res, 200, { ok: success });
      }

      return sendJson(res, 404, { ok: false, error: 'endpoint_not_found' });
    }

    // --- 3. First-Class Pinned SDK & CDN Route Handling ---
    const sdkMatch = pathname.match(/^\/sdk\/(v[0-9\.]+|latest)\/([a-zA-Z0-9_\.-]+\.js)$/);
    if (sdkMatch && (method === 'GET' || method === 'HEAD')) {
      const versionTag = sdkMatch[1];
      const scriptFile = sdkMatch[2];
      const targetScript = ALLOWED_SDK_FILES.has(scriptFile) ? path.resolve(PUBLIC_DIR, scriptFile) : '';

      if (targetScript && targetScript.startsWith(PUBLIC_DIR + path.sep) && fs.existsSync(targetScript)) {
        const stat = await fsp.stat(targetScript);
        const etag = `W/"${stat.size.toString(16)}-${stat.mtimeMs.toString(16)}"`;
        const isCurrentPinnedVersion = versionTag === `v${PKG_VERSION}`;
        const cacheControl = isCurrentPinnedVersion
          ? 'public, max-age=31536000, immutable'
          : 'public, max-age=3600, stale-while-revalidate=86400';

        const headers = {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Content-Length': stat.size,
          'ETag': etag,
          'Cache-Control': cacheControl,
          'Access-Control-Allow-Origin': '*',
          'Timing-Allow-Origin': '*',
          'X-Content-Type-Options': 'nosniff',
          'Last-Modified': stat.mtime.toUTCString(),
        };

        if (req.headers['if-none-match'] === etag) {
          res.writeHead(304, headers);
          return res.end();
        }

        res.writeHead(200, headers);
        if (method === 'HEAD') return res.end();
        return fs.createReadStream(targetScript).pipe(res);
      }
    }

    // --- 4. High-Performance Asynchronous Static File Serving ---
    if (method !== 'GET' && method !== 'HEAD') {
      return sendMethodNotAllowed(res, ['GET', 'HEAD']);
    }

    // Strict path normalization & traversal jail
    let decodedPath;
    try {
      decodedPath = decodeURIComponent(pathname);
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Bad Request');
    }
    if (decodedPath.includes('\0')) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Bad Request');
    }
    let targetPath = path.resolve(PUBLIC_DIR, '.' + (decodedPath === '/' ? '/index.html' : decodedPath));
    if (!targetPath.startsWith(PUBLIC_DIR + path.sep) && targetPath !== PUBLIC_DIR) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Access denied');
    }

    try {
      if (fs.existsSync(targetPath) && fs.statSync(targetPath).isFile()) {
        const entry = staticEntry(targetPath);
        const headers = {
          'Content-Type': entry.contentType,
          'Content-Length': entry.size,
          'ETag': entry.etag,
          'Cache-Control': entry.cacheControl,
          'Access-Control-Allow-Origin': '*',
        };
        if (req.headers['if-none-match'] === entry.etag) {
          res.writeHead(304, headers);
          return res.end();
        }
        res.writeHead(200, headers);
        if (method === 'HEAD') return res.end();
        return res.end(entry.body);
      }
      let stat = await fsp.stat(targetPath);
      if (stat.isDirectory()) {
        targetPath = path.join(targetPath, 'index.html');
        stat = await fsp.stat(targetPath);
      }

      if (stat.isFile()) {
        const ext = path.extname(targetPath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        const etag = `W/"${stat.size.toString(16)}-${stat.mtimeMs.toString(16)}"`;

        // HTTP 304 Conditional Caching Check
        if (req.headers['if-none-match'] === etag) {
          res.writeHead(304, {
            'ETag': etag,
            'Cache-Control': ext === '.html' ? 'public, max-age=0, must-revalidate' : 'public, max-age=3600, stale-while-revalidate=86400',
            'Access-Control-Allow-Origin': '*',
          });
          return res.end();
        }

        const cacheControl = (ext === '.html' || ext === '.js')
          ? 'no-cache, no-store, must-revalidate, max-age=0'
          : 'public, max-age=86400';

        res.writeHead(200, {
          'Content-Type': contentType,
          'Content-Length': stat.size,
          'ETag': etag,
          'Cache-Control': cacheControl,
          'Access-Control-Allow-Origin': '*',
          'Timing-Allow-Origin': '*',
          'Last-Modified': stat.mtime.toUTCString(),
        });

        if (method === 'HEAD') {
          return res.end();
        }

        const stream = fs.createReadStream(targetPath);
        stream.on('error', (streamErr) => {
          console.error('[Stream Error]', streamErr);
          if (!res.headersSent) res.writeHead(500);
          res.end();
        });
        return stream.pipe(res);
      }
    } catch (fsErr) {
      if (fsErr.code !== 'ENOENT') {
        console.error('[Static File Error]', fsErr);
      }
    }

    // 404 Fallback
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('404 Not Found');
  } catch (err) {
    if (err.message === 'Unsupported Content-Type') {
      return sendJson(res, 415, { ok: false, error: 'unsupported_media_type' });
    }
    if (err.message === 'Payload too large') {
      return sendJson(res, 413, { ok: false, error: 'payload_too_large' });
    }
    if (err.message === 'Invalid JSON') {
      return sendJson(res, 400, { ok: false, error: 'invalid_json' });
    }
    if (err.message === 'Body read timeout') {
      return sendJson(res, 408, { ok: false, error: 'request_timeout' });
    }
    console.error('[Server Error]', err);
    if (!res.headersSent) {
      sendJson(res, 500, { ok: false, error: 'internal_error' });
    } else {
      res.end();
    }
  }
});

// Track keep-alive connections for clean teardown, and reclaim half-open ones.
// Without idle timeouts, closed clients leave sockets in CLOSE-WAIT and the
// listen backlog fills up, which eventually stalls the origin.
server.keepAliveTimeout = 5000;
server.headersTimeout = 10000;
server.requestTimeout = 30000;

// One keep-alive socket must not become an endless pipeline: after 100 requests
// on the same connection Node closes it, so a client that reuses one socket
// forever cannot pin an origin worker indefinitely.
server.maxRequestsPerSocket = 100;

// Header floods: a request with thousands of headers costs parsing time and
// memory before it ever reaches a route. Sixty is far above anything a browser
// or a normal client sends.
server.maxHeadersCount = 60;

const peerSockets = new Map();   // peer address -> open sockets

// Idle timeouts follow the shield. Calm origin: browsers keep their connection.
// Engaged origin: a flood socket is worth less than the descriptor it burns, so
// half-open connections are reclaimed in seconds instead of twenty.
let appliedPosture = '';
function applyConnectionPosture() {
  const posture = botshield.connectionPosture();
  const signature = posture.keepAliveTimeoutMs + '/' + posture.idleTimeoutMs;
  if (signature === appliedPosture) return;   // no change: don't reset every socket's timer
  appliedPosture = signature;
  server.keepAliveTimeout = posture.keepAliveTimeoutMs;
  server.headersTimeout = posture.headersTimeoutMs;
  server.requestTimeout = posture.requestTimeoutMs;
  for (const socket of activeSockets) {
    try { socket.setTimeout(posture.idleTimeoutMs, () => socket.destroy()); } catch (err) { /* socket already gone */ }
  }
}
// Reachable for tests and for the dashboard: which posture is in force.
server.applyConnectionPosture = applyConnectionPosture;
setInterval(applyConnectionPosture, 5000).unref();

server.on('connection', (socket) => {
  activeConnections++;
  activeSockets.add(socket);
  socket.setTimeout(botshield.connectionPosture().idleTimeoutMs, () => socket.destroy());

  // One address holding hundreds of sockets is a slowloris-shaped flood, not a
  // visitor. The tunnel multiplexer talks to us over loopback, so it is exempt.
  const peer = socket.remoteAddress || 'unknown';
  const isLoopback = peer === '127.0.0.1' || peer === '::1' || (peer || '').startsWith('::ffff:127.');
  let peerCount = 0;
  if (!isLoopback) {
    peerCount = (peerSockets.get(peer) || 0) + 1;
    peerSockets.set(peer, peerCount);
    if (peerSockets.size > 10000) {
      for (const [k, v] of peerSockets) if (v === 0) peerSockets.delete(k);
    }
  }

  socket.on('close', () => {
    activeConnections--;
    activeSockets.delete(socket);
    if (!isLoopback) {
      const n = (peerSockets.get(peer) || 1) - 1;
      if (n <= 0) peerSockets.delete(peer); else peerSockets.set(peer, n);
    }
  });
  socket.on('error', () => socket.destroy());

  if (!isLoopback && peerCount > botshield.config.maxConnsPerIp) {
    shedCount++;
    noteShed(peer, 'per_ip_conn_ceiling');
    botshield.noteSocketShed(peer, 'per_ip_conn_ceiling');
    writeSocket503(socket, 'per_ip_conn_ceiling', { ok: false, error: 'too_many_connections', retryAfter: 10 }, 10);
    socket.destroy();
    return;
  }

  if (activeConnections > botshield.config.hardConnCeiling) {
    shedCount++;
    noteShed(socket.remoteAddress || 'unknown', 'hard_conn_ceiling');
    botshield.noteSocketShed(socket.remoteAddress || 'unknown', 'hard_conn_ceiling');
    writeSocket503(socket, 'hard_conn_ceiling', { ok: false, error: 'overloaded', retryAfter: 5 }, 5);
    socket.destroy();
  }
});

function writeSocket503(socket, reason, payload, retryAfterSec) {
  const body = JSON.stringify(payload);
  const msg =
    `HTTP/1.1 503 Service Unavailable\r\n` +
    `Content-Type: application/json\r\n` +
    `Retry-After: ${retryAfterSec}\r\n` +
    `Connection: close\r\n` +
    `X-OBSX-BotShield: shed:${reason}\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n` +
    body;
  try {
    socket.write(msg);
  } catch (err) { /* socket already gone */ }
}

// Graceful process termination
function handleShutdown(signal) {
  console.log(`[OBSX Security] Received ${signal}. Draining connections...`);
  server.close(() => {
    console.log('[OBSX Security] Server stopped gracefully.');
    const kv = getKv();
    if (kv.close) kv.close();
    process.exit(0);
  });

  // Force close after 5 seconds if connections linger
  setTimeout(() => {
    console.warn('[OBSX Security] Force closing active connections...');
    for (const socket of activeSockets) {
      socket.destroy();
    }
    const kv = getKv();
    if (kv.close) kv.close();
    process.exit(0);
  }, 5000).unref();
}

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  console.error('[OBSX UnhandledRejection]', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[OBSX UncaughtException]', err);
});

if (require.main === module) {
  server.listen(PORT, BIND, 4096, () => {
    console.log(`[OBSX Security] Server listening on http://localhost:${PORT}`);
    updater.startAutoUpdater();
  });
}

module.exports = server;