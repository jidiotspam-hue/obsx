'use strict';

// Load local environment configuration if present (.env)
require('./lib/config');

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const core = require('./lib/core');
const accounts = require('./lib/accounts');
const crypto = require('./lib/crypto');
const mailer = require('./lib/mailer');
const updater = require('./lib/updater');
const { getKv } = require('./lib/kv');

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
        resolve(text.trim() ? JSON.parse(text) : {});
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

function getClientIp(req) {
  if (process.env.TRUST_PROXY === 'true') {
    if (req.headers['cf-connecting-ip']) {
      return String(req.headers['cf-connecting-ip']).trim();
    }
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (xff.length > 0) return xff[xff.length - 1];
  }
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : '127.0.0.1';
}

function isRequestHttps(req) {
  if (req.socket && req.socket.encrypted) return true;
  if (req.headers['x-forwarded-proto'] === 'https') return true;
  if (req.headers['cf-visitor']) {
    try {
      return JSON.parse(req.headers['cf-visitor']).scheme === 'https';
    } catch {
      // ignore
    }
  }
  return process.env.NODE_ENV === 'production';
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

function isStrictGateActive() {
  const isTestRunner =
    process.env.NODE_ENV === 'test' ||
    process.argv.some((a) => a.includes('test'));
  return (
    process.env.STRICT_GATE === 'true' ||
    process.env.NODE_ENV === 'production' ||
    (!isTestRunner && process.env.STRICT_GATE !== 'false')
  );
}

async function gateSelfRequest(req, body, actionName) {
  const token = (body && body.token) || req.headers['x-obsx-token'];
  const nonce = (body && body.nonce) || req.headers['x-obsx-nonce'];
  const isStrict = isStrictGateActive();

  if (!token) {
    if (isStrict) {
      return {
        allowed: false,
        statusCode: 403,
        error: 'security_gate_rejected',
        reasons: [{ code: 'missing_token', weight: 100, text: `Attestation token is required for ${actionName}.` }],
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
  });

  if (verdict.allowed === false || (isStrict && verdict.verdict !== 'accept')) {
    return {
      allowed: false,
      statusCode: 403,
      error: 'security_gate_rejected',
      reasons: verdict.reasons,
      verdict,
    };
  }

  return { allowed: true, verdict };
}

const server = http.createServer(async (req, res) => {
  const clientIp = getClientIp(req);
  const isHttps = isRequestHttps(req);
  const proxyHeaders = detectProxyHeaders(req);
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const method = req.method;

  // Global Hardened Security Headers
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self';"
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
        const body = await readBody(req);
        const project = await core.projectByPublicKey(body.site);
        if (!project) return sendJson(res, 404, { ok: false, error: 'unknown_site' }, CORS_HEADERS);

        const session = await core.startSession(project, {
          ip: clientIp,
          ua: req.headers['user-agent'],
          origin: req.headers.origin || '',
          proxyHeaders,
          mode: body.mode || undefined,
        });
        return sendJson(res, 200, { ok: true, ...session }, CORS_HEADERS);
      }

      // 2. Signal Recording (Public SDK Entry)
      if (pathname === '/api/v1/signal') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const body = await readBody(req);
        const result = await core.recordSignals(body, { ip: clientIp, proxyHeaders });
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
        const verdict = await core.verify(project, body, { ip: clientIp, proxyHeaders, headers: req.headers, ua: req.headers['user-agent'] });
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
          requireBiometrics: isStrictGateActive(),
        });
        res.setHeader('X-OBSX-Mode', verdict.mode || 'enforce');
        if (verdict.shadowVerdict) res.setHeader('X-OBSX-Shadow-Verdict', verdict.shadowVerdict);
        return sendJson(res, 200, verdict, CORS_HEADERS);
      }

      // 5. User Auth - Email OTP (Passwordless Login / Registration)
      // Guarded by OBSX Client Attestation & Cryptographic PoW
      if (pathname === '/api/v1/auth/email') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const body = await readBody(req);

        // Guard authentication with OBSX Attestation Gate
        const action = body.action === 'verify' ? 'Operator Sign-In Verification' : 'Operator OTP Request';
        const gate = await gateSelfRequest(req, body, action);
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
        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Operator Create Project');
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
        const user = await accounts.getSessionUser(req);
        if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });

        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Security Alert Dispatch Probe');
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          });
        }

        // Strictly constrain alert dispatches to the authenticated operator email (Prevents Open Mail Relay)
        const targetEmail = user.email;

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
        const user = await accounts.getSessionUser(req);
        if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });

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
        return sendJson(res, 200, telemetry, CORS_HEADERS);
      }

      // 11b-2. Runtime Version, Build Attestation & Upstream Auto-Updater Status
      if (pathname === '/api/v1/system/version') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET', 'OPTIONS']);
        const info = updater.getSystemVersionInfo();
        res.setHeader('X-OBSX-Build', `${info.version}-${info.shortCommit}-${info.edition}`);
        return sendJson(res, 200, info, CORS_HEADERS);
      }

      if (pathname === '/api/v1/system/update') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const user = await accounts.getSessionUser(req);
        const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1';
        if (!user && !isLoopback) {
          return sendJson(res, 401, { ok: false, error: 'unauthorized' });
        }
        const updateRes = await updater.checkAndApplyUpstreamUpdate({ force: true });
        return sendJson(res, 200, { ok: true, ...updateRes, versionInfo: updater.getSystemVersionInfo() });
      }

      if (pathname === '/api/v1/system/diff') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
        const user = await accounts.getSessionUser(req);
        const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1';
        if (!user && !isLoopback) {
          return sendJson(res, 401, { ok: false, error: 'unauthorized' });
        }
        return sendJson(res, 200, updater.getUpstreamCodeDiff());
      }

      if (pathname === '/api/v1/system/adapt') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
        const user = await accounts.getSessionUser(req);
        const isLoopback = clientIp === '127.0.0.1' || clientIp === '::1';
        if (!user && !isLoopback) {
          return sendJson(res, 401, { ok: false, error: 'unauthorized' });
        }
        const adaptRes = updater.autoAdaptDirtyNode();
        return sendJson(res, adaptRes.ok ? 200 : 409, adaptRes);
      }

      if (pathname === '/api/v1/sentinel/ring') {
        if (method !== 'GET') return sendMethodNotAllowed(res, ['GET', 'OPTIONS']);
        const ring = await core.getGlobalThreatRing();
        return sendJson(res, 200, ring, CORS_HEADERS);
      }

      // 11c. High-Stakes Vault Payment & Scratch Exploit Arena
      if (pathname === '/api/v1/vault/drain') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const body = await readBody(req);
        const result = await core.processVaultDrain({
          mode: body.mode || 'obsx',
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
        return sendJson(res, 200, result, CORS_HEADERS);
      }

      if (pathname === '/api/v1/vault/reset') {
        if (method !== 'POST') return sendMethodNotAllowed(res, ['POST', 'OPTIONS']);
        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Reset Security Vault Pool');
        if (!gate.allowed) {
          return sendJson(res, gate.statusCode || 403, {
            ok: false,
            error: gate.error || 'security_gate_rejected',
            reasons: gate.reasons,
            verdict: gate.verdict,
          }, CORS_HEADERS);
        }
        const result = await core.resetVault();
        return sendJson(res, 200, result, CORS_HEADERS);
      }

      // 12. Project Settings Management & Secret Key Rotation
      if (pathname.startsWith('/api/v1/project/')) {
        // Rotate key: POST /api/v1/project/:pid/rotate-key
        if (pathname.endsWith('/rotate-key')) {
          if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const pid = pathname.slice('/api/v1/project/'.length, -'/rotate-key'.length);
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });

          const body = await readBody(req);
          const gate = await gateSelfRequest(req, body, 'Operator Rotate Secret Key');
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
        if (pathname.endsWith('/settings')) {
          if (method !== 'PATCH' && method !== 'POST') return sendMethodNotAllowed(res, ['PATCH', 'POST']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const pid = pathname.slice('/api/v1/project/'.length, -'/settings'.length);
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          const body = await readBody(req);

          const gate = await gateSelfRequest(req, body, 'Operator Update Project Settings');
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
        if (pathname.endsWith('/circuit-breaker')) {
          if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const pid = pathname.slice('/api/v1/project/'.length, -'/circuit-breaker'.length);
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          return sendJson(res, 200, {
            ok: true,
            hasSentinel: false,
            message: 'Managed cloud feature on obsx.tech',
          });
        }

        // Circuit Breaker Reset: POST /api/v1/project/:pid/circuit-breaker/reset
        if (pathname.endsWith('/circuit-breaker/reset')) {
          if (method !== 'POST') return sendMethodNotAllowed(res, ['POST']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const pid = pathname.slice('/api/v1/project/'.length, -'/circuit-breaker/reset'.length);
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });

          const body = await readBody(req);
          const gate = await gateSelfRequest(req, body, 'Operator Reset Circuit Breaker');
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
        if (pathname.endsWith('/telemetry')) {
          if (method !== 'GET') return sendMethodNotAllowed(res, ['GET']);
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized', message: 'Operator session required' });
          const pid = pathname.slice('/api/v1/project/'.length, -'/telemetry'.length);
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found', message: 'Project not found or unauthorized' });

          const token = req.headers['x-obsx-token'];
          if (token) {
            const gate = await gateSelfRequest(req, null, 'Operator Project Telemetry Query');
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
            upstreamAdvisory: updater.getOperatorDriftAdvisory(),
            ...telemetry,
          });
        }

        // Get project details: GET /api/v1/project/:pid
        if (method === 'GET') {
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const pid = pathname.slice('/api/v1/project/'.length);
          const project = await core.loadProject(pid);
          if (!project || project.owner !== user.uid) return sendJson(res, 404, { ok: false, error: 'project_not_found' });
          return sendJson(res, 200, { ok: true, project });
        }

        // Delete project: DELETE /api/v1/project/:pid
        if (method === 'DELETE') {
          const user = await accounts.getSessionUser(req);
          if (!user) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
          const pid = pathname.slice('/api/v1/project/'.length);

          const body = await readBody(req);
          const gate = await gateSelfRequest(req, body, 'Operator Delete Project');
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
      function getCallerUid(user, req, clientIp) {
        if (user) return user.uid;
        const cookies = (req && req.headers ? req.headers.cookie : '') || '';
        const guestCookieMatch = cookies.match(/obsx_guest=([A-Za-z0-9_-]+)/);
        const guestHeader = (req && req.headers ? req.headers['x-guest-id'] : '') || '';
        const guestSecret = (guestCookieMatch ? guestCookieMatch[1] : '') || guestHeader;
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
          const uid = getCallerUid(user, req, clientIp);
          const body = await readBody(req);
          const mode = body.protectionMode || 'obsx';

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
              action: 'Save Protected Note',
              requireBiometrics: isStrictGateActive(),
            });
            if (verificationVerdict.allowed === false || verificationVerdict.verdict !== 'accept') {
              console.log('[NOTES REJECTED BY OBSX]', verificationVerdict);
              return sendJson(res, 403, {
                ok: false,
                error: 'security_violation',
                protection: 'obsx',
                verdict: verificationVerdict,
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
                verdict: verificationVerdict,
              });
            }
          }

          const note = await core.createUserNote(uid, {
            title: body.title || 'Untitled Note',
            content: body.content || '',
            category: body.category || 'General',
            protection: mode,
          });

          return sendJson(res, 201, {
            ok: true,
            note,
            verdict: verificationVerdict,
          });
        }

        return sendMethodNotAllowed(res, ['GET', 'POST']);
      }

      // Delete Note
      if (pathname.startsWith('/api/v1/notes/')) {
        if (method !== 'DELETE') return sendMethodNotAllowed(res, ['DELETE']);
        const user = await accounts.getSessionUser(req);
        const uid = getCallerUid(user, req, clientIp);
        const noteId = pathname.slice('/api/v1/notes/'.length);

        const body = await readBody(req);
        const gate = await gateSelfRequest(req, body, 'Delete Protected Note');
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
      const targetScript = path.resolve(PUBLIC_DIR, scriptFile);

      if (targetScript.startsWith(PUBLIC_DIR + path.sep) && fs.existsSync(targetScript)) {
        const stat = await fsp.stat(targetScript);
        const etag = `W/"${stat.size.toString(16)}-${stat.mtimeMs.toString(16)}"`;
        const cacheControl =
          versionTag === 'latest'
            ? 'public, max-age=3600, stale-while-revalidate=86400'
            : 'public, max-age=31536000, immutable';

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
    const decodedPath = decodeURIComponent(pathname);
    let targetPath = path.resolve(PUBLIC_DIR, '.' + (decodedPath === '/' ? '/index.html' : decodedPath));
    if (!targetPath.startsWith(PUBLIC_DIR + path.sep) && targetPath !== PUBLIC_DIR) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Access denied');
    }

    try {
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

// Track keep-alive connections for clean teardown
server.on('connection', (socket) => {
  activeSockets.add(socket);
  socket.on('close', () => activeSockets.delete(socket));
});

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
  server.listen(PORT, () => {
    console.log(`[OBSX Security] Server listening on http://localhost:${PORT}`);
    updater.startAutoUpdater();
  });
}

module.exports = server;