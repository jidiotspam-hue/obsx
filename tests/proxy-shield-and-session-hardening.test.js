'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { loadEnv, ENV_FILE_DENYLIST_KEYS } = require('../lib/config');
const botshield = require('../lib/botshield');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const mailer = require('../lib/mailer');
const { MemoryStore, getKv } = require('../lib/kv');

const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const BOT_UA = 'curl/8.5.0';

function makeMockRes() {
  const out = { status: 0, headers: {}, body: '' };
  return {
    out,
    writeHead(status, headers = {}) {
      out.status = status;
      out.headers = { ...out.headers, ...headers };
    },
    end(chunk = '') {
      if (chunk) out.body += String(chunk);
    },
  };
}

function makeMockReq(ua, { method = 'GET', headers = {}, isHttps = false } = {}) {
  const base = ua === BROWSER_UA
    ? {
        'user-agent': ua,
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
      }
    : { 'user-agent': ua };
  return {
    method,
    headers: { ...base, ...headers },
    isHttps,
  };
}

function solveBotShieldPow(challenge, bits) {
  assert.ok(challenge && bits > 0, 'valid PoW challenge and bits required');
  for (let n = 0; n < 1_000_000; n++) {
    if (botshield.powOk(challenge, String(n), bits)) return String(n);
  }
  throw new Error('no PoW nonce found');
}

function parseChallenge(html) {
  const cid = /var cid = "([^"]+)"/.exec(html);
  const ch = /challenge = "([^"]+)"/.exec(html);
  const bits = /bits = (\d+)/.exec(html);
  return {
    cid: cid ? cid[1] : null,
    challenge: ch ? ch[1] : null,
    bits: bits ? Number(bits[1]) : 0,
  };
}

function httpRawRequest(port, reqPath, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: reqPath, method, headers: { Connection: 'close', ...headers } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch {}
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('error', reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

test('config: TRUST_CLOUDFLARE, OBSX_LICENSE_STATE_FILE, and OBSX_UPDATE_TRUSTED_SIGNERS are denylisted from .env', () => {
  assert.ok(ENV_FILE_DENYLIST_KEYS.has('TRUST_CLOUDFLARE'));
  assert.ok(ENV_FILE_DENYLIST_KEYS.has('OBSX_LICENSE_STATE_FILE'));
  assert.ok(ENV_FILE_DENYLIST_KEYS.has('OBSX_UPDATE_TRUSTED_SIGNERS'));

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-cfg-deny-'));
  const envFile = path.join(tmpDir, '.env');
  const saved = {
    TRUST_CLOUDFLARE: process.env.TRUST_CLOUDFLARE,
    OBSX_LICENSE_STATE_FILE: process.env.OBSX_LICENSE_STATE_FILE,
    OBSX_UPDATE_TRUSTED_SIGNERS: process.env.OBSX_UPDATE_TRUSTED_SIGNERS,
    OBSX_TEST_NON_DENY_KEY: process.env.OBSX_TEST_NON_DENY_KEY,
  };

  try {
    delete process.env.TRUST_CLOUDFLARE;
    delete process.env.OBSX_LICENSE_STATE_FILE;
    delete process.env.OBSX_UPDATE_TRUSTED_SIGNERS;
    delete process.env.OBSX_TEST_NON_DENY_KEY;

    fs.writeFileSync(
      envFile,
      [
        'TRUST_CLOUDFLARE=true',
        'OBSX_LICENSE_STATE_FILE=/tmp/untrusted-license.json',
        'OBSX_UPDATE_TRUSTED_SIGNERS=untrusted-signer',
        'OBSX_TEST_NON_DENY_KEY=allowed_value # inline comment',
      ].join('\n'),
      'utf8'
    );

    loadEnv(envFile);
    assert.equal(process.env.TRUST_CLOUDFLARE, undefined);
    assert.equal(process.env.OBSX_LICENSE_STATE_FILE, undefined);
    assert.equal(process.env.OBSX_UPDATE_TRUSTED_SIGNERS, undefined);
    assert.equal(process.env.OBSX_TEST_NON_DENY_KEY, 'allowed_value');
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('accounts: HTTPS requests require __Host-obsx_session and reject plain obsx_session cookies', async () => {
  const email = `hostprefix-${crypto.randomId(6).toLowerCase()}@example.com`;
  const started = await accounts.startEmailAuth(email, '198.51.100.210');
  assert.equal(started.ok, true);
  assert.ok(started.devCode);

  const verified = await accounts.verifyEmailAuth(email, started.devCode, true, {
    clientIp: '198.51.100.210',
    termsAccepted: true,
  });
  assert.ok(verified.uid && verified.sid);
  const match = String(verified.sessionCookie || '').match(/__Host-obsx_session=([^;]+)/);
  assert.ok(match && match[1], 'HTTPS login must issue __Host-obsx_session cookie');
  const sid = match[1];

  const plainReq = { headers: { cookie: `obsx_session=${sid}` } };
  const hostReq = { headers: { cookie: `__Host-obsx_session=${sid}` } };

  // Plain obsx_session works over HTTP (local dev) but MUST be rejected over HTTPS
  const httpUser = await accounts.getSessionUser(plainReq, false);
  assert.equal(httpUser && httpUser.email, email);

  const httpsPlainUser = await accounts.getSessionUser(plainReq, true);
  assert.equal(httpsPlainUser, null, 'plain obsx_session must be rejected over HTTPS');

  // deleteUserSession over HTTPS must not revoke a session via plain cookie fallback
  await accounts.deleteUserSession(plainReq, true);
  const stillAlive = await accounts.getSessionUser(hostReq, true);
  assert.equal(stillAlive && stillAlive.email, email, '__Host-obsx_session must succeed over HTTPS');

  // Revocation with __Host-obsx_session succeeds
  await accounts.deleteUserSession(hostReq, true);
  const afterDelete = await accounts.getSessionUser(hostReq, true);
  assert.equal(afterDelete, null);
});

test('server: TRUST_CLOUDFLARE gates CF-Connecting-IP/CF-Visitor, /api/v1/health redacts internals, and slowloris POSTs do not poison workLatencyEma', async () => {
  const server = require('../server');
  const prevCfg = { ...botshield.config };
  const saved = {
    TRUST_PROXY: process.env.TRUST_PROXY,
    TRUST_CLOUDFLARE: process.env.TRUST_CLOUDFLARE,
    OBSX_ENFORCE_HTTPS: process.env.OBSX_ENFORCE_HTTPS,
    OBSX_PUBLIC_HOST: process.env.OBSX_PUBLIC_HOST,
    OBSX_SIGNAL_BUDGET: process.env.OBSX_SIGNAL_BUDGET,
    OBSX_SECRET: process.env.OBSX_SECRET,
    OPERATOR_EMAILS: process.env.OPERATOR_EMAILS,
  };

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100000,
      calmBudget: 10000,
      ipBudget: 10000,
      statusBudget: 10000,
      maxWorkLatencyMs: 500,
    });

    process.env.TRUST_PROXY = 'true';
    delete process.env.TRUST_CLOUDFLARE;
    process.env.OBSX_ENFORCE_HTTPS = 'true';
    process.env.OBSX_PUBLIC_HOST = 'example.com';
    process.env.OBSX_SIGNAL_BUDGET = '1';
    process.env.OBSX_SECRET = '0123456789abcdef0123456789abcdef';

    // 1. Without TRUST_CLOUDFLARE=true, CF-Visitor: http is ignored (no 308 redirect)
    const noCfVisitor = await httpRawRequest(port, '/docs.html', {
      headers: {
        Host: 'example.com',
        'User-Agent': BROWSER_UA,
        Accept: 'text/html',
        'Accept-Language': 'en-US',
        'CF-Visitor': '{"scheme":"http"}',
        'X-Forwarded-For': '198.51.100.211',
      },
    });
    assert.equal(noCfVisitor.status, 200);

    // 2. Without TRUST_CLOUDFLARE=true, forged CF-Connecting-IP cannot bypass per-IP signal rate budget
    process.env.OBSX_ENFORCE_HTTPS = 'false';
    const sig1 = await httpRawRequest(port, '/api/v1/signal', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.212',
        'CF-Connecting-IP': '198.51.100.1',
      },
      body: JSON.stringify({ token: 'invalid.tok', signals: { sh: 'fp1' } }),
    });
    assert.notEqual(sig1.status, 429);

    const sig2 = await httpRawRequest(port, '/api/v1/signal', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '203.0.113.212',
        'CF-Connecting-IP': '198.51.100.2', // spoofed different CF IP, same XFF peer
      },
      body: JSON.stringify({ token: 'invalid.tok', signals: { sh: 'fp2' } }),
    });
    assert.equal(sig2.status, 429, 'spoofed CF-Connecting-IP must not evade rate limit when TRUST_CLOUDFLARE is unset');
    assert.equal(sig2.json && sig2.json.error, 'signal_rate_limited');

    // 3. With TRUST_CLOUDFLARE=true, CF-Visitor and CF-Connecting-IP ARE honored
    process.env.TRUST_CLOUDFLARE = 'true';
    process.env.OBSX_ENFORCE_HTTPS = 'true';
    const cfVisitorHttp = await httpRawRequest(port, '/docs.html', {
      headers: {
        Host: 'example.com',
        'User-Agent': BROWSER_UA,
        Accept: 'text/html',
        'Accept-Language': 'en-US',
        'CF-Visitor': '{"scheme":"http"}',
        'CF-Connecting-IP': '198.51.100.213',
        'X-Forwarded-For': '198.51.100.213',
      },
    });
    assert.equal(cfVisitorHttp.status, 308);
    assert.equal(cfVisitorHttp.headers.location, 'https://example.com/docs.html');

    const cfVisitorHttps = await httpRawRequest(port, '/api/v1/health', {
      headers: {
        Host: 'example.com',
        'CF-Visitor': '{"scheme":"https"}',
        'CF-Connecting-IP': '198.51.100.214',
        'X-Forwarded-For': '198.51.100.214',
      },
    });
    assert.equal(cfVisitorHttps.status, 200);
    assert.ok(cfVisitorHttps.headers['strict-transport-security'], 'TRUST_CLOUDFLARE=true should trust CF-Visitor https for HSTS');

    process.env.OBSX_ENFORCE_HTTPS = 'false';
    const sigTrustedCf = await httpRawRequest(port, '/api/v1/signal', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '198.51.100.215',
        'X-Forwarded-For': '198.51.100.215',
      },
      body: JSON.stringify({ token: 'invalid.tok', signals: { sh: 'fp3' } }),
    });
    assert.notEqual(sigTrustedCf.status, 429, 'fresh CF-Connecting-IP gets its own budget when TRUST_CLOUDFLARE=true');

    // 4. /api/v1/health redacts operational internals for anonymous callers and reveals them to operators
    const anonHealth = await httpRawRequest(port, '/api/v1/health');
    assert.equal(anonHealth.status, 200);
    assert.equal(anonHealth.json.ok, true);
    assert.equal(typeof anonHealth.json.uptime, 'number');
    assert.equal(anonHealth.json.rssMb, undefined);
    assert.equal(anonHealth.json.activeConnections, undefined);
    assert.equal(anonHealth.json.botShield, undefined);
    assert.equal(anonHealth.json.workLatencyMs, undefined);

    const opKeyHealth = await httpRawRequest(port, '/api/v1/health', {
      headers: { 'X-OBSX-Operator-Key': process.env.OBSX_SECRET },
    });
    assert.equal(opKeyHealth.status, 200);
    assert.equal(typeof opKeyHealth.json.rssMb, 'number');
    assert.equal(typeof opKeyHealth.json.activeConnections, 'number');
    assert.equal(typeof opKeyHealth.json.workLatencyMs, 'number');
    assert.equal(typeof opKeyHealth.json.botShield, 'object');

    // Operator session over HTTPS requires __Host-obsx_session to unlock /api/v1/health diagnostics
    const opEmail = `health-op-${crypto.randomId(5).toLowerCase()}@example.com`;
    process.env.OPERATOR_EMAILS = opEmail;
    const opStart = await accounts.startEmailAuth(opEmail, '198.51.100.216');
    const opVerify = await accounts.verifyEmailAuth(opEmail, opStart.devCode, true, {
      clientIp: '198.51.100.216',
      termsAccepted: true,
    });
    const opSid = String(opVerify.sessionCookie).match(/__Host-obsx_session=([^;]+)/)[1];

    const plainHttpsHealth = await httpRawRequest(port, '/api/v1/health', {
      headers: {
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-For': '198.51.100.216',
        'CF-Connecting-IP': '198.51.100.216',
        Cookie: `obsx_session=${opSid}`,
      },
    });
    assert.equal(plainHttpsHealth.json.botShield, undefined, 'plain cookie over HTTPS must not grant operator health view');

    const hostHttpsHealth = await httpRawRequest(port, '/api/v1/health', {
      headers: {
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-For': '198.51.100.216',
        'CF-Connecting-IP': '198.51.100.216',
        Cookie: `__Host-obsx_session=${opSid}`,
      },
    });
    assert.equal(typeof hostHttpsHealth.json.botShield, 'object', '__Host- cookie over HTTPS unlocks operator health view');

    // 5. Aborted slowloris POST and slow client body streaming must NOT poison BotShield workLatencyEma
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100000,
      calmBudget: 10000,
      ipBudget: 10000,
      maxWorkLatencyMs: 500,
    });

    await new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: '127.0.0.1', port }, () => {
        sock.write(
          'POST /api/v1/demo HTTP/1.1\r\n' +
          'Host: 127.0.0.1\r\n' +
          'Content-Type: application/json\r\n' +
          'Content-Length: 100\r\n' +
          'X-Forwarded-For: 198.51.100.217\r\n' +
          'CF-Connecting-IP: 198.51.100.217\r\n\r\n' +
          '{"a":'
        );
        setTimeout(() => {
          sock.destroy();
          setTimeout(resolve, 60);
        }, 220);
      });
      sock.on('error', reject);
    });

    assert.equal(botshield.stats().health.workLatencyMs, 0, 'aborted slowloris socket must not record workLatencyEma');

    // Slow body upload that completes after 180ms should subtract _obsxBodyWaitMs
    await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path: '/api/v1/demo',
          method: 'POST',
          headers: {
            Connection: 'close',
            'Content-Type': 'application/json',
            'X-Forwarded-For': '198.51.100.218',
            'CF-Connecting-IP': '198.51.100.218',
          },
        },
        (res) => {
          res.resume();
          res.on('end', () => setTimeout(resolve, 30));
        }
      );
      req.on('error', reject);
      req.write('{"action":');
      setTimeout(() => {
        req.end('"slow_upload"}');
      }, 180);
    });

    assert.ok(
      botshield.stats().health.workLatencyMs < 100,
      `expected server workLatencyMs < 100 after subtracting body wait, got ${botshield.stats().health.workLatencyMs}`
    );
  } finally {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    botshield.configure(prevCfg);
    botshield.reset();
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('botshield: decayWorkLatency self-heals saturation, maxConnsPerIp defaults to 30, and verified users retain hardConnCeiling headroom', () => {
  const prevCfg = { ...botshield.config };
  try {
    if (!process.env.OBSX_MAX_CONNS_PER_IP) {
      assert.equal(botshield.config.maxConnsPerIp, 30);
    }

    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100,
      baseDifficulty: 8,
      maxDifficulty: 8,
      maxWorkLatencyMs: 500,
      maxActiveConnections: 20,
      hardConnCeiling: 50,
      ipBudget: 1000,
      calmBudget: 1000,
      verifiedBudget: 1000,
    });

    // Poison workLatencyEma above maxWorkLatencyMs -> sheds traffic with 503
    botshield.noteWorkLatency(4000);
    const shedRes = makeMockRes();
    const shedOut = botshield.evaluate(
      makeMockReq(BROWSER_UA),
      shedRes,
      '198.51.100.220',
      '/',
      5,
      new URL('http://example.com/'),
      { activeConnections: 1, inFlight: 1, reqRate: 5 }
    );
    assert.equal(shedOut.handled, true);
    assert.equal(shedRes.out.status, 503);

    // Self-healing decay brings stale workLatencyEma back down without needing fresh samples
    botshield.decayWorkLatency(Date.now() + 90_000);
    assert.equal(botshield.stats().health.workLatencyMs, 0);

    const recoveredRes = makeMockRes();
    const recoveredOut = botshield.evaluate(
      makeMockReq(BROWSER_UA),
      recoveredRes,
      '198.51.100.220',
      '/',
      5,
      new URL('http://example.com/'),
      { activeConnections: 1, inFlight: 1, reqRate: 5 }
    );
    assert.equal(recoveredOut.handled, false);

    // Obtain a verified BotShield cookie via PoW challenge
    botshield.configure({ mode: 'always' });
    const chRes = makeMockRes();
    botshield.evaluate(
      makeMockReq(BROWSER_UA),
      chRes,
      '198.51.100.221',
      '/',
      10,
      new URL('http://example.com/'),
      { activeConnections: 2, inFlight: 1, reqRate: 10 }
    );
    assert.equal(chRes.out.status, 403);
    const ch = parseChallenge(chRes.out.body);
    const nonce = solveBotShieldPow(ch.challenge, ch.bits);

    const solveRes = makeMockRes();
    const solveUrl = new URL(`http://example.com/?__bs=${ch.cid}&__bn=${nonce}&__ms=10`);
    botshield.evaluate(
      makeMockReq(BROWSER_UA),
      solveRes,
      '198.51.100.221',
      '/',
      10,
      solveUrl,
      { activeConnections: 2, inFlight: 1, reqRate: 10 }
    );
    const cookieHeader = String(solveRes.out.headers['Set-Cookie'] || '').split(';')[0];
    assert.ok(cookieHeader.startsWith('obsx_bs='), 'solved challenge must issue obsx_bs cookie');

    // Between maxActiveConnections (20) and hardConnCeiling (50): unverified sheds 503, verified passes
    const unverifiedHighConn = makeMockRes();
    const unvOut = botshield.evaluate(
      makeMockReq(BROWSER_UA),
      unverifiedHighConn,
      '198.51.100.222',
      '/',
      10,
      new URL('http://example.com/'),
      { activeConnections: 30, inFlight: 1, reqRate: 10 }
    );
    assert.equal(unvOut.handled, true);
    assert.equal(unverifiedHighConn.out.status, 503);

    const verifiedHighConn = makeMockRes();
    const verOut = botshield.evaluate(
      makeMockReq(BROWSER_UA, { headers: { cookie: cookieHeader } }),
      verifiedHighConn,
      '198.51.100.221',
      '/',
      10,
      new URL('http://example.com/'),
      { activeConnections: 30, inFlight: 1, reqRate: 10 }
    );
    assert.equal(verOut.handled, false);
    assert.equal(verOut.verified, true);

    // Above hardConnCeiling (50): even verified visitors are shed to protect origin sockets
    const aboveHardCap = makeMockRes();
    const hardOut = botshield.evaluate(
      makeMockReq(BROWSER_UA, { headers: { cookie: cookieHeader } }),
      aboveHardCap,
      '198.51.100.221',
      '/',
      10,
      new URL('http://example.com/'),
      { activeConnections: 51, inFlight: 1, reqRate: 10 }
    );
    assert.equal(hardOut.handled, true);
    assert.equal(aboveHardCap.out.status, 503);
  } finally {
    botshield.configure(prevCfg);
    botshield.reset();
  }
});

test('botshield: decoupled pathFuzz, engaged core API/SDK carve-outs, browser PoW on UA-fleet, and right-to-left XFF consistency', () => {
  const prevCfg = { ...botshield.config };
  try {
    // 1. Decoupled pathFuzz: trips pathFuzz without engaging global under_attack, and protects core routes
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100000,
      fanoutPathsPerMin: 5,
      ipBudget: 1000,
      calmBudget: 1000,
      checkForwarded: true,
    });

    for (let i = 0; i < 6; i++) {
      const r = makeMockRes();
      botshield.evaluate(
        makeMockReq(BROWSER_UA),
        r,
        '198.51.100.230',
        `/probe-${i}`,
        5,
        new URL(`http://example.com/probe-${i}`),
        { activeConnections: 1, inFlight: 1, reqRate: 5 }
      );
    }
    assert.equal(botshield.stats().attack.pathFuzz, true);
    assert.equal(botshield.stats().engaged, false, 'pathFuzz must remain decoupled from global engaged mode');

    // Unseen non-core path returns 404
    const fuzzRes = makeMockRes();
    const fuzzOut = botshield.evaluate(
      makeMockReq(BROWSER_UA),
      fuzzRes,
      '198.51.100.230',
      '/unseen-fuzz-target',
      5,
      new URL('http://example.com/unseen-fuzz-target'),
      { activeConnections: 1, inFlight: 1, reqRate: 5 }
    );
    assert.equal(fuzzOut.handled, true);
    assert.equal(fuzzRes.out.status, 404);

    // Core API and SDK paths are never 404'd by pathFuzz
    for (const corePath of ['/api/v1/verify', '/api/v1/session', '/api/v1/signal', '/obsx.min.js', '/tracer.min.js', '/sdk/obsx.js']) {
      const r = makeMockRes();
      const out = botshield.evaluate(
        makeMockReq(BOT_UA, { method: corePath.startsWith('/api/') ? 'POST' : 'GET' }),
        r,
        '198.51.100.231',
        corePath,
        5,
        new URL(`http://example.com${corePath}`),
        { activeConnections: 1, inFlight: 1, reqRate: 5 }
      );
      assert.equal(out.handled, false, `pathFuzz must not 404 core route ${corePath}`);
    }

    // 2. Engaged mode keeps Bearer /api/v1/verify and SDK/handshake routes reachable, while refusing unauthenticated verify
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'always',
      ipBudget: 1000,
      calmBudget: 1000,
    });

    const unauthVerifyRes = makeMockRes();
    const unauthVerifyOut = botshield.evaluate(
      makeMockReq(BOT_UA, { method: 'POST' }),
      unauthVerifyRes,
      '198.51.100.232',
      '/api/v1/verify',
      50,
      new URL('http://example.com/api/v1/verify'),
      { activeConnections: 2, inFlight: 1, reqRate: 50 }
    );
    assert.equal(unauthVerifyOut.handled, true);
    assert.equal(unauthVerifyRes.out.status, 403);

    const authVerifyRes = makeMockRes();
    const authVerifyOut = botshield.evaluate(
      makeMockReq(BOT_UA, { method: 'POST', headers: { authorization: 'Bearer sk_live_test123' } }),
      authVerifyRes,
      '198.51.100.232',
      '/api/v1/verify',
      50,
      new URL('http://example.com/api/v1/verify'),
      { activeConnections: 2, inFlight: 1, reqRate: 50 }
    );
    assert.equal(authVerifyOut.handled, false, 'Bearer /api/v1/verify must remain reachable when engaged');

    for (const p of ['/api/v1/session', '/api/v1/signal', '/obsx.min.js', '/tracer.min.js', '/sdk/v1.js']) {
      const r = makeMockRes();
      const out = botshield.evaluate(
        makeMockReq(BOT_UA, { method: p.startsWith('/api/') ? 'POST' : 'GET' }),
        r,
        '198.51.100.233',
        p,
        50,
        new URL(`http://example.com${p}`),
        { activeConnections: 2, inFlight: 1, reqRate: 50 }
      );
      assert.equal(out.handled, false, `${p} must remain reachable during site-wide engagement`);
    }

    // 3. UA fleet collision issues PoW challenge for browser HTML visitors instead of hard 403
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100000,
      uaFleetBudget: 10,
      ipBudget: 1000,
      calmBudget: 1000,
      fanoutIpsPerMin: 1000,
      fanoutSubnetsPerMin: 1000,
      subnetBudget: 10000,
      subnetQuarantinePerMin: 10000,
    });

    for (let i = 1; i <= 27; i++) {
      const r = makeMockRes();
      botshield.evaluate(
        makeMockReq(BROWSER_UA),
        r,
        `198.51.${i}.10`,
        '/',
        5,
        new URL('http://example.com/'),
        { activeConnections: 1, inFlight: 1, reqRate: 5 }
      );
    }

    const browserFleetRes = makeMockRes();
    const browserFleetOut = botshield.evaluate(
      makeMockReq(BROWSER_UA),
      browserFleetRes,
      '198.51.99.10',
      '/',
      5,
      new URL('http://example.com/'),
      { activeConnections: 1, inFlight: 1, reqRate: 5 }
    );
    assert.equal(browserFleetOut.handled, true);
    assert.equal(browserFleetRes.out.status, 403);
    assert.match(String(browserFleetRes.out.headers['Content-Type'] || ''), /text\/html/);
    assert.match(browserFleetRes.out.body, /challenge = "/, 'browser HTML hit on UA-fleet collision must get PoW challenge');

    const apiFleetRes = makeMockRes();
    const apiFleetOut = botshield.evaluate(
      makeMockReq(BROWSER_UA, { headers: { accept: 'application/json' } }),
      apiFleetRes,
      '198.51.101.10',
      '/api/v1/projects',
      5,
      new URL('http://example.com/api/v1/projects'),
      { activeConnections: 1, inFlight: 1, reqRate: 5 }
    );
    assert.equal(apiFleetOut.handled, true);
    assert.equal(apiFleetRes.out.status, 403);
    assert.match(String(apiFleetRes.out.headers['Content-Type'] || ''), /application\/json/);

    // 4. Right-to-left non-private XFF consistency rejects forged leftmost entries and allows private hops
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      checkForwarded: true,
      engageRps: 100000,
      ipBudget: 1000,
      calmBudget: 1000,
    });

    const forgedXffRes = makeMockRes();
    const forgedXffOut = botshield.evaluate(
      makeMockReq(BROWSER_UA, { headers: { 'x-forwarded-for': '198.51.100.5, 203.0.113.99' } }),
      forgedXffRes,
      '198.51.100.5',
      '/',
      5,
      new URL('http://example.com/'),
      { activeConnections: 1, inFlight: 1, reqRate: 5, proxyTrustEnabled: true }
    );
    assert.equal(forgedXffOut.handled, true);
    assert.equal(forgedXffRes.out.status, 403);

    const validPrivateHopsRes = makeMockRes();
    const validPrivateHopsOut = botshield.evaluate(
      makeMockReq(BROWSER_UA, { headers: { 'x-forwarded-for': '198.51.100.5, 10.0.0.4, 127.0.0.1' } }),
      validPrivateHopsRes,
      '198.51.100.5',
      '/',
      5,
      new URL('http://example.com/'),
      { activeConnections: 1, inFlight: 1, reqRate: 5, proxyTrustEnabled: true }
    );
    assert.equal(validPrivateHopsOut.handled, false);
  } finally {
    botshield.configure(prevCfg);
    botshield.reset();
  }
});

test('core: project quota (OBSX_MAX_PROJECTS_PER_USER), signal allowlist/size/count caps', async () => {
  const savedMax = process.env.OBSX_MAX_PROJECTS_PER_USER;
  try {
    process.env.OBSX_MAX_PROJECTS_PER_USER = '2';
    const ownerUid = `u_quota_${crypto.randomId(6)}`;

    const p1 = await core.createProject({ name: 'Quota One' }, ownerUid);
    const p2 = await core.createProject({ name: 'Quota Two' }, ownerUid);
    assert.ok(p1.pid && p2.pid);

    await assert.rejects(
      () => core.createProject({ name: 'Quota Three' }, ownerUid),
      (err) => err && err.code === 'project_quota_exceeded' && err.statusCode === 429
    );

    // Signal allowlist stripping, array/string bounding, 16 KiB cap, and 16-batch per-session cap
    const sess = await core.startSession(p1, { ip: '198.51.100.240', ua: BROWSER_UA });
    const manyPoints = Array.from({ length: 150 }, (_, i) => ({ x: i, y: i, t: i * 10 }));

    const firstSig = await core.recordSignals(
      {
        token: sess.token,
        signals: {
          sh: 's'.repeat(400),
          gpuRenderer: 'g'.repeat(400),
          mousePoints: manyPoints,
          unexpectedBlob: 'should_be_stripped',
          __proto__: { polluted: true },
        },
      },
      { ip: '198.51.100.240', ua: BROWSER_UA }
    );
    assert.equal(firstSig.ok, true);

    const decoded = await crypto.verifyToken(sess.token, getKv());
    const stored = await getKv().hgetall(`tr:s:${decoded.s}`);
    const parsedSig = JSON.parse(stored.sig);
    assert.equal(parsedSig.unexpectedBlob, undefined, 'unknown signal keys must be stripped');
    assert.equal(parsedSig.sh.length, 256, 'sh string must be bounded to 256 chars');
    assert.equal(parsedSig.gpuRenderer.length, 256, 'gpuRenderer string must be bounded to 256 chars');
    assert.equal(parsedSig.mousePoints.length, 100, 'mousePoints must be capped at 100 items');

    // Oversized signal JSON (> 16 KiB) rejected
    const oversized = await core.recordSignals(
      {
        token: sess.token,
        signals: {
          sh: 'ok',
          rum: { pad: 'x'.repeat(17000) },
        },
      },
      { ip: '198.51.100.240', ua: BROWSER_UA }
    );
    assert.equal(oversized.ok, false);
    assert.equal(oversized.error, 'signals_too_large');

    // Remaining 15 batches succeed (total 16), 17th fails with signal_limit_exceeded
    for (let i = 1; i < 16; i++) {
      const r = await core.recordSignals(
        { token: sess.token, signals: { sh: `batch_${i}` } },
        { ip: '198.51.100.240', ua: BROWSER_UA }
      );
      assert.equal(r.ok, true, `signal batch ${i + 1} should succeed`);
    }
    const overBatch = await core.recordSignals(
      { token: sess.token, signals: { sh: 'batch_17' } },
      { ip: '198.51.100.240', ua: BROWSER_UA }
    );
    assert.equal(overBatch.ok, false);
    assert.equal(overBatch.error, 'signal_limit_exceeded');
  } finally {
    if (savedMax === undefined) delete process.env.OBSX_MAX_PROJECTS_PER_USER;
    else process.env.OBSX_MAX_PROJECTS_PER_USER = savedMax;
  }
});

test('kv & mailer: Pass 4b evicts unsigned HTTP sessions before auth/replay locks, and alertCooldowns scopes per recipient', async () => {
  const store = new MemoryStore(5, null);
  try {
    await store.set('tr:used:replay1', '1', 'EX', 600);
    await store.set('tr:auth:sess1', 'u_1', 'EX', 600);
    await store.hset('tr:s:signed', { p: 'p_1', sig: '{}', sigFromHttp: '1', tsig: '1' });
    await store.hset('tr:s:unsigned1', { p: 'p_1', sig: '{}', sigFromHttp: '1', tsig: 'missing_http' });
    await store.hset('tr:s:unsigned2', { p: 'p_1', sig: '{}', sigFromHttp: '1', tsig: '0' });

    // Adding a 6th key forces eviction; Pass 4b should purge unsigned HTTP session before auth/replay/signed
    await store.set('tr:p:durable1', 'keep');

    assert.equal(await store.get('tr:used:replay1'), '1', 'replay lock must be preserved');
    assert.equal(await store.get('tr:auth:sess1'), 'u_1', 'auth session must be preserved');
    const signedStillThere = await store.hgetall('tr:s:signed');
    assert.equal(signedStillThere && signedStillThere.tsig, '1', 'tsig-verified session must be preserved');
    const unsigned1 = await store.hgetall('tr:s:unsigned1');
    assert.deepEqual(unsigned1, {}, 'unsigned HTTP session must be evicted by Pass 4b');
  } finally {
    store.close();
  }

  // Mailer alertCooldowns is scoped per (code, recipient)
  const threatCode = `cooldown_scope_${crypto.randomId(6)}`;
  const r1 = await mailer.notifyCriticalIncident({
    code: threatCode,
    recipient: 'op-one@example.com',
    detail: 'first recipient alert',
  });
  const r2 = await mailer.notifyCriticalIncident({
    code: threatCode,
    recipient: 'op-two@example.com',
    detail: 'second recipient alert',
  });
  const r1Repeat = await mailer.notifyCriticalIncident({
    code: threatCode,
    recipient: 'op-one@example.com',
    detail: 'repeat for first recipient',
  });

  assert.equal(r1.throttled, false);
  assert.equal(r2.throttled, false, 'separate recipient must not be throttled by another recipient cooldown');
  assert.equal(r1Repeat.throttled, true, 'immediate duplicate to same recipient must be throttled');
});
