'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const botshield = require('../lib/botshield');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const mailer = require('../lib/mailer');
const { MemoryStore, defaultKvMaxKeys } = require('../lib/kv');

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
  let n = 0;
  while (!botshield.powOk(challenge, String(n), bits)) n++;
  return String(n);
}

function httpRawRequest(port, reqPath, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: reqPath, method, headers },
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

test('botshield: quarantine escape cap stops pending map churn and duplicate strike escalation', () => {
  const prevCfg = { ...botshield.config };
  try {
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100000,
      disengageRps: 0,
      maxAttempts: 2,
      escapeMaxAttempts: 4,
      quarantineMs: 120000,
      baseDifficulty: 4,
      maxDifficulty: 6,
      ipBudget: 10000,
      calmBudget: 10000,
      uaFleetBudget: 100000,
      subnetBudget: 100000,
      subnetQuarantinePerMin: 100000,
    });

    const ip = '198.51.100.77';
    const cap = { activeConnections: 4, inFlight: 1, isHttps: true, proxyTrustEnabled: true };

    for (let i = 0; i < 3; i++) {
      const res = makeMockRes();
      botshield.evaluate(makeMockReq(BOT_UA, { isHttps: true }), res, ip, '/', 10, new URL('http://example.com/'), cap);
    }

    const afterBan = botshield.stats(true);
    assert.equal(afterBan.counters.quarantined, 1);
    assert.equal(afterBan.stateSizes.pending, 2);

    // 1 browser escape attempt allowed (attempts 3 -> 4 == escapeMaxAttempts)
    const esc1 = makeMockRes();
    botshield.evaluate(makeMockReq(BROWSER_UA, { isHttps: true }), esc1, ip, '/', 10, new URL('http://example.com/'), cap);
    assert.equal(esc1.out.status, 403);
    assert.match(esc1.out.body, /proof-of-work/);
    assert.equal(botshield.stats(true).stateSizes.pending, 3);

    // Subsequent browser hits after exhausting escape cap must refuse immediately
    // without allocating pending challenges or incrementing quarantine count
    for (let i = 0; i < 25; i++) {
      const r = makeMockRes();
      botshield.evaluate(makeMockReq(BROWSER_UA, { isHttps: true }), r, ip, '/', 10, new URL('http://example.com/'), cap);
      assert.equal(r.out.status, 403);
      assert.equal(r.out.headers['X-OBSX-BotShield'], 'quarantine');
      assert.match(r.out.body, /bot_blocked/);
    }

    const finalStats = botshield.stats(true);
    assert.equal(finalStats.stateSizes.pending, 3);
    assert.equal(finalStats.counters.quarantined, 1);
  } finally {
    botshield.reset();
    botshield.configure(prevCfg);
  }
});

test('botshield: emits HSTS on HTTPS challenge, refusal, shed, 400/405, and verified 302 responses', () => {
  const prevCfg = { ...botshield.config };
  try {
    botshield.reset();
    botshield.configure({
      enabled: true,
      mode: 'auto',
      engageRps: 100000,
      disengageRps: 0,
      maxAttempts: 2,
      baseDifficulty: 4,
      maxDifficulty: 6,
      maxPathLen: 64,
      maxInFlight: 5,
      maxRssMb: 9999,
    });

    const httpsCap = { activeConnections: 4, inFlight: 1, isHttps: true, proxyTrustEnabled: true };
    const httpCap = { activeConnections: 4, inFlight: 1, isHttps: false, proxyTrustEnabled: true };
    const expectedHsts = 'max-age=31536000; includeSubDomains';

    // 1. HTTPS challenge 403 includes HSTS
    const chRes = makeMockRes();
    botshield.evaluate(makeMockReq(BOT_UA, { isHttps: true }), chRes, '198.51.100.81', '/', 10, new URL('http://example.com/'), httpsCap);
    assert.equal(chRes.out.status, 403);
    assert.equal(chRes.out.headers['Strict-Transport-Security'], expectedHsts);

    // 2. Verified 302 redirect includes HSTS
    const cidMatch = chRes.out.body.match(/cid = "([^"]+)"/);
    const challengeMatch = chRes.out.body.match(/challenge = "([^"]+)"/);
    const bitsMatch = chRes.out.body.match(/bits = (\d+)/);
    assert.ok(cidMatch && challengeMatch && bitsMatch);
    const nonce = solveBotShieldPow(challengeMatch[1], Number(bitsMatch[1]));
    const verifyRes = makeMockRes();
    const verifyUrl = new URL(`http://example.com/?__bs=${cidMatch[1]}&__bn=${nonce}`);
    botshield.evaluate(makeMockReq(BOT_UA, { isHttps: true }), verifyRes, '198.51.100.81', '/', 10, verifyUrl, httpsCap);
    assert.equal(verifyRes.out.status, 302);
    assert.equal(verifyRes.out.headers['Strict-Transport-Security'], expectedHsts);

    // 3. HTTPS 400 path_too_long includes HSTS
    const longRes = makeMockRes();
    botshield.evaluate(makeMockReq(BROWSER_UA, { isHttps: true }), longRes, '198.51.100.82', '/' + 'a'.repeat(80), 10, new URL('http://example.com/'), httpsCap);
    assert.equal(longRes.out.status, 400);
    assert.equal(longRes.out.headers['Strict-Transport-Security'], expectedHsts);

    // 4. HTTPS 405 invalid method includes HSTS
    const methodRes = makeMockRes();
    botshield.evaluate(makeMockReq(BROWSER_UA, { method: 'TRACE', isHttps: true }), methodRes, '198.51.100.83', '/', 10, new URL('http://example.com/'), httpsCap);
    assert.equal(methodRes.out.status, 405);
    assert.equal(methodRes.out.headers['Strict-Transport-Security'], expectedHsts);

    // 5. HTTPS 503 capacity shed includes HSTS
    const shedRes = makeMockRes();
    botshield.evaluate(makeMockReq(BROWSER_UA, { isHttps: true }), shedRes, '198.51.100.84', '/', 10, new URL('http://example.com/'), { ...httpsCap, inFlight: 50 });
    assert.equal(shedRes.out.status, 503);
    assert.equal(shedRes.out.headers['Strict-Transport-Security'], expectedHsts);

    // 6. Plaintext HTTP challenge omits HSTS
    const plainRes = makeMockRes();
    botshield.evaluate(makeMockReq(BOT_UA, { isHttps: false }), plainRes, '198.51.100.85', '/', 10, new URL('http://example.com/'), httpCap);
    assert.equal(plainRes.out.status, 403);
    assert.equal(plainRes.out.headers['Strict-Transport-Security'], undefined);
  } finally {
    botshield.reset();
    botshield.configure(prevCfg);
  }
});

test('low-memory resilience: default maxRssMb and KV maxKeys auto-size on <=1.5 GiB hosts', () => {
  const prevKvEnv = process.env.OBSX_KV_MAX_KEYS;
  try {
    delete process.env.OBSX_KV_MAX_KEYS;
    assert.equal(botshield.defaultMaxRssMb(905 * 1024 * 1024), 260);
    assert.equal(botshield.defaultMaxRssMb(8 * 1024 * 1024 * 1024), 620);
    assert.equal(defaultKvMaxKeys(905 * 1024 * 1024), 25000);
    assert.equal(defaultKvMaxKeys(8 * 1024 * 1024 * 1024), 100000);

    process.env.OBSX_KV_MAX_KEYS = '12345';
    assert.equal(defaultKvMaxKeys(905 * 1024 * 1024), 12345);
  } finally {
    if (prevKvEnv === undefined) delete process.env.OBSX_KV_MAX_KEYS;
    else process.env.OBSX_KV_MAX_KEYS = prevKvEnv;
  }
});

test('kv: excludes volatile rate-limit and guest keys from dirtying and snapshot writes', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-kv-volatile-'));
  const snapPath = path.join(tmpDir, 'snapshot.json');
  const store = new MemoryStore(500, snapPath);
  try {
    assert.equal(store._dirty, false);
    await store.incr('tr:rl:sub:abc123', 600);
    await store.incr('tr:cnt:em:xyz', 3600);
    await store.set('tr:cd:email:xyz', '1', 'EX', 45);
    await store.incr('tr:cb:cnt:p1:vec', 60);
    await store.incr('rate:verify:127.0.0.1', 60);
    await store.set('tr:guest:guest_1:notes', '["note_1"]', 'EX', 3600);
    assert.equal(store._dirty, false, 'volatile and guest keys must not dirty snapshot');

    await store.set('tr:durable:item', 'keep_me');
    assert.equal(store._dirty, true, 'durable keys must mark snapshot dirty');
    store.saveSnapshot();

    const store2 = new MemoryStore(500, snapPath);
    try {
      assert.equal(await store2.get('tr:durable:item'), 'keep_me');
      assert.equal(await store2.get('tr:rl:sub:abc123'), null);
      assert.equal(await store2.get('tr:cnt:em:xyz'), null);
      assert.equal(await store2.get('tr:cd:email:xyz'), null);
      assert.equal(await store2.get('rate:verify:127.0.0.1'), null);
      assert.equal(await store2.get('tr:guest:guest_1:notes'), null);
    } finally {
      store2.close();
    }
  } finally {
    store.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('core: suppresses outbound critical alert emails for public sandbox DEMO.pid by default', async () => {
  const origNotify = mailer.notifyCriticalIncident;
  const prevAlertSandbox = process.env.OBSX_ALERT_ON_SANDBOX;
  const calls = [];
  mailer.notifyCriticalIncident = async (payload) => {
    calls.push(payload);
    return { ok: true, throttled: false };
  };

  try {
    delete process.env.OBSX_ALERT_ON_SANDBOX;
    const demoProj = await core.loadProject(core.DEMO.pid);
    const demoVerdict = await core.verify(
      demoProj,
      { action: 'demo_probe', signals: { webdriver: true } },
      { ip: '198.51.100.120', ua: 'HeadlessChrome/131.0', proxyHeaders: ['bare_mux_protocol'] }
    );
    assert.equal(demoVerdict.verdict, 'reject');
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(calls.length, 0);

    const realProj = await core.createProject({ name: 'Non-Sandbox Alert Test' });
    const loadedReal = await core.loadProject(realProj.pid);
    const realVerdict = await core.verify(
      loadedReal,
      { action: 'real_probe', signals: { webdriver: true } },
      { ip: '198.51.100.121', ua: 'HeadlessChrome/131.0', proxyHeaders: ['bare_mux_protocol'] }
    );
    assert.equal(realVerdict.verdict, 'reject');
    await new Promise((r) => setTimeout(r, 20));
    assert.ok(calls.length >= 1);
  } finally {
    mailer.notifyCriticalIncident = origNotify;
    if (prevAlertSandbox === undefined) delete process.env.OBSX_ALERT_ON_SANDBOX;
    else process.env.OBSX_ALERT_ON_SANDBOX = prevAlertSandbox;
  }
});

test('core: global guest notes cap evicts oldest guest records across fresh guest_* IDs', async () => {
  const prevCap = process.env.OBSX_MAX_GLOBAL_GUEST_NOTES;
  const createdGuests = [];
  try {
    process.env.OBSX_MAX_GLOBAL_GUEST_NOTES = '5';
    for (let i = 0; i < 8; i++) {
      const gid = `guest_${crypto.randomId(8)}`;
      createdGuests.push(gid);
      await core.createUserNote(gid, {
        title: `Guest Note ${i}`,
        content: 'payload-' + i,
        protection: 'advisory',
      });
    }

    for (let i = 0; i < 3; i++) {
      const notes = await core.getUserNotes(createdGuests[i]);
      assert.equal(notes.length, 0);
    }
    for (let i = 3; i < 8; i++) {
      const notes = await core.getUserNotes(createdGuests[i]);
      assert.equal(notes.length, 1);
    }
  } finally {
    for (const gid of createdGuests) {
      await core.purgeUserNotes(gid);
    }
    if (prevCap === undefined) delete process.env.OBSX_MAX_GLOBAL_GUEST_NOTES;
    else process.env.OBSX_MAX_GLOBAL_GUEST_NOTES = prevCap;
  }
});

test('accounts: cross-subnet global mailbox cap and verifyEmailAuth per-subnet limit', async () => {
  const prevGlobalLim = process.env.OBSX_OTP_GLOBAL_MAILBOX_LIMIT;
  const prevVerifyLim = process.env.OBSX_VERIFY_SUBNET_LIMIT;
  try {
    process.env.OBSX_OTP_GLOBAL_MAILBOX_LIMIT = '8';
    const targetEmail = `global_cap_${crypto.randomId(6)}@example.com`;
    for (let i = 1; i <= 8; i++) {
      const r = await accounts.startEmailAuth(targetEmail, `198.18.${i}.10`);
      assert.equal(r.ok, true);
    }
    await assert.rejects(
      () => accounts.startEmailAuth(targetEmail, '198.18.99.10'),
      (err) => err && err.status === 429
    );

    process.env.OBSX_VERIFY_SUBNET_LIMIT = '10';
    const spraySubnetIp = '203.0.113.245';
    for (let i = 0; i < 10; i++) {
      await assert.rejects(
        () => accounts.verifyEmailAuth(`nobody_${i}@example.com`, '123456', false, { clientIp: spraySubnetIp }),
        /Code expired or invalid/i
      );
    }
    await assert.rejects(
      () => accounts.verifyEmailAuth('nobody_11@example.com', '123456', false, { clientIp: spraySubnetIp }),
      (err) => err && err.status === 429 && /Too many verification attempts/i.test(err.message)
    );
  } finally {
    if (prevGlobalLim === undefined) delete process.env.OBSX_OTP_GLOBAL_MAILBOX_LIMIT;
    else process.env.OBSX_OTP_GLOBAL_MAILBOX_LIMIT = prevGlobalLim;
    if (prevVerifyLim === undefined) delete process.env.OBSX_VERIFY_SUBNET_LIMIT;
    else process.env.OBSX_VERIFY_SUBNET_LIMIT = prevVerifyLim;
  }
});

test('mailer: enforces global SMTP concurrency and rolling rate limits', async () => {
  const saved = {
    FORCE_SMTP: process.env.FORCE_SMTP,
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_PORT: process.env.SMTP_PORT,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    OBSX_SMTP_MAX_CONCURRENT: process.env.OBSX_SMTP_MAX_CONCURRENT,
    OBSX_SMTP_MAX_PER_10M: process.env.OBSX_SMTP_MAX_PER_10M,
  };

  const openSockets = [];
  const mockSmtp = net.createServer((sock) => {
    openSockets.push(sock);
    sock.write('220 mock-smtp ready\r\n');
    sock.once('data', () => {
      setTimeout(() => {
        try {
          sock.write('250 mock-smtp\r\n');
          sock.end();
        } catch {}
      }, 60);
    });
  });

  await new Promise((resolve) => mockSmtp.listen(0, '127.0.0.1', resolve));
  const smtpPort = mockSmtp.address().port;

  try {
    mailer._resetSmtpLimitsForTest();
    process.env.FORCE_SMTP = 'true';
    process.env.SMTP_HOST = '127.0.0.1';
    process.env.SMTP_PORT = String(smtpPort);
    process.env.SMTP_USER = 'sender@example.com';
    process.env.SMTP_PASS = 'app-pass-placeholder';
    process.env.OBSX_SMTP_MAX_CONCURRENT = '1';
    process.env.OBSX_SMTP_MAX_PER_10M = '2';

    const p1 = mailer.sendVerificationCode('a@example.com', '111111');
    const p2 = mailer.sendVerificationCode('b@example.com', '222222');
    const [r1, r2] = await Promise.all([p1, p2]);
    assert.equal(r1.ok, false);
    assert.equal(r2.ok, false);
    assert.equal(r2.error, 'smtp_concurrency_limited');

    const r3 = await mailer.sendVerificationCode('c@example.com', '333333');
    assert.equal(r3.ok, false);
    assert.match(r3.error, /smtp_requires_starttls/);

    const r4 = await mailer.sendVerificationCode('d@example.com', '444444');
    assert.equal(r4.ok, false);
    assert.equal(r4.error, 'smtp_rate_limited');
  } finally {
    mailer._resetSmtpLimitsForTest();
    for (const s of openSockets) {
      try { s.destroy(); } catch {}
    }
    await new Promise((resolve) => mockSmtp.close(resolve));
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('server: OBSX_ENFORCE_HTTPS redirects proxied HTTP safely, uses rightmost XFP, and bounds demo routes', async () => {
  const server = require('../server');
  const saved = {
    TRUST_PROXY: process.env.TRUST_PROXY,
    OBSX_ENFORCE_HTTPS: process.env.OBSX_ENFORCE_HTTPS,
    OBSX_PUBLIC_HOST: process.env.OBSX_PUBLIC_HOST,
    OBSX_DEMO_BUDGET: process.env.OBSX_DEMO_BUDGET,
  };

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    process.env.TRUST_PROXY = 'true';
    process.env.OBSX_ENFORCE_HTTPS = 'true';
    process.env.OBSX_PUBLIC_HOST = 'example.com';

    // 1. Proxied plaintext HTTP GET redirects 308 to canonical OBSX_PUBLIC_HOST (ignores forged Host)
    const redir = await httpRawRequest(port, '/dashboard.html?tab=live', {
      headers: {
        Host: 'evil.example',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '198.51.100.140',
      },
    });
    assert.equal(redir.status, 308);
    assert.equal(redir.headers.location, 'https://example.com/dashboard.html?tab=live');

    // 2. Spoofed leftmost X-Forwarded-Proto ("https, http") still treated as plaintext HTTP
    const spoofedXfp = await httpRawRequest(port, '/docs.html', {
      headers: {
        Host: 'example.com',
        'X-Forwarded-Proto': 'https, http',
        'X-Forwarded-For': '198.51.100.141',
      },
    });
    assert.equal(spoofedXfp.status, 308);
    assert.equal(spoofedXfp.headers.location, 'https://example.com/docs.html');

    // 3. Protocol-relative path cannot become an open redirect
    const protoRel = await httpRawRequest(port, '//evil.com/phish', {
      headers: {
        Host: 'example.com',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '198.51.100.142',
      },
    });
    assert.equal(protoRel.status, 308);
    assert.equal(protoRel.headers.location, 'https://example.com/evil.com/phish');

    // 4. Proxied plaintext HTTP POST returns 426 Upgrade Required
    const postPlain = await httpRawRequest(port, '/api/v1/demo', {
      method: 'POST',
      headers: {
        Host: 'example.com',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '198.51.100.143',
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    assert.equal(postPlain.status, 426);
    assert.equal(postPlain.json && postPlain.json.error, 'https_required');

    // 5. Health endpoint and direct loopback requests without proxy plaintext headers stay 200
    const healthRes = await httpRawRequest(port, '/api/v1/health', {
      headers: { 'X-Forwarded-Proto': 'http', 'X-Forwarded-For': '198.51.100.144' },
    });
    assert.equal(healthRes.status, 200);
    assert.equal(healthRes.headers['strict-transport-security'], undefined);

    const loopbackVer = await httpRawRequest(port, '/api/v1/system/version');
    assert.equal(loopbackVer.status, 200);

    // 6. Demo/vault per-IP rate budget enforcement
    process.env.OBSX_ENFORCE_HTTPS = 'false';
    process.env.OBSX_DEMO_BUDGET = '2';
    const burstIp = '198.51.100.149';
    const d1 = await httpRawRequest(port, '/api/v1/demo', {
      method: 'POST',
      headers: { 'X-Forwarded-For': burstIp, 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'budget_test' }),
    });
    const d2 = await httpRawRequest(port, '/api/v1/vault/drain', {
      method: 'POST',
      headers: { 'X-Forwarded-For': burstIp, 'Content-Type': 'application/json' },
      body: JSON.stringify({ attackVector: 'test' }),
    });
    const d3 = await httpRawRequest(port, '/api/v1/demo', {
      method: 'POST',
      headers: { 'X-Forwarded-For': burstIp, 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'budget_test_3' }),
    });
    assert.equal(d1.status, 200);
    assert.equal(d2.status, 200);
    assert.equal(d3.status, 429);
    assert.equal(d3.json && d3.json.error, 'demo_rate_limited');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('server: duplicate process exits non-zero on EADDRINUSE instead of hanging as zombie', async () => {
  const blocker = net.createServer();
  await new Promise((resolve) => blocker.listen(0, '127.0.0.1', resolve));
  const occupiedPort = blocker.address().port;

  try {
    const exitInfo = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(__dirname, '../server.js')], {
        cwd: path.join(__dirname, '..'),
        env: {
          ...process.env,
          NODE_ENV: 'production',
          PORT: String(occupiedPort),
          OBSX_BIND: '127.0.0.1',
          OBSX_PERSIST_KV: 'false',
          OBSX_AUTO_UPDATE: 'false',
          OBSX_AUTO_RESTART: 'false',
          OBSX_ACCEPT_LICENSE: 'true',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error('Duplicate server.js hung instead of exiting on EADDRINUSE'));
      }, 5000);
      child.on('exit', (code, signal) => {
        clearTimeout(timer);
        resolve({ code, signal, stderr });
      });
    });

    assert.equal(exitInfo.signal, null);
    assert.notEqual(exitInfo.code, 0);
    assert.match(exitInfo.stderr, /EADDRINUSE/i);
  } finally {
    await new Promise((resolve) => blocker.close(resolve));
  }
});

test('review regressions: async KV snapshot race, cleanup volatile expiry, guest eviction, Host fail-closed, and post-BotShield HTTP', async () => {
  // 1. Async snapshot must NOT lose writes arriving mid-writeFile and must restore _dirty on failure
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsx-snap-race-'));
  const snapPath = path.join(tmpDir, 'snapshot.json');
  const origWriteFile = fs.promises.writeFile;
  const store = new MemoryStore(500, snapPath);
  try {
    await store.set('tr:durable:A', '1');
    let injected = false;
    fs.promises.writeFile = async (...args) => {
      if (!injected) {
        injected = true;
        await store.set('tr:durable:B', '2');
      }
      return origWriteFile.apply(fs.promises, args);
    };
    await store._saveSnapshotAsync();
    assert.equal(store._dirty, true, 'concurrent durable write during writeFile must leave _dirty=true');
    fs.promises.writeFile = origWriteFile;
    store.close();

    const reloaded = new MemoryStore(500, snapPath);
    try {
      assert.equal(await reloaded.get('tr:durable:A'), '1');
      assert.equal(await reloaded.get('tr:durable:B'), '2');
    } finally {
      reloaded.close();
    }

    // Write failure restores _dirty=true so subsequent sync/close retries cleanly
    const failStore = new MemoryStore(500, snapPath);
    try {
      await failStore.set('tr:durable:C', '3');
      fs.promises.writeFile = async () => { throw new Error('disk_full_sim'); };
      await failStore._saveSnapshotAsync();
      assert.equal(failStore._dirty, true, 'failed async snapshot must restore _dirty=true');
    } finally {
      fs.promises.writeFile = origWriteFile;
      failStore.close();
    }

    // 2. cleanup() expiring volatile keys must NOT dirty snapshot, while durable expiry does
    const store3 = new MemoryStore(500, snapPath);
    try {
      store3._dirty = false;
      await store3.incr('tr:rl:sub:expire_only', 1);
      store3.ttls.set('tr:rl:sub:expire_only', Date.now() - 50);
      store3.cleanup();
      assert.equal(store3._dirty, false, 'expiring volatile key must not dirty snapshot');

      await store3.set('tr:durable:expiring', 'bye', 'EX', 1);
      store3._dirty = false;
      store3.ttls.set('tr:durable:expiring', Date.now() - 50);
      store3.cleanup();
      assert.equal(store3._dirty, true, 'expiring durable key must dirty snapshot');
    } finally {
      store3.close();
    }

    // 2b. Pass 2 volatile eviction removes tr:guest:* keys while preserving verified human sessions
    const tinyStore = new MemoryStore(6, null);
    try {
      await tinyStore.hset('tr:s:verified_human', { p: 'p1', sig: '{"ok":1}' });
      for (let i = 0; i < 10; i++) {
        await tinyStore.set(`tr:guest:n:note_${i}`, 'payload');
      }
      assert.ok(tinyStore.store.size <= 6);
      const surviving = await tinyStore.hgetall('tr:s:verified_human');
      assert.equal(surviving.p, 'p1');
    } finally {
      tinyStore.close();
    }
  } finally {
    fs.promises.writeFile = origWriteFile;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // 3. Guest-note global eviction must NOT cause ghost-quota lockout for the evicted guest
  const prevGuestCap = process.env.OBSX_MAX_GLOBAL_GUEST_NOTES;
  const guestA = `guest_${crypto.randomId(8)}`;
  const guestB = `guest_${crypto.randomId(8)}`;
  try {
    process.env.OBSX_MAX_GLOBAL_GUEST_NOTES = '25';
    for (let i = 0; i < 25; i++) {
      await core.createUserNote(guestA, { title: `A-${i}`, content: 'a' });
    }
    for (let i = 0; i < 25; i++) {
      await core.createUserNote(guestB, { title: `B-${i}`, content: 'b' });
    }
    assert.equal((await core.getUserNotes(guestA)).length, 0);
    const createdAfterEviction = await core.createUserNote(guestA, { title: 'A-fresh', content: 'recovered' });
    assert.ok(createdAfterEviction && createdAfterEviction.id);
    assert.equal((await core.getUserNotes(guestA)).length, 1);
  } finally {
    await core.purgeUserNotes(guestA);
    await core.purgeUserNotes(guestB);
    if (prevGuestCap === undefined) delete process.env.OBSX_MAX_GLOBAL_GUEST_NOTES;
    else process.env.OBSX_MAX_GLOBAL_GUEST_NOTES = prevGuestCap;
  }

  // 4. OBSX_ENFORCE_HTTPS without OBSX_PUBLIC_HOST/OBSX_ALLOWED_HOSTS fails closed (426, no open redirect)
  //    and runs AFTER BotShield so plaintext HTTP traffic cannot bypass shield tracking/blocks
  const server = require('../server');
  const prevCfg = { ...botshield.config };
  const savedEnv = {
    TRUST_PROXY: process.env.TRUST_PROXY,
    OBSX_ENFORCE_HTTPS: process.env.OBSX_ENFORCE_HTTPS,
    OBSX_PUBLIC_HOST: process.env.OBSX_PUBLIC_HOST,
    OBSX_ALLOWED_HOSTS: process.env.OBSX_ALLOWED_HOSTS,
  };
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    process.env.TRUST_PROXY = 'true';
    process.env.OBSX_ENFORCE_HTTPS = 'true';
    delete process.env.OBSX_PUBLIC_HOST;
    delete process.env.OBSX_ALLOWED_HOSTS;

    botshield.reset();
    botshield.configure({ enabled: true, mode: 'auto', maxRssMb: 9999 });

    const botPlain = await httpRawRequest(port, '/dashboard.html', {
      headers: {
        Host: 'attacker.example',
        'User-Agent': BOT_UA,
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '198.51.100.180',
      },
    });
    assert.equal(botPlain.status, 403);
    assert.equal(botPlain.headers['x-obsx-botshield'], 'challenge');
    assert.ok(botshield.stats(true).counters.requests >= 1);

    const noHostAllowlist = await httpRawRequest(port, '/dashboard.html', {
      headers: {
        Host: 'attacker.example',
        'User-Agent': BROWSER_UA,
        Accept: 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '198.51.100.181',
      },
    });
    assert.equal(noHostAllowlist.status, 426);
    assert.equal(noHostAllowlist.headers.location, undefined);

    process.env.OBSX_ALLOWED_HOSTS = 'example.com,www.example.com';
    const allowedBrowser = await httpRawRequest(port, '/dashboard.html', {
      headers: {
        Host: 'www.example.com',
        'User-Agent': BROWSER_UA,
        Accept: 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '198.51.100.182',
      },
    });
    assert.equal(allowedBrowser.status, 308);
    assert.equal(allowedBrowser.headers.location, 'https://www.example.com/dashboard.html');
  } finally {
    botshield.reset();
    botshield.configure(prevCfg);
    await new Promise((resolve) => server.close(resolve));
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});
