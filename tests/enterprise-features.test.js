'use strict';

process.env.TRUST_PROXY = 'true';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const server = require('../server');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const telemetry = require('../lib/telemetry');

let port = 0;
let baseUrl = '';
let testServer = null;

test.before(async () => {
  await new Promise((resolve) => {
    testServer = server.listen(0, '127.0.0.1', () => {
      port = testServer.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  if (testServer) {
    if (typeof testServer.closeAllConnections === 'function') {
      testServer.closeAllConnections();
    }
    await new Promise((resolve) => testServer.close(resolve));
  }
});

function request(method, path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers = { ...(options.headers || {}) };
    let bodyData = null;

    if (options.body) {
      bodyData = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
      }
      headers['Content-Length'] = Buffer.byteLength(bodyData);
    }

    const req = http.request(url, { method, headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: raw,
          json,
        });
      });
    });

    req.on('error', reject);
    if (bodyData) req.write(bodyData);
    req.end();
  });
}

// 1. Adaptive Proof of Work Difficulty Escalation
test('enterprise: proxy-tainted session requests trigger adaptive difficulty escalation', async () => {
  const p = await core.loadProject(core.DEMO.pid);

  // Clean request -> difficulty = 2
  const cleanSession = await core.startSession(p, { ip: '198.51.100.1' });
  assert.equal(cleanSession.difficulty, 2, 'Clean session should use standard difficulty 2');

  // Request with proxy headers -> difficulty escalated to >= 3
  const taintedSession = await core.startSession(p, {
    ip: '198.51.100.1',
    proxyHeaders: ['bare_mux_protocol', 'wisp_tunnel'],
  });
  assert.ok(taintedSession.difficulty >= 3, 'Tainted request must escalate PoW difficulty');
});

// 2. Chrome DevTools Protocol (CDP) & Driver Automation Traps
test('enterprise: active CDP and chromedriver artifacts are detected and hard rejected', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Record signals carrying active CDP / chromedriver markers
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      tampered: ['automation_cdp:cdc_adoQpoasnfa76pfcZLmcfl_Array', 'automation_framework:playwright_puppeteer'],
      elapsedMs: 2000,
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const verdict = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  });

  Date.now = realNow;

  assert.equal(verdict.verdict, 'reject');
  assert.equal(verdict.risk, 100);
  assert.ok(verdict.reasons.some((r) => r.code === 'automation_cdp'));
});

// 3. Ephemeral Software Rasterizer / SwiftShader Emulation Detection
test('enterprise: software emulated GPU rasterizers are flagged and heavily penalized', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      gpuRenderer: 'Google Inc. (Google) ~ Google SwiftShader (OpenGL ES 3.0)',
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 180 },
        { x: 50, y: 70, t: 260 },
      ],
      elapsedMs: 2000,
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const verdict = await core.verify(p, {
    token: s.token,
    nonce: String(nonce),
  }, { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36' });

  Date.now = realNow;

  assert.equal(verdict.verdict, 'reject');
  assert.ok(verdict.reasons.some((r) => r.code === 'software_rasterizer_anomaly'));
});

// 4. Mobile Synthetic Touch Pressure Mechanics
test('enterprise: synthetic touches with constant pressure (Playwright/Puppeteer touch) are detected', async () => {
  const touches = [
    { x: 100, y: 200, f: 1.0, r: 0, t: 100 },
    { x: 105, y: 205, f: 1.0, r: 0, t: 150 },
    { x: 110, y: 210, f: 1.0, r: 0, t: 200 },
    { x: 115, y: 215, f: 1.0, r: 0, t: 250 },
    { x: 120, y: 220, f: 1.0, r: 0, t: 300 },
  ];

  const evalResult = telemetry.evaluateTouchDynamics(touches);
  assert.equal(evalResult.isSyntheticTouch, true, 'Constant pressure touch must be flagged as synthetic');

  // Biological human touch with natural pressure curve and radius expansion
  const humanTouches = [
    { x: 100, y: 200, f: 0.2, r: 8.5, t: 100 },
    { x: 102, y: 201, f: 0.6, r: 12.0, t: 150 },
    { x: 103, y: 202, f: 0.9, r: 15.2, t: 200 },
    { x: 104, y: 203, f: 0.7, r: 13.1, t: 250 },
    { x: 105, y: 204, f: 0.3, r: 9.0, t: 300 },
  ];
  const humanResult = telemetry.evaluateTouchDynamics(humanTouches);
  assert.equal(humanResult.isSyntheticTouch, false, 'Human touch with pressure variance must pass');
});

// 5. Live Telemetry & Observability Metrics API
test('enterprise: /api/v1/metrics delivers live aggregate breakdown and rates', async () => {
  const res = await request('GET', '/api/v1/metrics');
  assert.equal(res.status, 200);
  assert.ok(res.json.ok);
  assert.ok(typeof res.json.metrics.total === 'number');
  assert.ok(typeof res.json.metrics.acceptRate === 'number');
  assert.ok(typeof res.json.metrics.breakdown === 'object');
  assert.ok(typeof res.json.metrics.topReasons === 'object');
});

// 6. Project Settings Management & Dynamic Threshold Updating
test('enterprise: project settings can be retrieved and updated by project owner', async () => {
  const email = `proj_owner_${crypto.randomId(6)}@obsx.tech`;
  const start = await accounts.startEmailAuth(email, '127.0.0.1');
  const auth = await accounts.verifyEmailAuth(email, start.devCode, false);
  const cookie = auth.sessionCookie.split(';')[0];

  // Create project
  const createRes = await request('POST', '/api/v1/project', {
    headers: { Cookie: cookie },
    body: { name: 'Fintech Shield API', origins: ['https://fintech.example.com'] },
  });
  assert.equal(createRes.status, 201);
  const pid = createRes.json.project.pid;

  // Retrieve project details: GET /api/v1/project/:pid
  const getRes = await request('GET', `/api/v1/project/${pid}`, {
    headers: { Cookie: cookie },
  });
  assert.equal(getRes.status, 200);
  assert.equal(getRes.json.project.name, 'Fintech Shield API');

  // Update settings: PATCH /api/v1/project/:pid/settings
  const updateRes = await request('PATCH', `/api/v1/project/${pid}/settings`, {
    headers: { Cookie: cookie },
    body: {
      rejectAt: 75,
      powDifficulty: 4,
      origins: ['https://fintech.example.com', 'https://secure.fintech.example.com'],
    },
  });
  assert.equal(updateRes.status, 200);
  assert.equal(updateRes.json.settings.rejectAt, 75);
  assert.equal(updateRes.json.settings.powDifficulty, 4);
  assert.equal(updateRes.json.settings.origins.length, 2);
});

// 7. Secret Key Rotation
test('enterprise: project owners can atomically rotate secret keys', async () => {
  const email = `rot_owner_${crypto.randomId(6)}@obsx.tech`;
  const start = await accounts.startEmailAuth(email, '127.0.0.1');
  const auth = await accounts.verifyEmailAuth(email, start.devCode, false);
  const cookie = auth.sessionCookie.split(';')[0];

  const createRes = await request('POST', '/api/v1/project', {
    headers: { Cookie: cookie },
    body: { name: 'Key Rotation Project' },
  });
  const pid = createRes.json.project.pid;
  const initialSk = createRes.json.project.secretKey;

  // Rotate key: POST /api/v1/project/:pid/rotate-key
  const rotateRes = await request('POST', `/api/v1/project/${pid}/rotate-key`, {
    headers: { Cookie: cookie },
  });
  assert.equal(rotateRes.status, 200);
  assert.ok(rotateRes.json.secretKey.startsWith('sk_'));
  assert.notEqual(rotateRes.json.secretKey, initialSk, 'New key must be distinct from old key');

  // Verify that new key resolves project successfully
  const projectByNewKey = await core.projectBySecretKey(rotateRes.json.secretKey);
  assert.equal(projectByNewKey.pid, pid);
});

// 8. Project Listing & Deletion
test('enterprise: project owners can list and delete projects', async () => {
  const email = `list_owner_${crypto.randomId(6)}@obsx.tech`;
  const start = await accounts.startEmailAuth(email, '127.0.0.1');
  const auth = await accounts.verifyEmailAuth(email, start.devCode, false);
  const cookie = auth.sessionCookie.split(';')[0];

  // List initially - empty
  const initialList = await request('GET', '/api/v1/projects', {
    headers: { Cookie: cookie },
  });
  assert.equal(initialList.status, 200);
  assert.equal(initialList.json.projects.length, 0);

  // Create project
  const createRes = await request('POST', '/api/v1/project', {
    headers: { Cookie: cookie },
    body: { name: 'Temporary Project' },
  });
  assert.equal(createRes.status, 201);
  const pid = createRes.json.project.pid;

  // List again - contains 1 project
  const afterList = await request('GET', '/api/v1/projects', {
    headers: { Cookie: cookie },
  });
  assert.equal(afterList.status, 200);
  assert.equal(afterList.json.projects.length, 1);
  assert.equal(afterList.json.projects[0].pid, pid);
  assert.equal(afterList.json.projects[0].name, 'Temporary Project');

  // Delete project
  const deleteRes = await request('DELETE', `/api/v1/project/${pid}`, {
    headers: { Cookie: cookie },
  });
  assert.equal(deleteRes.status, 200);
  assert.equal(deleteRes.json.ok, true);

  // List after deletion - empty again
  const finalList = await request('GET', '/api/v1/projects', {
    headers: { Cookie: cookie },
  });
  assert.equal(finalList.status, 200);
  assert.equal(finalList.json.projects.length, 0);
});

// 9. Challenge-Bound Telemetry Seal (tsig) & Global Sentinel Fleet Ring
test('enterprise: challenge-bound telemetry HMAC seal (tsig) rejects tampered beacon signatures', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  await core.recordSignals({
    token: s.token,
    nonce: String(nonce),
    tsig: 'forged_hmac_seal_xyz',
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 28, y: 38, t: 165 },
        { x: 55, y: 74, t: 245 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;
  const v = await core.verify(p, { token: s.token, nonce: String(nonce) });
  Date.now = realNow;

  assert.ok(v.reasons.some((r) => r.code === 'tampered_builtins'));
});

test('enterprise: Global Sentinel Fleet Ring escalates and exposes hostile subnets via /api/v1/sentinel/ring', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const hostileIp = '198.51.100.77';

  for (let i = 0; i < 3; i++) {
    const s = await core.startSession(p, { ip: hostileIp });
    await core.verify(p, { token: s.token, nonce: 'bad' }, { ip: hostileIp });
  }

  const ring = await core.getGlobalThreatRing();
  assert.equal(ring.ok, true);
  assert.ok(ring.isolatedSubnetCount >= 1);

  const escalatedSession = await core.startSession(p, { ip: hostileIp });
  assert.ok(escalatedSession.difficulty >= 4, 'Global threat ring must pre-escalate PoW difficulty');
});

