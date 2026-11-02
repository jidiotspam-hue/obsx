'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const server = require('../server');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const { getKv } = require('../lib/kv');

function makeRequest(port, options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, ...options }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(raw) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: raw });
        }
      });
    });
    req.on('error', reject);
    if (postData) req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    req.end();
  });
}

async function getValidAttestation() {
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
      mousePoints: [
        { x: 20, y: 30, t: 100 },
        { x: 45, y: 65, t: 450 },
        { x: 80, y: 110, t: 900 },
        { x: 120, y: 160, t: 1600 },
      ],
      rum: {
        dnsMs: 12,
        tcpMs: 18,
        ttfbMs: 45,
        domMs: 120,
      },
    },
  });

  return { token: s.token, nonce: String(nonce) };
}

async function makeAttestedRequest(port, options, postData = {}, cookie = '') {
  const att = await getValidAttestation();
  const realNow = Date.now;
  Date.now = () => realNow() + 2000;
  try {
    const payload = { ...postData, token: att.token, nonce: att.nonce };
    const headers = {
      'Content-Type': 'application/json',
      ...(cookie ? { Cookie: cookie } : {}),
      'x-obsx-token': att.token,
      'x-obsx-nonce': att.nonce,
      ...(options.headers || {}),
    };
    return await makeRequest(port, { ...options, headers }, payload);
  } finally {
    Date.now = realNow;
  }
}

test('Tenant project telemetry isolation and access control', async (t) => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  try {
    // 1. Authenticate Operator Alice
    const aliceEmail = `alice_telemetry_${Date.now()}@obsx.tech`;
    const aliceStart = await accounts.startEmailAuth(aliceEmail, '127.0.0.1');
    const aliceAuth = await accounts.verifyEmailAuth(aliceEmail, aliceStart.devCode, false);
    const aliceCookie = `obsx_session=${aliceAuth.sid}`;

    // 2. Authenticate Operator Bob
    const bobEmail = `bob_telemetry_${Date.now()}@obsx.tech`;
    const bobStart = await accounts.startEmailAuth(bobEmail, '127.0.0.1');
    const bobAuth = await accounts.verifyEmailAuth(bobEmail, bobStart.devCode, false);
    const bobCookie = `obsx_session=${bobAuth.sid}`;

    // 3. Alice creates Project A
    const aliceProjRes = await makeAttestedRequest(
      port,
      { path: '/api/v1/project', method: 'POST' },
      { name: 'Alice Production API' },
      aliceCookie
    );
    assert.equal(aliceProjRes.status, 201);
    const projectA = aliceProjRes.body.project;
    assert.ok(projectA && projectA.pid);

    // 4. Bob creates Project B
    const bobProjRes = await makeAttestedRequest(
      port,
      { path: '/api/v1/project', method: 'POST' },
      { name: 'Bob Production API' },
      bobCookie
    );
    assert.equal(bobProjRes.status, 201);
    const projectB = bobProjRes.body.project;
    assert.ok(projectB && projectB.pid);

    // 5. Unauthenticated request to /api/v1/project/:pid/telemetry is rejected with 401
    const unauthRes = await makeRequest(port, {
      path: `/api/v1/project/${projectA.pid}/telemetry`,
      method: 'GET',
    });
    assert.equal(unauthRes.status, 401);
    assert.equal(unauthRes.body.error, 'unauthorized');

    // 6. Cross-tenant access: Bob trying to query Alice's project is rejected with 404
    const forbiddenRes = await makeRequest(port, {
      path: `/api/v1/project/${projectA.pid}/telemetry`,
      method: 'GET',
      headers: { Cookie: bobCookie },
    });
    assert.equal(forbiddenRes.status, 404);
    assert.equal(forbiddenRes.body.error, 'project_not_found');

    // 7. Tampered attestation token in headers is rejected with 403 security_gate_rejected
    const tamperedRes = await makeRequest(port, {
      path: `/api/v1/project/${projectA.pid}/telemetry`,
      method: 'GET',
      headers: {
        Cookie: aliceCookie,
        'x-obsx-token': 'fake_tampered_token_xyz',
        'x-obsx-nonce': '0',
      },
    });
    assert.equal(tamperedRes.status, 403);
    assert.equal(tamperedRes.body.error, 'security_gate_rejected');

    // 8. Alice queries Project A before any traffic hits it: hasTraffic is false
    const freshQueryRes = await makeRequest(port, {
      path: `/api/v1/project/${projectA.pid}/telemetry`,
      method: 'GET',
      headers: { Cookie: aliceCookie },
    });
    assert.equal(freshQueryRes.status, 200);
    assert.equal(freshQueryRes.body.ok, true);
    assert.equal(freshQueryRes.body.hasTraffic, false);
    assert.equal(freshQueryRes.body.stats.total, 0);
    assert.equal(freshQueryRes.body.recentEvents.length, 0);

    // 9. Send live attested verification traffic to Project A
    const aliceLoadedProj = await core.loadProject(projectA.pid);
    const sessionA = await core.startSession(aliceLoadedProj, { ip: '192.0.2.1' });

    let nonceA = 0;
    while (!crypto.verifyPoW(sessionA.challenge, String(nonceA), sessionA.difficulty)) {
      nonceA++;
    }

    await core.recordSignals({
      token: sessionA.token,
      signals: {
        sh: 'trc_v1_live',
        mousePoints: [
          { x: 10, y: 15, t: 120 },
          { x: 30, y: 40, t: 500 },
          { x: 60, y: 80, t: 1000 },
          { x: 100, y: 130, t: 1800 },
        ],
        rum: { dnsMs: 10, tcpMs: 15, ttfbMs: 40, domMs: 100 },
      },
    });

    const realNow = Date.now;
    let verifyResult;
    try {
      Date.now = () => realNow() + 2000;
      verifyResult = await core.verify(
        aliceLoadedProj,
        { token: sessionA.token, nonce: String(nonceA) },
        { ip: '192.0.2.1', action: 'Alice Checkout Transaction' }
      );
    } finally {
      Date.now = realNow;
    }
    assert.equal(verifyResult.allowed, true);
    assert.equal(verifyResult.verdict, 'accept');

    // 10. Alice queries Project A telemetry after traffic: hasTraffic is true, stats.total is 1
    const postTrafficRes = await makeRequest(port, {
      path: `/api/v1/project/${projectA.pid}/telemetry`,
      method: 'GET',
      headers: { Cookie: aliceCookie },
    });
    assert.equal(postTrafficRes.status, 200);
    assert.equal(postTrafficRes.body.hasTraffic, true);
    assert.equal(postTrafficRes.body.stats.total, 1);
    assert.equal(postTrafficRes.body.stats.breakdown.accept, 1);
    assert.equal(postTrafficRes.body.stats.acceptRate, 100);
    assert.equal(postTrafficRes.body.recentEvents.length, 1);
    assert.equal(postTrafficRes.body.recentEvents[0].action, 'Alice Checkout Transaction');

    // 11. Verify NO bleed: Bob queries Project B -> total remains 0, hasTraffic remains false
    const bobQueryRes = await makeRequest(port, {
      path: `/api/v1/project/${projectB.pid}/telemetry`,
      method: 'GET',
      headers: { Cookie: bobCookie },
    });
    assert.equal(bobQueryRes.status, 200);
    assert.equal(bobQueryRes.body.hasTraffic, false);
    assert.equal(bobQueryRes.body.stats.total, 0);
    assert.equal(bobQueryRes.body.recentEvents.length, 0);
  } finally {
    await new Promise((r) => testServer.close(r));
  }
});
