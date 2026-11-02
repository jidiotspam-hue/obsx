'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const server = require('../server');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const { getKv } = require('../lib/kv');

function makeRequest(port, method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const reqHeaders = {
      ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
      ...headers,
    };

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: reqHeaders,
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          let json = {};
          try {
            json = raw.trim() ? JSON.parse(raw) : {};
          } catch {
            json = { raw };
          }
          resolve({ status: res.statusCode, headers: res.headers, json });
        });
      }
    );

    req.on('error', reject);
    if (data) req.write(data);
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

async function makeAttestedRequest(port, method, path, headers = {}, body = null) {
  const att = await getValidAttestation();
  const realNow = Date.now;
  Date.now = () => realNow() + 2000;
  try {
    const isDelete = method === 'DELETE';
    const reqHeaders = isDelete
      ? { ...headers, 'X-OBSX-Token': att.token, 'X-OBSX-Nonce': att.nonce }
      : headers;
    const reqBody = isDelete
      ? (body || { token: att.token, nonce: att.nonce })
      : { ...(body || {}), token: att.token, nonce: att.nonce };
    return await makeRequest(port, method, path, reqHeaders, reqBody);
  } finally {
    Date.now = realNow;
  }
}

test('self-protection: mutating administrative endpoints strictly reject forged or tampered attestation tokens', async () => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  try {
    // 1. Create project with tampered token
    const fakeToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.forged.signature';
    const start = await accounts.startEmailAuth('operator_test_gate@obsx.tech', '127.0.0.1');
    const userAuth = await accounts.verifyEmailAuth('operator_test_gate@obsx.tech', start.devCode, false);
    const cookie = `obsx_session=${userAuth.sid}`;

    const projRes = await makeRequest(port, 'POST', '/api/v1/project', { Cookie: cookie }, {
      name: 'Attacked Project',
      token: fakeToken,
      nonce: '0',
    });

    assert.equal(projRes.status, 403);
    assert.equal(projRes.json.ok, false);
    assert.equal(projRes.json.error, 'security_gate_rejected');
    assert.ok(projRes.json.reasons.some((r) => r.code === 'invalid_token'));

    // 2. Alert dispatcher with tampered token
    const alertRes = await makeRequest(port, 'POST', '/api/v1/alert/test', { Cookie: cookie }, {
      recipient: 'operator_test_gate@obsx.tech',
      token: fakeToken,
      nonce: '0',
    });

    assert.equal(alertRes.status, 403);
    assert.equal(alertRes.json.ok, false);
    assert.equal(alertRes.json.error, 'security_gate_rejected');

    // 3. Vault reset with tampered token
    const vaultRes = await makeRequest(port, 'POST', '/api/v1/vault/reset', {}, {
      token: fakeToken,
      nonce: '0',
    });

    assert.equal(vaultRes.status, 403);
    assert.equal(vaultRes.json.ok, false);
    assert.equal(vaultRes.json.error, 'security_gate_rejected');
  } finally {
    await new Promise((r) => testServer.close(r));
  }
});

test('self-protection: authentic attestation tokens with micro-PoW allow project management and record live telemetry', async () => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  try {
    const start = await accounts.startEmailAuth('verified_operator@obsx.tech', '127.0.0.1');
    const userAuth = await accounts.verifyEmailAuth('verified_operator@obsx.tech', start.devCode, false);
    const cookie = `obsx_session=${userAuth.sid}`;

    // 1. Create Project with valid attestation
    const projRes = await makeAttestedRequest(port, 'POST', '/api/v1/project', { Cookie: cookie }, {
      name: 'Attested Production API',
      origins: ['https://example.com'],
    });

    assert.equal(projRes.status, 201);
    assert.equal(projRes.json.ok, true);
    const pid = projRes.json.project.pid;
    assert.ok(pid);

    // 2. Rotate Secret Key with valid attestation
    const rotRes = await makeAttestedRequest(port, 'POST', `/api/v1/project/${pid}/rotate-key`, { Cookie: cookie });

    assert.equal(rotRes.status, 200);
    assert.equal(rotRes.json.ok, true);
    assert.ok(rotRes.json.secretKey.startsWith('sk_'));

    // 3. Update Settings (Passive Mode toggle) with valid attestation
    const settingsRes = await makeAttestedRequest(port, 'PATCH', `/api/v1/project/${pid}/settings`, { Cookie: cookie }, {
      mode: 'passive',
    });

    assert.equal(settingsRes.status, 200);
    assert.equal(settingsRes.json.ok, true);
    assert.equal(settingsRes.json.settings.mode, 'passive');

    // 4. Verify Live Telemetry logs show the attested actions
    const telemetry = await core.getLiveTelemetry();
    assert.ok(telemetry.ok);
    const actions = telemetry.recentEvents.map((e) => e.action);
    assert.ok(actions.includes('Operator Create Project'));
    assert.ok(actions.includes('Operator Rotate Secret Key'));
    assert.ok(actions.includes('Operator Update Project Settings'));

    // 5. Delete project with valid attestation
    const delRes = await makeAttestedRequest(port, 'DELETE', `/api/v1/project/${pid}`, { Cookie: cookie });

    assert.equal(delRes.status, 200);
    assert.equal(delRes.json.ok, true);
  } finally {
    await new Promise((r) => testServer.close(r));
  }
});

test('self-protection: notes deletion requires and verifies OBSX attestation gate', async () => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  try {
    const start = await accounts.startEmailAuth('notes_gate_user@obsx.tech', '127.0.0.1');
    const userAuth = await accounts.verifyEmailAuth('notes_gate_user@obsx.tech', start.devCode, false);
    const cookie = `obsx_session=${userAuth.sid}`;

    // Create note
    const note = await core.createUserNote(userAuth.uid, {
      title: 'Gated Note',
      content: 'Protected contents',
      protection: 'obsx',
    });

    // Attempt delete with tampered token
    const badDel = await makeRequest(port, 'DELETE', `/api/v1/notes/${note.id}`, { Cookie: cookie }, {
      token: 'fake_tampered_token',
      nonce: '0',
    });

    assert.equal(badDel.status, 403);
    assert.equal(badDel.json.ok, false);
    assert.equal(badDel.json.error, 'security_gate_rejected');

    // Note remains untouched
    let notes = await core.getUserNotes(userAuth.uid);
    assert.equal(notes.length, 1);

    // Attempt delete with genuine attestation
    const goodDel = await makeAttestedRequest(port, 'DELETE', `/api/v1/notes/${note.id}`, { Cookie: cookie });

    assert.equal(goodDel.status, 200);
    assert.equal(goodDel.json.ok, true);

    notes = await core.getUserNotes(userAuth.uid);
    assert.equal(notes.length, 0);
  } finally {
    await new Promise((r) => testServer.close(r));
  }
});
