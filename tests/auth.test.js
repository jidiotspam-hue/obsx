'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const server = require('../server');
const core = require('../lib/core');
const crypto = require('../lib/crypto');
const accounts = require('../lib/accounts');
const { getKv } = require('../lib/kv');

test('auth: email OTP is rate-limited per caller IP, not globally per email', async () => {
  const attackerIp = '198.51.100.99';
  const victimIp = '203.0.113.10';

  // Attacker sends 10 requests rapidly from attackerIp across varied emails
  for (let i = 0; i < 10; i++) {
    await accounts.startEmailAuth(`user_${i}@example.com`, attackerIp);
  }

  // 11th request from attackerIp is rate-limited
  await assert.rejects(
    async () => accounts.startEmailAuth('another_user@example.com', attackerIp),
    /Too many requests/
  );

  // BUT victim on victimIp is NOT locked out!
  const victimAttempt = await accounts.startEmailAuth('clean_user@example.com', victimIp);
  assert.equal(victimAttempt.ok, true, 'Real user from separate IP must not be locked out');
});

test('auth: wrong code attempts are limited to 5 before key eviction', async () => {
  const email = 'test_auth@example.com';
  await accounts.startEmailAuth(email, '127.0.0.1');

  // 5 wrong attempts
  for (let i = 0; i < 5; i++) {
    await assert.rejects(
      async () => accounts.verifyEmailAuth(email, '000000'),
      /Invalid code/
    );
  }

  // 6th attempt fails due to eviction
  await assert.rejects(
    async () => accounts.verifyEmailAuth(email, '000000'),
    /Too many incorrect attempts/
  );
});

test('auth: requests with tampered OBSX attestation token are hard rejected with 403', async () => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  const res = await new Promise((resolve) => {
    const data = JSON.stringify({
      email: 'tampered@obsx.tech',
      action: 'start',
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tampered.signature',
    });
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/api/v1/auth/email',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(raw) }));
      }
    );
    req.write(data);
    req.end();
  });

  await new Promise((r) => testServer.close(r));

  assert.equal(res.status, 403);
  assert.equal(res.json.ok, false);
  assert.equal(res.json.error, 'security_gate_rejected');
  assert.ok(res.json.reasons.some((r) => r.code === 'invalid_token'));
});

test('auth: requests with valid OBSX client attestation and micro-PoW pass gate', async () => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

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
        { x: 12, y: 18, t: 100 },
        { x: 28, y: 40, t: 210 },
        { x: 55, y: 75, t: 320 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 1500;

  const res = await new Promise((resolve) => {
    const data = JSON.stringify({
      email: 'valid_gate_user@obsx.tech',
      action: 'start',
      token: s.token,
      nonce: String(nonce),
    });
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/api/v1/auth/email',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(raw) }));
      }
    );
    req.write(data);
    req.end();
  });

  Date.now = realNow;
  await new Promise((r) => testServer.close(r));

  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
  assert.ok(res.json.message);
});

test('auth: requests without token outside test mode are rejected with 403', async () => {
  const origEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';

  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  const res = await new Promise((resolve) => {
    const data = JSON.stringify({
      email: 'missing_token_user@obsx.tech',
      action: 'start',
    });
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/api/v1/auth/email',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(raw) }));
      }
    );
    req.write(data);
    req.end();
  });

  process.env.NODE_ENV = origEnv;
  await new Promise((r) => testServer.close(r));

  assert.equal(res.status, 403);
  assert.equal(res.json.ok, false);
  assert.equal(res.json.error, 'security_gate_rejected');
  assert.ok(res.json.reasons.some((r) => r.code === 'missing_token'));
});

test('auth: unauthenticated project creation is strictly rejected with 401', async () => {
  const testServer = http.createServer((req, res) => server.emit('request', req, res));
  await new Promise((r) => testServer.listen(0, '127.0.0.1', r));
  const port = testServer.address().port;

  const res = await new Promise((resolve) => {
    const data = JSON.stringify({ name: 'Hacker Project' });
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/api/v1/project',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(raw) }));
      }
    );
    req.write(data);
    req.end();
  });

  await new Promise((r) => testServer.close(r));

  assert.equal(res.status, 401);
  assert.equal(res.json.ok, false);
  assert.equal(res.json.error, 'unauthorized');
});

test('auth: cookie-tossing attack prioritizes __Host- cookie over plain injected cookie', async () => {
  const victimEmail = 'victim_cookie_toss@obsx.tech';
  const start = await accounts.startEmailAuth(victimEmail, '127.0.0.1');
  const victimAuth = await accounts.verifyEmailAuth(victimEmail, start.devCode, true);
  const victimSid = victimAuth.sid;
  const attackerSid = 'attacker_forged_subdomain_session_123';

  // Browser sends injected plain cookie first, followed by legitimate __Host- cookie
  const req = {
    headers: {
      cookie: `obsx_session=${attackerSid}; __Host-obsx_session=${victimSid}`,
    },
  };

  const user = await accounts.getSessionUser(req);
  assert.ok(user, 'User must resolve');
  assert.equal(user.email, victimEmail, 'Must resolve the __Host- cookie session, defeating subdomain tossing');
});

test('auth: type confusion with numeric codes and invalid code formats are safely handled', async () => {
  const email = 'type_confusion_test@obsx.tech';
  const start = await accounts.startEmailAuth(email, '127.0.0.1');

  // Passing raw number instead of string should not crash
  const numCode = Number(start.devCode);
  const auth = await accounts.verifyEmailAuth(email, numCode, false);
  assert.equal(auth.email, email);

  // Passing invalid format throws clean error without uncaught TypeErrors
  await assert.rejects(
    async () => accounts.verifyEmailAuth(email, 'abc', false),
    /Invalid code/
  );
});

test('auth: unicode Cyrillic homoglyph emails are rejected by strict ASCII normalization', async () => {
  // Cyrillic 'а' (\u0430) looks identical to Latin 'a' (\u0061)
  const cyrillicEmail = '\u0430lex@obsx.tech';
  await assert.rejects(
    async () => accounts.startEmailAuth(cyrillicEmail, '127.0.0.1'),
    /invalid_email/
  );
});

test('auth: sub-addressing (+tag) cannot bypass per-mailbox cooldown or rate limits', async () => {
  const baseEmail = 'tag_test_target@obsx.tech';
  await accounts.startEmailAuth(baseEmail, '127.0.0.1');

  // Immediately attempting with +tag to same inbox is stopped by 45s cooldown
  await assert.rejects(
    async () => accounts.startEmailAuth('tag_test_target+spam1@obsx.tech', '127.0.0.1'),
    /Please wait 45 seconds/
  );
});
