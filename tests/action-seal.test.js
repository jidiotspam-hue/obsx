'use strict';

const test = require('node:test');
const assert = require('node:assert');
const core = require('../lib/core');
const crypto = require('../lib/crypto');

test('action-seal: deterministic canonicalization orders keys and handles nested types', () => {
  const obj1 = { b: 2, a: 1, c: { y: 'bar', x: 'foo' } };
  const obj2 = { c: { x: 'foo', y: 'bar' }, a: 1, b: 2 };

  assert.equal(crypto.canon(obj1), '{"a":1,"b":2,"c":{"x":"foo","y":"bar"}}');
  assert.equal(crypto.canon(obj1), crypto.canon(obj2));

  // Arrays preserve order
  assert.equal(crypto.canon([3, 1, 2]), '[3,1,2]');

  // Metadata keys are ignored in sealing
  const withMeta = { score: 100, obsx: { sig: 'abc' }, seal: { ts: 123 }, advisory: { token: 'xyz' } };
  assert.equal(crypto.canon(withMeta), '{"score":100}');
});

test('action-seal: authentic sealed action payload verifies with sealed: "ok"', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  // Solve PoW
  let nonce = 0;
  while (!crypto.verifyPoW(s.challenge, String(nonce), s.difficulty)) {
    nonce++;
  }

  // Record valid human signals
  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 150 },
        { x: 45, y: 70, t: 200 },
        { x: 68, y: 110, t: 250 },
        { x: 95, y: 160, t: 300 },
        { x: 125, y: 220, t: 350 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const payload = { score: 42, visitor: 'alex_verified' };
  const ts = Date.now();
  const sig = crypto.signActionSeal(s.rk, s.session, ts, String(nonce), payload);

  const sealedRequest = {
    ...payload,
    token: s.token,
    nonce: String(nonce),
    obsx: {
      token: s.token,
      nonce: String(nonce),
      ts,
      sig,
    },
  };

  const v = await core.verify(p, sealedRequest);
  Date.now = realNow;

  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.sealed, 'ok');
  assert.equal(v.risk, 0);
});

test('action-seal: wire tampering of score or visitor is strictly rejected with bad_signature', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  await core.recordSignals({
    token: s.token,
    signals: {
      sh: 'trc_v1_live',
      mousePoints: [
        { x: 10, y: 15, t: 100 },
        { x: 25, y: 35, t: 150 },
        { x: 45, y: 70, t: 200 },
        { x: 68, y: 110, t: 250 },
      ],
    },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const originalPayload = { score: 42, visitor: 'alex_verified' };
  const ts = Date.now();
  const sig = crypto.signActionSeal(s.rk, s.session, ts, 'nonce_123', originalPayload);

  // Attacker tampers score on wire: 42 -> 99999
  const tamperedRequest = {
    score: 99999, // Altered on wire!
    visitor: 'alex_verified',
    token: s.token,
    nonce: 'nonce_123',
    obsx: {
      token: s.token,
      nonce: 'nonce_123',
      ts,
      sig, // Original signature
    },
  };

  const v = await core.verify(p, tamperedRequest);
  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.equal(v.risk, 100);
  assert.equal(v.sealed, 'invalid');
  assert.ok(
    v.reasons.some((r) => r.code === 'bad_signature'),
    'Must explicitly reject with bad_signature'
  );
});

test('action-seal: stale signature timestamp (> 5 minutes) is rejected with stale_signature', async () => {
  const p = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(p, { ip: '127.0.0.1' });

  await core.recordSignals({
    token: s.token,
    signals: { sh: 'trc_v1_live' },
  });

  const realNow = Date.now;
  Date.now = () => realNow() + 2000;

  const payload = { action: 'checkout', amount: 500 };
  const staleTs = Date.now() - 400000; // 6.6 minutes old!
  const sig = crypto.signActionSeal(s.rk, s.session, staleTs, 'nonce_stale', payload);

  const staleRequest = {
    ...payload,
    token: s.token,
    nonce: 'nonce_stale',
    obsx: {
      token: s.token,
      nonce: 'nonce_stale',
      ts: staleTs,
      sig,
    },
  };

  const v = await core.verify(p, staleRequest);
  Date.now = realNow;

  assert.equal(v.verdict, 'reject');
  assert.equal(v.risk, 100);
  assert.equal(v.sealed, 'stale');
  assert.ok(
    v.reasons.some((r) => r.code === 'stale_signature'),
    'Must explicitly flag stale_signature'
  );
});
